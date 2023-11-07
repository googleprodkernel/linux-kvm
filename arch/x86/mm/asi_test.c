// SPDX-License-Identifier: GPL-2.0-only
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/sched/mm.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include <kunit/resource.h>
#include <kunit/test.h>

#include <asm/asi.h>

#include "asi_internal.h"

/*
 * Thank you for visiting asi_test.c. We have some local naming conventions:
 *
 *  - do_ is the prefix for general wrappers around kernel APIs. do_foo should
 *    call foo, and nothing more except dealing with error handling (via
 *    KUNIT_ASSERT_*) and cleanup (via KUnit's resource/action API).
 *  - action_ is the prefix for cleanup-specific wrappers. action_foo should do
 *    nothing but call foo in a way that's suitable for use with KUnit's action
 *    API.
 *  - If action_ helpers need state beyond what can be squashed into void *,
 *    we'll use a struct with _ctx at the end of the name. action_foo should use
 *    struct foo_ctx.
 *  - Test functions start with test_. Note they don't need "asi" in the name
 *    because they are already namespaced within the "asi" test suite.
 *
 * A few things to be careful about when writing tests:
 * - Do not use KUNIT_ASSERT_* in ASI critical sections, only KUNIT_EXPECT_*. If
 *   the former fails, it stops running the test thread and runs cleanup actions
 *   in a different thread, which tries to context switch in the critical
 *   section.
 */

struct asi_test_info {
	int                     index;
	struct asi              *asi;
	struct mm_struct	*mm;
	struct asi_hooks        *ops;
};

static void action_mmdrop(void *ctx)
{
	mmdrop((struct mm_struct *)ctx);
}

static void action_kthread_unuse_mm(void *ctx)
{
	struct mm_struct *mm = ctx;

	if (current->mm == mm)
		kthread_unuse_mm(mm);
}

static void action_asi_unregister_class(void *ctx)
{
	asi_unregister_class((int)(uintptr_t)ctx);
}

static void action_asi_destroy(void *ctx)
{
	asi_destroy((struct asi *)ctx);
}

static struct asi_test_info *setup_test_asi(struct kunit *test,
					    struct asi_hooks *ops)
{
	struct asi_test_info *info;

	if (!static_asi_enabled())
		kunit_skip(test, "ASI disabled. Set asi=on in kmdline to run test");

	info = kunit_kzalloc(
			test, sizeof(struct asi_test_info), GFP_KERNEL);
	info->ops = ops;

	info->index = asi_register_class("test-asi", info->ops);
	KUNIT_ASSERT_GE(test, info->index, 0);
	kunit_add_action(test, action_asi_unregister_class, (void *)(uintptr_t)info->index);

	info->mm = mm_alloc();
	KUNIT_ASSERT_NOT_NULL(test, info->mm);
	kunit_add_action(test, action_mmdrop, info->mm);
	kthread_use_mm(info->mm);
	kunit_add_action(test, action_kthread_unuse_mm, info->mm);

	KUNIT_ASSERT_GE(test, 0, asi_init(info->mm, info->index, &info->asi));
	kunit_add_action(test, action_asi_destroy, info->asi);
	return info;
}

struct free_pages_ctx {
	unsigned int order;
	struct page *pages;
};

static void action___free_pages(void *ctx)
{
	struct free_pages_ctx *context = ctx;

	__free_pages(context->pages, context->order);
}

static struct page *do_alloc_pages(struct kunit *test, gfp_t gfp, unsigned int order)
{
	struct free_pages_ctx *ctx = kunit_kzalloc(
		test, sizeof(struct free_pages_ctx), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, ctx);
	ctx->pages = alloc_pages(gfp, order);
	KUNIT_ASSERT_NOT_NULL(test, ctx->pages);
	ctx->order = order;
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, action___free_pages, ctx), 0);
	return ctx->pages;
}

struct vm_unmap_ram_ctx {
	void *vaddr;
	unsigned int num_pages;
};

static void action_vm_unmap_ram(void *ctx)
{
	struct vm_unmap_ram_ctx *context = ctx;

	vm_unmap_ram(context->vaddr, context->num_pages);
}

static void *do_vm_map_ram(struct kunit *test, struct page **pages, unsigned int count)
{
	struct vm_unmap_ram_ctx *ctx = kunit_kzalloc(
		test, sizeof(struct vm_unmap_ram_ctx), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, ctx);
	ctx->vaddr = vm_map_ram(pages, count, /*node=*/-1);
	KUNIT_ASSERT_NOT_NULL(test, ctx->vaddr);
	ctx->num_pages = count;
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, action_vm_unmap_ram, ctx), 0);
	return ctx->vaddr;
}

/*
 * Takes an array of contiguous struct pages and returns an array of pointers to
 * those struct pages. Handy when you get some contiguous pages and want to pass
 * them to an API that supports non-contiguous pages.
 */
static struct page **pages_to_ptr_array(struct kunit *test, struct page *pages, int num_pages)
{
	struct page **pg_array = kunit_kzalloc(test, num_pages * sizeof(struct page *), GFP_KERNEL);
	int i;

	KUNIT_ASSERT_NOT_NULL(test, pages);
	for (i = 0; i < num_pages; i++)
		pg_array[i] = nth_page(pages, i);

	return pg_array;
}

static bool addr_present(pgd_t *pgd, unsigned long addr)
{
	phys_addr_t phys;
	unsigned long page_size, flags;

	return follow_physaddr(pgd, addr, &phys, &page_size, &flags);
}

/*
 * TODO: b/311180042 - This is a very minimal smoke test. We need to test
 * different source mapping sizes, different numbers of pages per call, and
 * mixed source mapping sizes within the same call. We also need to test gaps in
 * the source mapping, and cases where two calls map overlapping regions.
 * Ideally we should do that while maintaining the hopefully-foolproof
 * straight-line coding style.
 */
static void test_asi_map_global_nonsensitive(struct kunit *test)
{
	int order = 1; /* Test with 2 pages */
	int num_pages = 1 << order;
	int size = num_pages * PAGE_SIZE;
	struct page *pages = do_alloc_pages(test, GFP_KERNEL, order);
	struct page **pg_array = pages_to_ptr_array(test, pages, num_pages);
	/* Map the va in the unrestricted address space */
	void *vaddr = do_vm_map_ram(test, pg_array, num_pages);
	unsigned long va_0 = (unsigned long)vaddr;
	unsigned long va_1 = va_0 + size - sizeof(void *);
	struct asi *asi = ASI_GLOBAL_NONSENSITIVE;
	pgd_t *restricted_pgd = asi->pgd;
	pgd_t *unrestricted_pgd = init_mm.pgd;

	/*
	 * va_0/va_1 should be accessible in the unrestricted address space, but
	 * not in the restricted.
	 */
	KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, va_0));
	KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, va_1));
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_1));

	/*
	 * After mapping the first half of the region, the first half should be
	 * accessible in the restricted address space, but the second half
	 * should not.
	 */
	KUNIT_ASSERT_EQ(test, asi_map(ASI_GLOBAL_NONSENSITIVE, (void *)va_0, PAGE_SIZE), 0);
	KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_1));

	/* Map the entire allocated region. */
	KUNIT_ASSERT_EQ(test, asi_map(ASI_GLOBAL_NONSENSITIVE, (void *)va_0, size), 0);
	KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, va_1));

	/* Unmap the first half of the region */
	asi_unmap(ASI_GLOBAL_NONSENSITIVE, (void *)va_0, PAGE_SIZE);
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, va_1));

	/* Unmap the entire region */
	asi_unmap(ASI_GLOBAL_NONSENSITIVE, (void *)va_0, size);
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_1));
}

static struct kunit_case asi_test_cases[] = {
	KUNIT_CASE(test_asi_map_global_nonsensitive),
	{}
};

static unsigned long taint_pre;

static int store_taint_pre(struct kunit *test)
{
	taint_pre = get_taint();
	return 0;
}

static void check_taint_post(struct kunit *test)
{
	unsigned long new_taint = get_taint() & ~taint_pre;

	KUNIT_EXPECT_EQ_MSG(test, new_taint, 0,
		"Kernel newly tainted after test. Maybe a WARN?");
}

static struct kunit_suite asi_test_suite = {
	.name = "asi",
	.init = store_taint_pre,
	.exit = check_taint_post,
	.test_cases = asi_test_cases,
};

kunit_test_suite(asi_test_suite);

MODULE_LICENSE("GPL");
