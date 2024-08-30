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
#include <asm/set_memory.h>

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

static void test_asi_state(struct kunit *test)
{
	struct asi_test_info *info = setup_test_asi(test, NULL);
	struct asi *asi = info->asi;

	preempt_disable();

	asi_enter(asi);
	KUNIT_EXPECT_TRUE(test, asi_is_restricted());
	KUNIT_EXPECT_FALSE(test, asi_is_relaxed());

	asi_relax();
	KUNIT_EXPECT_TRUE(test, asi_is_restricted());
	KUNIT_EXPECT_TRUE(test, asi_is_relaxed());

	asi_exit();
	KUNIT_EXPECT_FALSE(test, asi_is_restricted());
	KUNIT_EXPECT_TRUE(test, asi_is_relaxed());

	preempt_enable();
}

/*******************************************************************************
 * ASI Hooks
 *
 * Test ASI callbacks on ASI transitions among states.
 ******************************************************************************/
static int post_enter_cnt = 0;
static int pre_exit_cnt = 0;

static void post_asi_enter_cnt_hook(void)
{
	post_enter_cnt++;
}

static void pre_asi_exit_cnt_hook(void)
{
	pre_exit_cnt++;
}

struct asi_hooks asi_cnt_hooks = {
	.post_asi_enter = post_asi_enter_cnt_hook,
	.pre_asi_exit = pre_asi_exit_cnt_hook,
};

static void reset_asi_cnt_hooks(void)
{
	post_enter_cnt = 0;
	pre_exit_cnt = 0;
}

static void test_asi_hooks(struct kunit *test)
{
	struct asi_test_info *info = setup_test_asi(test, &asi_cnt_hooks);
	struct asi *asi = info->asi;

	reset_asi_cnt_hooks();

	/* Enter hook is called when entering a restricted domain */
	preempt_disable();
	asi_enter(asi);
	KUNIT_EXPECT_EQ(test, post_enter_cnt, 1);
	KUNIT_EXPECT_EQ(test, pre_exit_cnt, 0);

	/* Enter hook is not called if we do not leave the restricted domain */
	asi_relax();
	asi_enter(asi);
	KUNIT_EXPECT_EQ(test, post_enter_cnt, 1);
	KUNIT_EXPECT_EQ(test, pre_exit_cnt, 0);

	/*
	 * Exit hook is called whenever we leave a resticted domain.
	 * Since we do not expect return to user while running kunit tests,
	 * use that as a reason to avoid possible false positives, e.g. due to
	 * a #PF (in an intr handler).
	 */
	asi_relax();
	asi_exit();
	KUNIT_EXPECT_EQ(test, post_enter_cnt, pre_exit_cnt);
	KUNIT_EXPECT_EQ(test, pre_exit_cnt, 1);

	preempt_enable();
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

static pte_t *lookup_address_asi_global(unsigned long addr, int *level)
{
	pgd_t *restricted_pgd = asi_pgd(ASI_GLOBAL_NONSENSITIVE);

	return lookup_address_in_pgd(pgd_offset_pgd(restricted_pgd, addr),
				     addr, level);
}

static void action_vunmap(void *ctx)
{
	vunmap(ctx);
}

static void *do_vmap(struct kunit *test, struct page **pages,
		     unsigned int count, unsigned long flags, pgprot_t prot)
{
	void *addr = vmap(pages, count, flags, prot);

	KUNIT_ASSERT_NOT_NULL(test, addr);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, action_vunmap, addr), 0);
	return addr;
}

static void test_change_page_attr(struct kunit *test)
{
	pte_t *ptep, *restricted_ptep;
	unsigned long laddr, vaddr;
	struct page *page;
	int level;

	kunit_skip(test, "Not yet supported in this branch");

	/*
	 * Allocate a page and make sure it's mapped by a 4K mapping in the
	 * unrestricted page tables so that the mapping is equivalent to that in
	 * the restricted page tables.
	 */
	page = do_alloc_pages(test, GFP_KERNEL, 0);
	laddr = (unsigned long)page_to_virt(page);
	set_memory_4k(laddr, 1);

	/*
	 * Check that the allocated page has equal a writeable mapping in
	 * both the restricted and unrestricted page tables.
	 */
	ptep = lookup_address(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_TRUE(test, pte_write(*restricted_ptep));

	/* Now make the page read-only in the direct map */
	set_memory_ro(laddr, 1);

	/* Check that the direct map mappings are still equal, but are now RO */
	ptep = lookup_address(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_FALSE(test, pte_write(*restricted_ptep));

	/* Restore the mappings to RW and check again */
	set_memory_rw(laddr, 1);

	ptep = lookup_address(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_TRUE(test, pte_write(*restricted_ptep));

	/*
	 * Check that vmap creates an equal writeable mapping in the vmalloc
	 * address space in both the restricted and unrestricted page tables.
	 */
	vaddr = (unsigned long)do_vmap(test, &page, 1, VM_MAP, PAGE_KERNEL);
	ptep = lookup_address(vaddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(vaddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_TRUE(test, pte_write(*restricted_ptep));

	/*
	 * Set the memory to RO again using the vmap address. The same
	 * operations should apply to the direct map aliases as well.
	 */
	set_memory_ro(vaddr, 1);

	/* Check that the vmap mappings are still equal, but are now RO */
	ptep = lookup_address(vaddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(vaddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_FALSE(test, pte_write(*restricted_ptep));

	/* Check that direct map mappings are still equal, but are now RO */
	ptep = lookup_address(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_FALSE(test, pte_write(*restricted_ptep));

	/*
	 * Reset the mappings to RW as some debug code on the page free path
	 * writes to freed pages to poison them.
	 */
	set_memory_rw(vaddr, 1);
}

/*
 * In more recent kernels with large mappings support in vmalloc (v5.13+), this
 * test can be simplified by using a large vmalloc mapping instead of trying to
 * find an existing large mapping in the direct map.
 */
static void test_change_page_attr_split_mapping(struct kunit *test)
{
	int pmd_order = PMD_SHIFT - PAGE_SHIFT;
	pte_t *ptep, *restricted_ptep;
	unsigned long addr, laddr;
	struct page *page;
	int retries = 100;
	int level;

	kunit_skip(test, "Not yet supported in this branch");

	if (!boot_cpu_has(X86_FEATURE_PSE))
		kunit_skip(test, "Large mappings are not supported by the CPU");

	/*
	 * In probe_page_size_mask(), only small mappings are used in the direct
	 * map if debug_pagealloc_enabled() is true.
	 */
	if (debug_pagealloc_enabled())
		kunit_skip(test, "No large mappings in the direct map");

	/* Try to allocate pages with a large mapping in the direct map */
	do {
		page = do_alloc_pages(test, GFP_KERNEL, pmd_order);
		laddr = (unsigned long)page_to_virt(page);
		ptep = lookup_address(laddr, &level);
		KUNIT_ASSERT_NOT_NULL(test, ptep);

		if (level < PG_LEVEL_2M)
			continue;

		/*
		 * Check that the allocated pages have a large mapping in the
		 * ASI page tables as well.  ASI may use 4K mappings even if the
		 * direct map has a 2M mapping if the PMD was already pointing
		 * at a PTEs page as we never free page table pages in ASI.
		 */
		restricted_ptep = lookup_address_asi_global(laddr, &level);
		KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);
		if (level >= PG_LEVEL_2M)
			break;
	} while (--retries);

	if (level < PG_LEVEL_2M)
		kunit_skip(test, "Could not find pages with a large mapping");

	/*
	 * Split the mappings into 4K mappings, and check that they are
	 * equivalent in both the restricted and unrestricted page tables.
	 */
	set_memory_4k(laddr, 1 << pmd_order);
	for (addr = laddr; addr < laddr + PMD_SIZE; addr += PAGE_SIZE) {
		ptep = lookup_address(addr, &level);
		KUNIT_ASSERT_NOT_NULL(test, ptep);
		KUNIT_EXPECT_EQ(test, level, PG_LEVEL_4K);

		restricted_ptep = lookup_address_asi_global(addr, &level);
		KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);
		KUNIT_EXPECT_EQ(test, level, PG_LEVEL_4K);

		KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	}
}

static void action_free_percpu(void __percpu *ptr)
{
	free_percpu(ptr);
}

static void __percpu *do___alloc_percpu(struct kunit *test, size_t sz, size_t align)
{
	void __percpu *pcpu;
	int r;

	pcpu = __alloc_percpu(sz, align);
	KUNIT_ASSERT_NOT_NULL(test, pcpu);

	r = kunit_add_action_or_reset(test, action_free_percpu, pcpu);
	KUNIT_ASSERT_EQ(test, r, 0);

	return pcpu;
}

static DEFINE_PER_CPU(uint64_t, static_percpu_data);
#define DYNAMIC_PCPU_BUF_SZ	(PAGE_SIZE * 2)

/*
 * Verify that statically allocated percpu memory and dynamically
 * allocated percpu memory are mapped in the restricted address space.
 */
static void test_percpu_alloc(struct kunit *test)
{
	struct asi *asi = ASI_GLOBAL_NONSENSITIVE;
	pgd_t *unrestricted_pgd = init_mm.pgd;
	pgd_t *restricted_pgd = asi->pgd;
	uint64_t __percpu *dynamic_pcpu;
	uint64_t test_end_offset = 8;
	uint64_t base, end;
	int cpu;

	BUILD_BUG_ON(test_end_offset > DYNAMIC_PCPU_BUF_SZ);

	dynamic_pcpu = do___alloc_percpu(test, DYNAMIC_PCPU_BUF_SZ, PAGE_SIZE);
	for_each_possible_cpu(cpu) {
		/* Test statically allocated per-cpu data */
		base = (uint64_t)per_cpu_ptr(&static_percpu_data, cpu);

		KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, base));
		KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, base));

		/* Test dynamically allocated per-cpu data */
		base = (uint64_t)per_cpu_ptr(dynamic_pcpu, cpu);
		end = base + DYNAMIC_PCPU_BUF_SZ - test_end_offset;

		KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, base));
		KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, end));
		KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, base));
		KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, end));
	}
}

static struct kunit_case asi_test_cases[] = {
	KUNIT_CASE(test_asi_state),
	KUNIT_CASE(test_asi_hooks),
	KUNIT_CASE(test_asi_map_global_nonsensitive),
	KUNIT_CASE(test_percpu_alloc),
	KUNIT_CASE(test_change_page_attr),
	KUNIT_CASE(test_change_page_attr_split_mapping),
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
MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);
