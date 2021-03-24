// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>

#include <asm/asi.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>

#undef pr_fmt
#define pr_fmt(fmt)     "ASI: " fmt

static struct asi_class asi_class[ASI_MAX_NUM];
static DEFINE_SPINLOCK(asi_class_lock);

DEFINE_PER_CPU_ALIGNED(struct asi_state, asi_cpu_state);
EXPORT_PER_CPU_SYMBOL_GPL(asi_cpu_state);

int asi_register_class(const char *name, uint flags,
		       const struct asi_hooks *ops)
{
	int i;

	if (!boot_cpu_has(X86_FEATURE_ASI))
		return 0;

	VM_BUG_ON(name == NULL);

	spin_lock(&asi_class_lock);

	for (i = 1; i < ASI_MAX_NUM; i++) {
		if (asi_class[i].name == NULL) {
			asi_class[i].name = name;
			asi_class[i].flags = flags;
			if (ops != NULL)
				asi_class[i].ops = *ops;
			break;
		}
	}

	spin_unlock(&asi_class_lock);

	if (i == ASI_MAX_NUM)
		i = -ENOSPC;

	return i;
}
EXPORT_SYMBOL_GPL(asi_register_class);

void asi_unregister_class(int index)
{
	if (!boot_cpu_has(X86_FEATURE_ASI))
		return;

	spin_lock(&asi_class_lock);

	WARN_ON(asi_class[index].name == NULL);
	memset(&asi_class[index], 0, sizeof(struct asi_class));

	spin_unlock(&asi_class_lock);
}
EXPORT_SYMBOL_GPL(asi_unregister_class);

#ifndef mm_inc_nr_p4ds
#define mm_inc_nr_p4ds(mm)	do {} while (false)
#endif

#ifndef mm_dec_nr_p4ds
#define mm_dec_nr_p4ds(mm)	do {} while (false)
#endif

#define pte_offset		pte_offset_kernel

#define DEFINE_ASI_PGTBL_ALLOC(base, level)				\
static level##_t * asi_##level##_alloc(struct asi *asi,			\
				       base##_t *base, ulong addr,	\
				       gfp_t flags)			\
{									\
	if (unlikely(base##_none(*base))) {				\
		ulong pgtbl = get_zeroed_page(flags);			\
		phys_addr_t pgtbl_pa;					\
									\
		if (pgtbl == 0)						\
			return NULL;					\
									\
		pgtbl_pa = __pa(pgtbl);					\
		paravirt_alloc_##level(asi->mm, PHYS_PFN(pgtbl_pa));	\
									\
		if (cmpxchg((ulong *)base, 0,				\
			    pgtbl_pa | _PAGE_TABLE) == 0) {		\
			mm_inc_nr_##level##s(asi->mm);			\
		} else {						\
			paravirt_release_##level(PHYS_PFN(pgtbl_pa));	\
			free_page(pgtbl);				\
		}							\
									\
		/* NOP on native. PV call on Xen. */			\
		set_##base(base, *base);				\
	}								\
	VM_BUG_ON(base##_large(*base));					\
	return level##_offset(base, addr);				\
}

DEFINE_ASI_PGTBL_ALLOC(pgd, p4d)
DEFINE_ASI_PGTBL_ALLOC(p4d, pud)
DEFINE_ASI_PGTBL_ALLOC(pud, pmd)
DEFINE_ASI_PGTBL_ALLOC(pmd, pte)

#define asi_free_dummy(asi, addr)
#define __pmd_free(mm, pmd) free_page((ulong)(pmd))
#define pud_page_vaddr(pud) ((ulong)pud_pgtable(pud))
#define p4d_page_vaddr(p4d) ((ulong)p4d_pgtable(p4d))

static inline unsigned long pte_page_vaddr(pte_t pte)
{
	return (unsigned long)__va(pte_val(pte) & PTE_PFN_MASK);
}

#define DEFINE_ASI_PGTBL_FREE(level, LEVEL, next, free)			\
static void asi_free_##level(struct asi *asi, ulong pgtbl_addr)		\
{									\
	uint i;								\
	level##_t *level = (level##_t *)pgtbl_addr;			\
									\
	for (i = 0; i < PTRS_PER_##LEVEL; i++) {			\
		ulong vaddr;						\
									\
		if (level##_none(level[i]))				\
			continue;					\
									\
		vaddr = level##_page_vaddr(level[i]);			\
									\
		if (!level##_leaf(level[i]))				\
			asi_free_##next(asi, vaddr);			\
		else							\
			VM_WARN(true, "Lingering mapping in ASI %p at %lx",\
				asi, vaddr);				\
	}								\
	paravirt_release_##level(PHYS_PFN(__pa(pgtbl_addr)));		\
	free(asi->mm, level);						\
	mm_dec_nr_##level##s(asi->mm);					\
}

DEFINE_ASI_PGTBL_FREE(pte, PTE, dummy, pte_free_kernel)
DEFINE_ASI_PGTBL_FREE(pmd, PMD, pte, __pmd_free)
DEFINE_ASI_PGTBL_FREE(pud, PUD, pmd, pud_free)
DEFINE_ASI_PGTBL_FREE(p4d, P4D, pud, p4d_free)

static void asi_free_pgd_range(struct asi *asi, uint start, uint end)
{
	uint i;

	for (i = start; i < end; i++)
		if (pgd_present(asi->pgd[i]))
			asi_free_p4d(asi, (ulong)p4d_offset(asi->pgd + i, 0));
}

/*
 * Free the page tables allocated for the given ASI instance.
 * The caller must ensure that all the mappings have already been cleared
 * and appropriate TLB flushes have been issued before calling this function.
 */
static void asi_free_pgd(struct asi *asi)
{
	VM_BUG_ON(asi->mm == &init_mm);

	asi_free_pgd_range(asi, KERNEL_PGD_BOUNDARY, PTRS_PER_PGD);
	free_pages((ulong)asi->pgd, PGD_ALLOCATION_ORDER);
}

static int __init set_asi_param(char *str)
{
	if (strcmp(str, "on") == 0)
		setup_force_cpu_cap(X86_FEATURE_ASI);

	return 0;
}
early_param("asi", set_asi_param);

int asi_init(struct mm_struct *mm, int asi_index)
{
	struct asi *asi = &mm->asi[asi_index];

	if (!boot_cpu_has(X86_FEATURE_ASI))
		return 0;

	/* Index 0 is reserved for special purposes. */
	WARN_ON(asi_index == 0 || asi_index >= ASI_MAX_NUM);
	WARN_ON(asi->pgd != NULL);

	/*
	 * For now, we allocate 2 pages to avoid any potential problems with
	 * KPTI code. This won't be needed once KPTI is folded into the ASI
	 * framework.
	 */
	asi->pgd = (pgd_t *)__get_free_pages(GFP_PGTABLE_USER,
					     PGD_ALLOCATION_ORDER);
	if (!asi->pgd)
		return -ENOMEM;

	asi->class = &asi_class[asi_index];
	asi->mm = mm;

	return 0;
}
EXPORT_SYMBOL_GPL(asi_init);

void asi_destroy(struct asi *asi)
{
	if (!boot_cpu_has(X86_FEATURE_ASI))
		return;

	asi_free_pgd(asi);
	memset(asi, 0, sizeof(struct asi));
}
EXPORT_SYMBOL_GPL(asi_destroy);

void __asi_enter(void)
{
	u64 asi_cr3;
	struct asi *target = this_cpu_read(asi_cpu_state.target_asi);

	VM_BUG_ON(preemptible());
	VM_BUG_ON(current->thread.intr_nest_depth != 0);

	if (!target || target == this_cpu_read(asi_cpu_state.curr_asi))
		return;

	VM_BUG_ON(this_cpu_read(cpu_tlbstate.loaded_mm) ==
		  LOADED_MM_SWITCHING);

	this_cpu_write(asi_cpu_state.curr_asi, target);

	asi_cr3 = build_cr3(target->pgd,
			    this_cpu_read(cpu_tlbstate.loaded_mm_asid));
	write_cr3(asi_cr3);

	if (target->class->ops.post_asi_enter)
		target->class->ops.post_asi_enter();
}

void asi_enter(struct asi *asi)
{
	if (!static_cpu_has(X86_FEATURE_ASI))
		return;

	VM_WARN_ON_ONCE(!asi);

	this_cpu_write(asi_cpu_state.target_asi, asi);
	barrier();

	__asi_enter();
}
EXPORT_SYMBOL_GPL(asi_enter);

void asi_exit(void)
{
	u64 unrestricted_cr3;
	struct asi *asi;

	if (!static_cpu_has(X86_FEATURE_ASI))
		return;

	preempt_disable();

	VM_BUG_ON(this_cpu_read(cpu_tlbstate.loaded_mm) ==
		  LOADED_MM_SWITCHING);

	asi = this_cpu_read(asi_cpu_state.curr_asi);

	if (asi) {
		if (asi->class->ops.pre_asi_exit)
			asi->class->ops.pre_asi_exit();

		unrestricted_cr3 =
			build_cr3(this_cpu_read(cpu_tlbstate.loaded_mm)->pgd,
				  this_cpu_read(cpu_tlbstate.loaded_mm_asid));

		write_cr3(unrestricted_cr3);
		this_cpu_write(asi_cpu_state.curr_asi, NULL);
	}

	preempt_enable();
}
EXPORT_SYMBOL_GPL(asi_exit);

void asi_init_mm_state(struct mm_struct *mm)
{
	memset(mm->asi, 0, sizeof(mm->asi));
}
