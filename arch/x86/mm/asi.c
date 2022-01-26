// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/memcontrol.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/module.h>

#include <asm/asi.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>

#include "mm_internal.h"
#include "../../../mm/internal.h"

#undef pr_fmt
#define pr_fmt(fmt)     "ASI: " fmt

static struct asi_class asi_class[ASI_MAX_NUM] __asi_not_sensitive;
static DEFINE_SPINLOCK(asi_class_lock __asi_not_sensitive);

DEFINE_PER_CPU_ALIGNED(struct asi_state, asi_cpu_state);
EXPORT_PER_CPU_SYMBOL_GPL(asi_cpu_state);

__aligned(PAGE_SIZE) pgd_t asi_global_nonsensitive_pgd[PTRS_PER_PGD];

DEFINE_STATIC_KEY_FALSE(asi_local_map_initialized);
EXPORT_SYMBOL(asi_local_map_initialized);

unsigned long asi_local_map_base __ro_after_init;
EXPORT_SYMBOL(asi_local_map_base);

unsigned long vmalloc_global_nonsensitive_start __ro_after_init;
EXPORT_SYMBOL(vmalloc_global_nonsensitive_start);

unsigned long vmalloc_local_nonsensitive_end __ro_after_init;
EXPORT_SYMBOL(vmalloc_local_nonsensitive_end);

/* Approximate percent only. Rounded to PGDIR_SIZE boundary. */
static uint vmalloc_local_nonsensitive_percent __ro_after_init = 50;
core_param(vmalloc_local_nonsensitive_percent,
	   vmalloc_local_nonsensitive_percent, uint, 0444);

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

static ulong get_pgtbl_from_pool(struct asi_pgtbl_pool *pool)
{
	struct page *pgtbl;

	if (pool->count == 0)
		return 0;

	pgtbl = pool->pgtbl_list;
	pool->pgtbl_list = pgtbl->asi_pgtbl_pool_next;
	pgtbl->asi_pgtbl_pool_next = NULL;
	pool->count--;

	return (ulong)page_address(pgtbl);
}

static void return_pgtbl_to_pool(struct asi_pgtbl_pool *pool, ulong virt)
{
	struct page *pgtbl = virt_to_page(virt);

	pgtbl->asi_pgtbl_pool_next = pool->pgtbl_list;
	pool->pgtbl_list = pgtbl;
	pool->count++;
}

int asi_fill_pgtbl_pool(struct asi_pgtbl_pool *pool, uint count, gfp_t flags)
{
	if (!static_cpu_has(X86_FEATURE_ASI))
		return 0;

	while (pool->count < count) {
		ulong pgtbl = get_zeroed_page(flags);

		if (!pgtbl)
			return -ENOMEM;

		return_pgtbl_to_pool(pool, pgtbl);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(asi_fill_pgtbl_pool);

void asi_clear_pgtbl_pool(struct asi_pgtbl_pool *pool)
{
	while (pool->count > 0)
		free_page(get_pgtbl_from_pool(pool));
}
EXPORT_SYMBOL_GPL(asi_clear_pgtbl_pool);

static void asi_clone_pgd(pgd_t *dst_table, pgd_t *src_table, size_t addr)
{
	pgd_t *src = pgd_offset_pgd(src_table, addr);
	pgd_t *dst = pgd_offset_pgd(dst_table, addr);

	if (!pgd_val(*dst))
		set_pgd(dst, *src);
	else
		VM_BUG_ON(pgd_val(*dst) != pgd_val(*src));
}

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
				       gfp_t flags,			\
				       struct asi_pgtbl_pool *pool)	\
{									\
	if (unlikely(base##_none(*base))) {				\
		ulong pgtbl = pool ? get_pgtbl_from_pool(pool)		\
				   : get_zeroed_page(flags);		\
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
			if (pool)					\
				return_pgtbl_to_pool(pool, pgtbl);	\
			else						\
				free_page(pgtbl);			\
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
 *
 * For standard non-sensitive ASI classes, the page tables shared with the
 * master pseudo-PGD are not freed.
 */
static void asi_free_pgd(struct asi *asi)
{
	VM_BUG_ON(asi->mm == &init_mm);

	if (!(asi->class->flags & ASI_MAP_STANDARD_NONSENSITIVE))
		asi_free_pgd_range(asi, KERNEL_PGD_BOUNDARY, PTRS_PER_PGD);

	free_pages((ulong)asi->pgd, PGD_ALLOCATION_ORDER);
}

static int __init set_asi_param(char *str)
{
	if (strcmp(str, "on") == 0) {
		/* TODO: We should eventually add support for KASAN. */
		if (IS_ENABLED(CONFIG_KASAN)) {
			pr_warn("ASI is currently not supported with KASAN");
			return 0;
		}

		/*
		 * We create a second copy of the direct map for the aliased
		 * ASI Local Map, so we can support only half of the max
		 * amount of RAM. That should be fine with 5 level page tables
		 * but could be an issue with 4 level page tables.
		 *
		 * An alternative vmap-style implementation of an aliased local
		 * region is possible without this limitation, but that has
		 * some other compromises and would be usable only if
		 * we trim down the types of structures marked as local
		 * non-sensitive by limiting the designation to only those that
		 * really are locally non-sensitive but globally sensitive.
		 * That is certainly ideal and likely feasible, and would also
		 * allow removal of some other relatively complex infrastructure
		 * introduced in later patches. But we are including this
		 * implementation here just for demonstration of a fully general
		 * mechanism.
		 *
		 * An altogether different alternative to a separate aliased
		 * region is also possible by just partitioning the regular
		 * direct map (either statically or dynamically via additional
		 * page-block types), which is certainly feasible but would
		 * require more effort to implement properly.
		 */
		if (set_phys_mem_limit(MAXMEM / 2))
			pr_warn("Limiting Memory Size to %llu", MAXMEM / 2);

		asi_local_map_base = __ASI_LOCAL_MAP_BASE;

		setup_force_cpu_cap(X86_FEATURE_ASI);
	}

	return 0;
}
early_param("asi", set_asi_param);

static int asi_map_percpu(struct asi *asi, void *percpu_addr, size_t len)
{
       int cpu, err;
       void *ptr;

       for_each_possible_cpu(cpu) {
               ptr = per_cpu_ptr(percpu_addr, cpu);
               err = asi_map(asi, ptr, len);
               if (err)
                       return err;
       }

       return 0;
}

static void asi_unmap_percpu(struct asi *asi, void *percpu_addr, size_t len)
{
       int cpu;
       void *ptr;

       for_each_possible_cpu(cpu) {
               ptr = per_cpu_ptr(percpu_addr, cpu);
               asi_unmap(asi, ptr, len, true);
       }
}

/* asi_load_module() is called from layout_and_allocate() in kernel/module.c
 * We map the module and its data in init_mm.asi_pgd[0].
*/
int asi_load_module(struct module* module)
{
        int err = 0;

        /* Map the cod/text */
        err = asi_map(ASI_GLOBAL_NONSENSITIVE,
                      module->core_layout.base,
                      module->core_layout.ro_after_init_size );
        if (err)
                return err;

        /* Map global variables annotated as non-sensitive for ASI */
        err = asi_map(ASI_GLOBAL_NONSENSITIVE,
                      module->core_layout.base +
                      module->core_layout.asi_section_offset,
                      module->core_layout.asi_section_size );
        if (err)
                return err;

        /* Map global variables annotated as non-sensitive for ASI */
        err = asi_map(ASI_GLOBAL_NONSENSITIVE,
                      module->core_layout.base +
                      module->core_layout.asi_readmostly_section_offset,
                      module->core_layout.asi_readmostly_section_size);
        if (err)
                return err;

        /* Map .data.once section as well */
        err = asi_map(ASI_GLOBAL_NONSENSITIVE,
                      module->core_layout.base +
                      module->core_layout.once_section_offset,
                      module->core_layout.once_section_size );
        if (err)
                return err;

	err = asi_map_percpu(ASI_GLOBAL_NONSENSITIVE,
			     module->percpu_asi,
			     module->percpu_asi_size );
        if (err)
                return err;

       return 0;
}
EXPORT_SYMBOL_GPL(asi_load_module);

void asi_unload_module(struct module* module)
{
        asi_unmap(ASI_GLOBAL_NONSENSITIVE,
                      module->core_layout.base,
                      module->core_layout.ro_after_init_size, true);

        asi_unmap(ASI_GLOBAL_NONSENSITIVE,
                      module->core_layout.base +
                      module->core_layout.asi_section_offset,
                      module->core_layout.asi_section_size, true);

        asi_unmap(ASI_GLOBAL_NONSENSITIVE,
                      module->core_layout.base +
                      module->core_layout.asi_readmostly_section_offset,
                      module->core_layout.asi_readmostly_section_size, true);

        asi_unmap(ASI_GLOBAL_NONSENSITIVE,
                      module->core_layout.base +
                      module->core_layout.once_section_offset,
                      module->core_layout.once_section_size, true);

	asi_unmap_percpu(ASI_GLOBAL_NONSENSITIVE, module->percpu_asi,
			 module->percpu_asi_size);

}

static int __init asi_global_init(void)
{
	uint i, n;

	if (!boot_cpu_has(X86_FEATURE_ASI))
		return 0;

	preallocate_toplevel_pgtbls(asi_global_nonsensitive_pgd,
				    PAGE_OFFSET,
				    PAGE_OFFSET + PFN_PHYS(max_possible_pfn) - 1,
				    "ASI Global Non-sensitive direct map");

	preallocate_toplevel_pgtbls(asi_global_nonsensitive_pgd,
				    VMALLOC_GLOBAL_NONSENSITIVE_START,
				    VMALLOC_GLOBAL_NONSENSITIVE_END,
				    "ASI Global Non-sensitive vmalloc");

	/* TODO: We should also handle memory hotplug. */
	n = DIV_ROUND_UP(PFN_PHYS(max_pfn), PGDIR_SIZE);
	for (i = 0; i < n; i++)
		swapper_pg_dir[pgd_index(ASI_LOCAL_MAP) + i] =
			swapper_pg_dir[pgd_index(PAGE_OFFSET) + i];

	static_branch_enable(&asi_local_map_initialized);

        pcpu_map_asi_reserved_chunk();

	return 0;
}
subsys_initcall(asi_global_init)

/* We're assuming we hold mm->asi_init_lock */
static void __asi_destroy(struct asi *asi)
{
	if (!boot_cpu_has(X86_FEATURE_ASI))
		return;

        /* If refcount is non-zero, it means asi_init() was called multiple
         * times. We free the asi pgd only when the last VM is destroyed. */
        if (--(asi->asi_ref_count) > 0)
                return;

	asi_free_pgd(asi);
	memset(asi, 0, sizeof(struct asi));
}

int asi_init(struct mm_struct *mm, int asi_index, struct asi **out_asi)
{
        int err = 0;
        struct asi *asi = &mm->asi[asi_index];

	*out_asi = NULL;

	if (!boot_cpu_has(X86_FEATURE_ASI) || !mm->asi_enabled)
		return 0;

	/* Index 0 is reserved for special purposes. */
	WARN_ON(asi_index == 0 || asi_index >= ASI_MAX_NUM);
	WARN_ON(asi->pgd != NULL);

        /* Currently, mm and asi structs are conceptually tied together. In
         * future implementations an asi object might be unrelated to a specicic
         * mm. In that future implementation - the mutex will have to be inside
         * asi. */
	mutex_lock(&mm->asi_init_lock);

        if (asi->asi_ref_count++ > 0)
                goto exit_unlock; /* err is 0 */

	/*
	 * For now, we allocate 2 pages to avoid any potential problems with
	 * KPTI code. This won't be needed once KPTI is folded into the ASI
	 * framework.
	 */
	asi->pgd = (pgd_t *)__get_free_pages(GFP_PGTABLE_USER,
					     PGD_ALLOCATION_ORDER);
	if (!asi->pgd) {
                err = -ENOMEM;
		goto exit_unlock;
        }

	asi->class = &asi_class[asi_index];
	asi->mm = mm;
	asi->pcid_index = asi_index;
	rwlock_init(&asi->user_map_lock);

	if (asi->class->flags & ASI_MAP_STANDARD_NONSENSITIVE) {
		uint i;

		for (i = KERNEL_PGD_BOUNDARY; i < pgd_index(ASI_LOCAL_MAP); i++)
			set_pgd(asi->pgd + i, asi_global_nonsensitive_pgd[i]);

		for (i = pgd_index(ASI_LOCAL_MAP);
		     i <= pgd_index(ASI_LOCAL_MAP + PFN_PHYS(max_possible_pfn));
		     i++)
			set_pgd(asi->pgd + i, mm->asi[0].pgd[i]);

		for (i = pgd_index(VMALLOC_LOCAL_NONSENSITIVE_START);
		     i <= pgd_index(VMALLOC_LOCAL_NONSENSITIVE_END); i++)
			set_pgd(asi->pgd + i, mm->asi[0].pgd[i]);

		for (i = pgd_index(VMALLOC_GLOBAL_NONSENSITIVE_START);
		     i < PTRS_PER_PGD; i++)
			set_pgd(asi->pgd + i, asi_global_nonsensitive_pgd[i]);

		asi->tlb_gen = &mm->asi[0].__tlb_gen;
	} else {
		asi->tlb_gen = &asi->__tlb_gen;
		atomic64_set(asi->tlb_gen, 1);
	}

exit_unlock:
	if (err)
		__asi_destroy(asi);

        /* This unlock signals future asi_init() callers that we finished. */
	mutex_unlock(&mm->asi_init_lock);

	if (!err)
		*out_asi = asi;
	return err;
}
EXPORT_SYMBOL_GPL(asi_init);

void asi_destroy(struct asi *asi)
{
        struct mm_struct *mm;

	if (!boot_cpu_has(X86_FEATURE_ASI) || !asi)
		return;

        mm = asi->mm;
        mutex_lock(&mm->asi_init_lock);
        __asi_destroy(asi);
        mutex_unlock(&mm->asi_init_lock);
}
EXPORT_SYMBOL_GPL(asi_destroy);

void asi_get_latest_tlb_gens(struct asi *asi, u64 *latest_local_tlb_gen,
			     u64 *latest_global_tlb_gen)
{
	if (likely(asi->class->flags & ASI_MAP_STANDARD_NONSENSITIVE))
		*latest_global_tlb_gen =
			atomic64_read(ASI_GLOBAL_NONSENSITIVE->tlb_gen);
	else
		*latest_global_tlb_gen = 0;

	*latest_local_tlb_gen = atomic64_read(asi->tlb_gen);
}

void __asi_enter(void)
{
	u64 asi_cr3;
	u16 pcid;
	bool need_flush = false;
	u64 latest_local_tlb_gen, latest_global_tlb_gen;
	struct tlb_state *tlb_state;
	struct asi_tlb_context *tlb_context;
	struct asi *target = this_cpu_read(asi_cpu_state.target_asi);

	VM_BUG_ON(preemptible());
	VM_BUG_ON(current->thread.intr_nest_depth != 0);

	if (!target || target == this_cpu_read(asi_cpu_state.curr_asi))
		return;

	tlb_state = this_cpu_ptr(&cpu_tlbstate);
	VM_BUG_ON(tlb_state->loaded_mm == LOADED_MM_SWITCHING);

	this_cpu_write(asi_cpu_state.curr_asi, target);

	if (static_cpu_has(X86_FEATURE_PCID)) {
		/*
		 * curr_asi write has to happen before the asi->tlb_gen reads
		 * below.
		 *
		 * See comments in asi_flush_tlb_range().
		 */
		smp_mb();

		asi_get_latest_tlb_gens(target, &latest_local_tlb_gen,
					&latest_global_tlb_gen);

		tlb_context = &tlb_state->ctxs[tlb_state->loaded_mm_asid]
					.asi_context[target->pcid_index];

		if (READ_ONCE(tlb_context->local_tlb_gen) < latest_local_tlb_gen
		    || READ_ONCE(tlb_context->global_tlb_gen) <
		       latest_global_tlb_gen)
			need_flush = true;
	}

	/*
	 * It is possible that we may get a TLB flush IPI after
	 * already calculating need_flush, in which case we won't do the
	 * flush below. However, in that case the interrupt epilog
	 * will also call __asi_enter(), which will do the flush.
	 */

	pcid = asi_pcid(target, this_cpu_read(cpu_tlbstate.loaded_mm_asid));
	asi_cr3 = build_cr3_pcid(target->pgd, pcid, !need_flush);
	write_cr3(asi_cr3);

	if (static_cpu_has(X86_FEATURE_PCID)) {
		/*
		 * There is a small possibility that an interrupt happened
		 * after the read of the latest_*_tlb_gen above and when
		 * that interrupt did an asi_enter() upon return, it read
		 * an even higher latest_*_tlb_gen and already updated the
		 * tlb_context->*tlb_gen accordingly. In that case, the
		 * following will move back the tlb_context->*tlb_gen. That
		 * isn't ideal, but it should not cause any correctness issues.
		 * We may just end up doing an unnecessary TLB flush on the next
		 * asi_enter(). If we really needed to avoid that, we could
		 * just do a cmpxchg, but it is likely not necessary.
		 */
		WRITE_ONCE(tlb_context->local_tlb_gen, latest_local_tlb_gen);
		WRITE_ONCE(tlb_context->global_tlb_gen, latest_global_tlb_gen);
	}

	if (target->class->ops.post_asi_enter)
		target->class->ops.post_asi_enter();
}

void asi_enter(struct asi *asi)
{
	if (!static_cpu_has(X86_FEATURE_ASI) || !asi)
		return;

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
		bool need_flush = false;

		if (asi->class->ops.pre_asi_exit)
			asi->class->ops.pre_asi_exit();

		if (static_cpu_has(X86_FEATURE_PCID) &&
		    !static_cpu_has(X86_FEATURE_INVPCID_SINGLE)) {
			need_flush = this_cpu_read(
					cpu_tlbstate.kern_pcid_needs_flush);
			this_cpu_write(cpu_tlbstate.kern_pcid_needs_flush,
				       false);
		}

		/*
		 * It is possible that we may get a TLB flush IPI after
		 * already reading need_flush. However, in that case the IPI
		 * will not set flush_pending for the unrestricted address
		 * space, as that is done by flush_tlb_one_user() only if
		 * asi_intr_nest_depth() is 0.
		 */

		unrestricted_cr3 = build_cr3_pcid(
			this_cpu_read(cpu_tlbstate.loaded_mm)->pgd,
			kern_pcid(this_cpu_read(cpu_tlbstate.loaded_mm_asid)),
			!need_flush);

		write_cr3(unrestricted_cr3);
		this_cpu_write(asi_cpu_state.curr_asi, NULL);
	}

	preempt_enable();
}
EXPORT_SYMBOL_GPL(asi_exit);

int asi_init_mm_state(struct mm_struct *mm)
{
	struct mem_cgroup *memcg = get_mem_cgroup_from_mm(mm);

	memset(mm->asi, 0, sizeof(mm->asi));
	mm->asi_enabled = false;
	RCU_INIT_POINTER(mm->local_slab_caches, NULL);
	mm->local_slab_caches_array_size = 0;

	/*
	 * TODO: In addition to a cgroup flag, we may also want a per-process
	 * flag.
	 */
        if (memcg) {
		mm->asi_enabled = boot_cpu_has(X86_FEATURE_ASI) &&
				  memcg->use_asi;
		css_put(&memcg->css);
	}

	if (!mm->asi_enabled)
		return 0;

	mm->asi[0].tlb_gen = &mm->asi[0].__tlb_gen;
	atomic64_set(mm->asi[0].tlb_gen, 1);
	mm->asi[0].mm = mm;
	mm->asi[0].pgd = (pgd_t *)__get_free_page(GFP_PGTABLE_USER);
	if (!mm->asi[0].pgd)
		return -ENOMEM;

	return 0;
}

void asi_free_mm_state(struct mm_struct *mm)
{
	if (!boot_cpu_has(X86_FEATURE_ASI) || !mm->asi_enabled)
		return;

	free_local_slab_caches(mm);

	asi_free_pgd_range(&mm->asi[0], pgd_index(ASI_LOCAL_MAP),
			   pgd_index(ASI_LOCAL_MAP +
				     PFN_PHYS(max_possible_pfn)) + 1);

	asi_free_pgd_range(&mm->asi[0],
			   pgd_index(VMALLOC_LOCAL_NONSENSITIVE_START),
			   pgd_index(VMALLOC_LOCAL_NONSENSITIVE_END) + 1);

	free_page((ulong)mm->asi[0].pgd);
}

static bool is_page_within_range(size_t addr, size_t page_size,
				 size_t range_start, size_t range_end)
{
	size_t page_start, page_end, page_mask;

	page_mask = ~(page_size - 1);
	page_start = addr & page_mask;
	page_end = page_start + page_size;

	return page_start >= range_start && page_end <= range_end;
}

static bool follow_physaddr(struct mm_struct *mm, size_t virt,
			    phys_addr_t *phys, size_t *page_size, ulong *flags)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

#define follow_addr_at_level(base, level, LEVEL)			\
	do {								\
		*page_size = LEVEL##_SIZE;				\
		level = level##_offset(base, virt);			\
		if (!level##_present(*level))				\
			return false;					\
									\
		if (level##_large(*level)) {				\
			*phys = PFN_PHYS(level##_pfn(*level)) |		\
				(virt & ~LEVEL##_MASK);			\
			*flags = level##_flags(*level);			\
			return true;					\
		}							\
	} while (false)

	follow_addr_at_level(mm, pgd, PGDIR);
	follow_addr_at_level(pgd, p4d, P4D);
	follow_addr_at_level(p4d, pud, PUD);
	follow_addr_at_level(pud, pmd, PMD);

	*page_size = PAGE_SIZE;
	pte = pte_offset_map(pmd, virt);
	if (!pte)
		return false;

	if (!pte_present(*pte)) {
		pte_unmap(pte);
		return false;
	}

	*phys = PFN_PHYS(pte_pfn(*pte)) | (virt & ~PAGE_MASK);
	*flags = pte_flags(*pte);

	pte_unmap(pte);
	return true;

#undef follow_addr_at_level
}

/*
 * Map the given range into the ASI page tables. The source of the mapping
 * is the regular unrestricted page tables.
 *
 * If the source mapping is a large page and the range being mapped spans the
 * entire large page, then it will be mapped as a large page in the ASI page
 * tables too. If the range does not span the entire huge page, then it will
 * be mapped as smaller pages. In that case, the implementation is slightly
 * inefficient, as it will walk the source page tables again for each small
 * destination page, but that should be ok for now, as usually in such cases,
 * the range would consist of a small-ish number of pages.
 */
int __asi_map(struct asi *asi, size_t start, size_t end, gfp_t gfp_flags,
	      struct asi_pgtbl_pool *pool,
	      size_t allowed_start, size_t allowed_end)
{
	size_t virt;
	size_t page_size;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end & ~PAGE_MASK);
	VM_BUG_ON(end > allowed_end);
	VM_BUG_ON(start < allowed_start);

	gfp_flags &= GFP_RECLAIM_MASK;

	if (asi->mm != &init_mm)
		gfp_flags |= __GFP_ACCOUNT;

	for (virt = start; virt < end; virt = ALIGN(virt + 1, page_size)) {
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		phys_addr_t phys;
		ulong flags;

		if (!follow_physaddr(asi->mm, virt, &phys, &page_size, &flags))
			continue;

#define MAP_AT_LEVEL(base, BASE, level, LEVEL) {			       \
			if (base##_large(*base)) {			       \
				VM_BUG_ON(PHYS_PFN(phys & BASE##_MASK) !=      \
					  base##_pfn(*base));		       \
				continue;				       \
			}						       \
									       \
			level = asi_##level##_alloc(asi, base, virt,	       \
						    gfp_flags, pool);	       \
			if (!level)					       \
				return -ENOMEM;				       \
									       \
			if (page_size >= LEVEL##_SIZE &&		       \
			    (level##_none(*level) || level##_leaf(*level)) &&  \
			    is_page_within_range(virt, LEVEL##_SIZE,	       \
						 allowed_start, allowed_end)) {\
				page_size = LEVEL##_SIZE;		       \
				phys &= LEVEL##_MASK;			       \
									       \
				if (level##_none(*level))		       \
					set_##level(level,		       \
						    __##level(phys | flags));  \
				else					       \
					VM_BUG_ON(level##_pfn(*level) !=       \
						  PHYS_PFN(phys));	       \
				continue;				       \
			}						       \
		}

		pgd = pgd_offset_pgd(asi->pgd, virt);

		MAP_AT_LEVEL(pgd, PGDIR, p4d, P4D);
		MAP_AT_LEVEL(p4d, P4D, pud, PUD);
		MAP_AT_LEVEL(pud, PUD, pmd, PMD);
		MAP_AT_LEVEL(pmd, PMD, pte, PAGE);

		VM_BUG_ON(true); /* Should never reach here. */
#undef MAP_AT_LEVEL
	}

	return 0;
}

/*
 * Maps the given kernel address range into the ASI page tables.
 *
 * The caller MUST ensure that the source mapping will not change during this
 * function. For dynamic kernel memory, this is generally ensured by mapping
 * the memory within the allocator.
 */
int asi_map_gfp(struct asi *asi, void *addr, size_t len, gfp_t gfp_flags)
{
	size_t start = (size_t)addr;
	size_t end = start + len;

	if (!static_cpu_has(X86_FEATURE_ASI) || !asi)
		return 0;

	VM_BUG_ON(start < TASK_SIZE_MAX);

	return __asi_map(asi, start, end, gfp_flags, NULL, start, end);
}

int asi_map(struct asi *asi, void *addr, size_t len)
{
	return asi_map_gfp(asi, addr, len, GFP_KERNEL);
}

/*
 * Unmap a kernel address range previously mapped into the ASI page tables.
 * The caller must ensure appropriate TLB flushing.
 *
 * The area being unmapped must be a whole previously mapped region (or regions)
 * Unmapping a partial subset of a previously mapped region is not supported.
 * That will work, but may end up unmapping more than what was asked for, if
 * the mapping contained huge pages.
 *
 * Note that higher order direct map allocations are allowed to be partially
 * freed. If it turns out that that actually happens for any of the
 * non-sensitive allocations, then the above limitation may be a problem. For
 * now, vunmap_pgd_range() will emit a warning if this situation is detected.
 */
void asi_unmap(struct asi *asi, void *addr, size_t len, bool flush_tlb)
{
	size_t start = (size_t)addr;
	size_t end = start + len;
	pgtbl_mod_mask mask = 0;

	if (!static_cpu_has(X86_FEATURE_ASI) || !asi || !len)
		return;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(len & ~PAGE_MASK);
	VM_BUG_ON(start < TASK_SIZE_MAX);

	vunmap_pgd_range(asi->pgd, start, end, &mask, false);

	if (flush_tlb)
		asi_flush_tlb_range(asi, addr, len);
}

void *asi_va(unsigned long pa)
{
	struct page *page = pfn_to_page(PHYS_PFN(pa));

	return (void *)(pa + (PageLocalNonSensitive(page)
			      ? ASI_LOCAL_MAP : PAGE_OFFSET));
}
EXPORT_SYMBOL(asi_va);

static bool is_addr_in_local_nonsensitive_range(size_t addr)
{
	return addr >= ASI_LOCAL_MAP &&
	       addr < VMALLOC_GLOBAL_NONSENSITIVE_START;
}

static void asi_clone_user_pgd(struct asi *asi, size_t addr)
{
	pgd_t *src = pgd_offset_pgd(asi->mm->pgd, addr);
	pgd_t *dst = pgd_offset_pgd(asi->pgd, addr);
	pgdval_t old_src, curr_src;

	if (pgd_val(*dst))
		return;

	VM_BUG_ON(!irqs_disabled());

	/*
	 * This synchronizes against the PGD entry getting cleared by
	 * free_pgd_range(). That path has the following steps:
	 * 1. pgd_clear
	 * 2. asi_clear_user_pgd
	 * 3. Remote TLB Flush
	 * 4. Free page tables
	 *
	 * (3) will be blocked for the duration of this function because the
	 * IPI will remain pending until interrupts are re-enabled.
	 *
	 * The following loop ensures that if we read the PGD value before
	 * (1) and write it after (2), we will re-read the value and write
	 * the new updated value.
	 */
	curr_src = pgd_val(*src);
	do {
		set_pgd(dst, __pgd(curr_src));
		smp_mb();
		old_src = curr_src;
		curr_src = pgd_val(*src);
	} while (old_src != curr_src);
}

void asi_do_lazy_map(struct asi *asi, size_t addr)
{
	if (!static_cpu_has(X86_FEATURE_ASI) || !asi)
		return;

	if ((asi->class->flags & ASI_MAP_STANDARD_NONSENSITIVE) &&
	    is_addr_in_local_nonsensitive_range(addr))
		asi_clone_pgd(asi->pgd, asi->mm->asi[0].pgd, addr);
	else if ((asi->class->flags & ASI_MAP_ALL_USERSPACE) &&
		 addr < TASK_SIZE_MAX)
		asi_clone_user_pgd(asi, addr);
}

/*
 * Should be called after asi_map(ASI_LOCAL_NONSENSITIVE,...) for any mapping
 * that is required to exist prior to asi_enter() (e.g. thread stacks)
 */
void asi_sync_mapping(struct asi *asi, void *start, size_t len)
{
	size_t addr = (size_t)start;
	size_t end = addr + len;

	if (!static_cpu_has(X86_FEATURE_ASI) || !asi)
		return;

	if ((asi->class->flags & ASI_MAP_STANDARD_NONSENSITIVE) &&
	    is_addr_in_local_nonsensitive_range(addr))
		for (; addr < end; addr = pgd_addr_end(addr, end))
			asi_clone_pgd(asi->pgd, asi->mm->asi[0].pgd, addr);
}

void __init asi_vmalloc_init(void)
{
	uint start_index = pgd_index(VMALLOC_START);
	uint end_index = pgd_index(VMALLOC_END);
	uint global_start_index;

	if (!boot_cpu_has(X86_FEATURE_ASI)) {
		vmalloc_global_nonsensitive_start = VMALLOC_START;
		vmalloc_local_nonsensitive_end = VMALLOC_END;
		return;
	}

	if (vmalloc_local_nonsensitive_percent == 0) {
		vmalloc_local_nonsensitive_percent = 1;
		pr_warn("vmalloc_local_nonsensitive_percent must be non-zero");
	}

	if (vmalloc_local_nonsensitive_percent >= 100) {
		vmalloc_local_nonsensitive_percent = 99;
		pr_warn("vmalloc_local_nonsensitive_percent must be less than 100");
	}

	global_start_index = start_index + (end_index - start_index) *
			     vmalloc_local_nonsensitive_percent / 100;
	global_start_index = max(global_start_index, start_index + 1);

	vmalloc_global_nonsensitive_start = -(PTRS_PER_PGD - global_start_index)
					    * PGDIR_SIZE;
	vmalloc_local_nonsensitive_end = vmalloc_global_nonsensitive_start - 1;

	pr_debug("vmalloc_global_nonsensitive_start = %llx",
		 vmalloc_global_nonsensitive_start);

	VM_BUG_ON(vmalloc_local_nonsensitive_end >= VMALLOC_END);
	VM_BUG_ON(vmalloc_global_nonsensitive_start <= VMALLOC_START);
}

static void __asi_clear_user_pgd(struct mm_struct *mm, size_t addr)
{
	uint i;

	if (!static_cpu_has(X86_FEATURE_ASI) || !mm_asi_enabled(mm))
		return;

	/*
	 * This function is called right after pgd_clear/p4d_clear.
	 * We need to be sure that the preceding pXd_clear is visible before
	 * the ASI pgd clears below. Compare with asi_clone_user_pgd().
	 */
	smp_mb__before_atomic();

	/*
	 * We need to ensure that the ASI PGD tables do not get freed from
	 * under us. We can potentially use RCU to avoid that, but since
	 * this path is probably not going to be too performance sensitive,
	 * so we just acquire the lock to block asi_destroy().
	 */
	mutex_lock(&mm->asi_init_lock);

	for (i = 1; i < ASI_MAX_NUM; i++)
		if (mm->asi[i].class &&
		    (mm->asi[i].class->flags & ASI_MAP_ALL_USERSPACE))
			set_pgd(pgd_offset_pgd(mm->asi[i].pgd, addr),
				native_make_pgd(0));

	mutex_unlock(&mm->asi_init_lock);
}

void asi_clear_user_pgd(struct mm_struct *mm, size_t addr)
{
	if (pgtable_l5_enabled())
		__asi_clear_user_pgd(mm, addr);
}

void asi_clear_user_p4d(struct mm_struct *mm, size_t addr)
{
	if (!pgtable_l5_enabled())
		__asi_clear_user_pgd(mm, addr);
}

/*
 * Maps the given userspace address range into the ASI page tables.
 *
 * The caller MUST ensure that the source mapping will not change during this
 * function e.g. by synchronizing via MMU notifiers or acquiring the
 * appropriate locks.
 */
int asi_map_user(struct asi *asi, void *addr, size_t len,
		 struct asi_pgtbl_pool *pool,
		 size_t allowed_start, size_t allowed_end)
{
	int err;
	size_t start = (size_t)addr;
	size_t end = start + len;

	if (!static_cpu_has(X86_FEATURE_ASI) || !asi)
		return 0;

	VM_BUG_ON(end > TASK_SIZE_MAX);

	read_lock(&asi->user_map_lock);
	err = __asi_map(asi, start, end, GFP_NOWAIT, pool,
			allowed_start, allowed_end);
	read_unlock(&asi->user_map_lock);

	return err;
}
EXPORT_SYMBOL_GPL(asi_map_user);

static bool
asi_unmap_free_pte_range(struct asi_pgtbl_pool *pgtbls_to_free,
			 pte_t *pte, size_t addr, size_t end)
{
	do {
		pte_clear(NULL, addr, pte);
	} while (pte++, addr += PAGE_SIZE, addr != end);

	return true;
}

#define DEFINE_ASI_UNMAP_FREE_RANGE(level, LEVEL, next_level, NEXT_LVL_SIZE)   \
static bool								       \
asi_unmap_free_##level##_range(struct asi_pgtbl_pool *pgtbls_to_free,	       \
			       level##_t *level, size_t addr, size_t end)      \
{									       \
	bool unmapped = false;						       \
	size_t next;							       \
									       \
	do {								       \
		next = level##_addr_end(addr, end);			       \
		if (level##_none(*level))				       \
			continue;					       \
									       \
		if (IS_ALIGNED(addr, LEVEL##_SIZE) &&			       \
		    IS_ALIGNED(next, LEVEL##_SIZE)) {			       \
			if (!level##_large(*level)) {			       \
				ulong pgtbl = level##_page_vaddr(*level);      \
				struct page *page = virt_to_page(pgtbl);       \
									       \
				page->private = PG_LEVEL_##NEXT_LVL_SIZE;      \
				return_pgtbl_to_pool(pgtbls_to_free, pgtbl);   \
			}						       \
			level##_clear(level);				       \
			unmapped = true;				       \
		} else {						       \
			/*						       \
			 * At this time, we don't have a case where we need to \
			 * unmap a subset of a huge page. But that could arise \
			 * in the future. In that case, we'll need to split    \
			 * the huge mapping here.			       \
			 */						       \
			if (WARN_ON(level##_large(*level)))		       \
				continue;				       \
									       \
			unmapped |= asi_unmap_free_##next_level##_range(       \
					pgtbls_to_free,			       \
					next_level##_offset(level, addr),      \
					addr, next);			       \
		}							       \
	} while (level++, addr = next, addr != end);			       \
									       \
	return unmapped;						       \
}

DEFINE_ASI_UNMAP_FREE_RANGE(pmd, PMD, pte, 4K)
DEFINE_ASI_UNMAP_FREE_RANGE(pud, PUD, pmd, 2M)
DEFINE_ASI_UNMAP_FREE_RANGE(p4d, P4D, pud, 1G)
DEFINE_ASI_UNMAP_FREE_RANGE(pgd, PGDIR, p4d, 512G)

static bool asi_unmap_and_free_range(struct asi_pgtbl_pool *pgtbls_to_free,
				     struct asi *asi, size_t addr, size_t end)
{
	size_t next;
	bool unmapped = false;
	pgd_t *pgd = pgd_offset_pgd(asi->pgd, addr);

	BUILD_BUG_ON((void *)&((struct page *)NULL)->private ==
		     (void *)&((struct page *)NULL)->asi_pgtbl_pool_next);

	if (pgtable_l5_enabled())
		return asi_unmap_free_pgd_range(pgtbls_to_free, pgd, addr, end);

	do {
		next = pgd_addr_end(addr, end);
		unmapped |= asi_unmap_free_p4d_range(pgtbls_to_free,
						     p4d_offset(pgd, addr),
						     addr, next);
	} while (pgd++, addr = next, addr != end);

	return unmapped;
}

void asi_unmap_user(struct asi *asi, void *addr, size_t len)
{
	static void (*const free_pgtbl_at_level[])(struct asi *, size_t) = {
		NULL,
		asi_free_pte,
		asi_free_pmd,
		asi_free_pud,
		asi_free_p4d
	};

	struct asi_pgtbl_pool pgtbls_to_free = { 0 };
	size_t start = (size_t)addr;
	size_t end = start + len;
	bool unmapped;

	if (!static_cpu_has(X86_FEATURE_ASI) || !asi)
		return;

	write_lock(&asi->user_map_lock);
	unmapped = asi_unmap_and_free_range(&pgtbls_to_free, asi, start, end);
	write_unlock(&asi->user_map_lock);

	if (unmapped)
		asi_flush_tlb_range(asi, addr, len);

	while (pgtbls_to_free.count > 0) {
		size_t pgtbl = get_pgtbl_from_pool(&pgtbls_to_free);
		struct page *page = virt_to_page(pgtbl);

		VM_BUG_ON(page->private >= PG_LEVEL_NUM);
		free_pgtbl_at_level[page->private](asi, pgtbl);
	}
}
EXPORT_SYMBOL_GPL(asi_unmap_user);
