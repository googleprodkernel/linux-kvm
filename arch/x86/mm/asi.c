// SPDX-License-Identifier: GPL-2.0

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
	spin_lock(&asi_class_lock);

	WARN_ON(asi_class[index].name == NULL);
	memset(&asi_class[index], 0, sizeof(struct asi_class));

	spin_unlock(&asi_class_lock);
}
EXPORT_SYMBOL_GPL(asi_unregister_class);

int asi_init(struct mm_struct *mm, int asi_index)
{
	struct asi *asi = &mm->asi[asi_index];

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
	free_pages((ulong)asi->pgd, PGD_ALLOCATION_ORDER);
	memset(asi, 0, sizeof(struct asi));
}
EXPORT_SYMBOL_GPL(asi_destroy);

static void __asi_enter(void)
{
	u64 asi_cr3;
	struct asi *target = this_cpu_read(asi_cpu_state.target_asi);

	VM_BUG_ON(preemptible());

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
