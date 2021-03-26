/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_ASI_H
#define _ASM_X86_ASI_H

#include <asm-generic/asi.h>

#include <linux/sched.h>

#include <asm/pgtable_types.h>
#include <asm/percpu.h>
#include <asm/cpufeature.h>

#ifdef CONFIG_ADDRESS_SPACE_ISOLATION

#define ASI_MAX_NUM_ORDER	2
#define ASI_MAX_NUM		(1 << ASI_MAX_NUM_ORDER)

struct asi_state {
	struct asi *curr_asi;
	struct asi *target_asi;
};

struct asi_hooks {
	/* Both of these functions MUST be idempotent and re-entrant. */

	void (*post_asi_enter)(void);
	void (*pre_asi_exit)(void);
};

struct asi_class {
	struct asi_hooks ops;
	uint flags;
	const char *name;
};

struct asi {
	pgd_t *pgd;
	struct asi_class *class;
	struct mm_struct *mm;
};

DECLARE_PER_CPU_ALIGNED(struct asi_state, asi_cpu_state);

void asi_init_mm_state(struct mm_struct *mm);

int  asi_register_class(const char *name, uint flags,
			const struct asi_hooks *ops);
void asi_unregister_class(int index);

int  asi_init(struct mm_struct *mm, int asi_index);
void asi_destroy(struct asi *asi);

void asi_enter(struct asi *asi);
void asi_exit(void);

int  asi_map_gfp(struct asi *asi, void *addr, size_t len, gfp_t gfp_flags);
int  asi_map(struct asi *asi, void *addr, size_t len);
void asi_unmap(struct asi *asi, void *addr, size_t len, bool flush_tlb);
void asi_flush_tlb_range(struct asi *asi, void *addr, size_t len);

static inline void asi_init_thread_state(struct thread_struct *thread)
{
	thread->intr_nest_depth = 0;
}

static inline void asi_set_target_unrestricted(void)
{
	if (static_cpu_has(X86_FEATURE_ASI)) {
		barrier();
		this_cpu_write(asi_cpu_state.target_asi, NULL);
	}
}

static inline struct asi *asi_get_current(void)
{
	return static_cpu_has(X86_FEATURE_ASI)
	       ? this_cpu_read(asi_cpu_state.curr_asi)
	       : NULL;
}

static inline struct asi *asi_get_target(void)
{
	return static_cpu_has(X86_FEATURE_ASI)
	       ? this_cpu_read(asi_cpu_state.target_asi)
	       : NULL;
}

static inline bool is_asi_active(void)
{
	return (bool)asi_get_current();
}

static inline bool asi_is_target_unrestricted(void)
{
	return !asi_get_target();
}

#define static_asi_enabled() cpu_feature_enabled(X86_FEATURE_ASI)

static inline void asi_intr_enter(void)
{
	if (static_cpu_has(X86_FEATURE_ASI)) {
		current->thread.intr_nest_depth++;
		barrier();
	}
}

static inline void asi_intr_exit(void)
{
	void __asi_enter(void);

	if (static_cpu_has(X86_FEATURE_ASI)) {
		barrier();

		if (--current->thread.intr_nest_depth == 0)
			__asi_enter();
	}
}

static inline pgd_t *asi_pgd(struct asi *asi)
{
	return asi->pgd;
}

#else	/* CONFIG_ADDRESS_SPACE_ISOLATION */

static inline void asi_intr_enter(void) { }

static inline void asi_intr_exit(void) { }

static inline void asi_init_thread_state(struct thread_struct *thread) { }

static inline pgd_t *asi_pgd(struct asi *asi) { return NULL; }

#endif	/* CONFIG_ADDRESS_SPACE_ISOLATION */

#endif
