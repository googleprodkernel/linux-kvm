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

#define ASI_GLOBAL_NONSENSITIVE	(&init_mm.asi[0])
#define ASI_LOCAL_NONSENSITIVE	(&current->mm->asi[0])

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
	u16 pcid_index;
	atomic64_t *tlb_gen;
	atomic64_t __tlb_gen;
	int64_t asi_ref_count;
	rwlock_t user_map_lock;
};

struct asi_pgtbl_pool {
	struct page *pgtbl_list;
	uint count;
};

DECLARE_PER_CPU_ALIGNED_ASI_NOT_SENSITIVE(struct asi_state, asi_cpu_state);

extern pgd_t asi_global_nonsensitive_pgd[];

void asi_vmalloc_init(void);

int  asi_init_mm_state(struct mm_struct *mm);
void asi_free_mm_state(struct mm_struct *mm);

int  asi_register_class(const char *name, uint flags,
			const struct asi_hooks *ops);
void asi_unregister_class(int index);

int  asi_init(struct mm_struct *mm, int asi_index, struct asi **out_asi);
void asi_destroy(struct asi *asi);

void asi_enter(struct asi *asi);
void asi_exit(void);

int  asi_map_gfp(struct asi *asi, void *addr, size_t len, gfp_t gfp_flags);
int  asi_map(struct asi *asi, void *addr, size_t len);
void asi_unmap(struct asi *asi, void *addr, size_t len, bool flush_tlb);
void asi_flush_tlb_range(struct asi *asi, void *addr, size_t len);
void asi_sync_mapping(struct asi *asi, void *addr, size_t len);
void asi_do_lazy_map(struct asi *asi, size_t addr);
void asi_clear_user_pgd(struct mm_struct *mm, size_t addr);
void asi_clear_user_p4d(struct mm_struct *mm, size_t addr);

int  asi_map_user(struct asi *asi, void *addr, size_t len,
		  struct asi_pgtbl_pool *pool,
		  size_t allowed_start, size_t allowed_end);
void asi_unmap_user(struct asi *asi, void *va, size_t len);
int  asi_fill_pgtbl_pool(struct asi_pgtbl_pool *pool, uint count, gfp_t flags);
void asi_clear_pgtbl_pool(struct asi_pgtbl_pool *pool);

static inline void asi_init_pgtbl_pool(struct asi_pgtbl_pool *pool)
{
	pool->pgtbl_list = NULL;
	pool->count = 0;
}

static inline void asi_init_thread_state(struct thread_struct *thread)
{
	thread->intr_nest_depth = 0;
}

int asi_load_module(struct module* module);
void asi_unload_module(struct module* module);

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

		if (--current->thread.intr_nest_depth == 0) {
			barrier();
			__asi_enter();
		}
	}
}

static inline int asi_intr_nest_depth(void)
{
	return current->thread.intr_nest_depth;
}

void asi_get_latest_tlb_gens(struct asi *asi, u64 *latest_local_tlb_gen,
			     u64 *latest_global_tlb_gen);

#define INIT_MM_ASI(init_mm)						\
	.asi = {							\
		[0] = {							\
			.pgd = asi_global_nonsensitive_pgd,		\
			.mm = &init_mm,					\
			.__tlb_gen = ATOMIC64_INIT(1),			\
			.tlb_gen = &init_mm.asi[0].__tlb_gen		\
		}							\
	},

static inline pgd_t *asi_pgd(struct asi *asi)
{
	return asi->pgd;
}

/* IMPORTANT: Any modification to the name here should also be applied to
 * include/asm-generic/vmlinux.lds.h */
#define ASI_NON_SENSITIVE_SECTION_NAME ".data..asi_non_sensitive"
#define ASI_NON_SENSITIVE_READ_MOSTLY_SECTION_NAME \
                       ".data..asi_non_sensitive_readmostly"

#define __asi_not_sensitive \
    __section(ASI_NON_SENSITIVE_SECTION_NAME)

#define __asi_not_sensitive_readmostly \
    __section(ASI_NON_SENSITIVE_READ_MOSTLY_SECTION_NAME)

#else	/* CONFIG_ADDRESS_SPACE_ISOLATION */

static inline void asi_intr_enter(void) { }

static inline void asi_intr_exit(void) { }

static inline int asi_intr_nest_depth(void) { return 0; }

static inline void asi_init_thread_state(struct thread_struct *thread) { }

static inline pgd_t *asi_pgd(struct asi *asi) { return NULL; }

#endif	/* CONFIG_ADDRESS_SPACE_ISOLATION */

#endif
