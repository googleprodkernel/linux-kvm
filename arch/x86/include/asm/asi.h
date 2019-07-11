/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_ASI_H
#define _ASM_X86_ASI_H

#include <asm-generic/asi.h>

#include <asm/pgtable_types.h>
#include <asm/percpu.h>
#include <asm/processor.h>
#include <linux/sched.h>

#ifdef CONFIG_ADDRESS_SPACE_ISOLATION

#define ASI_MAX_NUM_ORDER	2
#define ASI_MAX_NUM		(1 << ASI_MAX_NUM_ORDER)

struct asi_hooks {
	/*
	 * Both of these functions MUST be idempotent and re-entrant. They will
	 * be called in no particular order and with no particular symmetry wrt.
	 * the number of calls. They are part of the ASI critical section, so
	 * they must not sleep and must not access sensitive data.
	 */
	void (*post_asi_enter)(void);
	void (*pre_asi_exit)(void);
};

/*
 * An ASI class is a type of isolation that can be applied to a process. A
 * process may have a domain for each class.
 */
struct asi_class {
	struct asi_hooks ops;
	const char *name;
};

/*
 * An ASI domain (struct asi) represents a restricted address space. The
 * unrestricted address space (and user address space under PTI) are not
 * represented as a domain.
 */
struct asi {
	pgd_t *pgd;
	struct asi_class *class;
	struct mm_struct *mm;
};

DECLARE_PER_CPU_ALIGNED(struct asi *, curr_asi);

void asi_init_mm_state(struct mm_struct *mm);

int  asi_register_class(const char *name, const struct asi_hooks *ops);
void asi_unregister_class(int index);

int  asi_init(struct mm_struct *mm, int asi_index, struct asi **out_asi);
void asi_destroy(struct asi *asi);

/* Enter an ASI domain (restricted address space) and begin the critical section. */
void asi_enter(struct asi *asi);

/*
 * Leave the "tense" state if we are in it, i.e. end the critical section. We
 * will stay relaxed until the next asi_enter.
 */
void asi_relax(void);

/* Immediately exit the restricted address space if in it */
void asi_exit(void);

/* The target is the domain we'll enter when returning to process context. */
static __always_inline struct asi *asi_get_target(struct task_struct *p)
{
	return p->thread.asi_state.target;
}

static __always_inline void asi_set_target(struct task_struct *p,
					   struct asi *target)
{
	p->thread.asi_state.target = target;
}

static __always_inline struct asi *asi_get_current(void)
{
	return this_cpu_read(curr_asi);
}

/* Are we currently in a restricted address space? */
static __always_inline bool asi_is_restricted(void)
{
	return (bool)asi_get_current();
}

/* If we exit/have exited, can we stay that way until the next asi_enter? */
static __always_inline bool asi_is_relaxed(void)
{
	return !asi_get_target(current);
}

/*
 * Is the current task in the critical section?
 *
 * This is just the inverse of !asi_is_relaxed(). We have both functions in order to
 * help write intuitive client code. In particular, asi_is_tense returns false
 * when ASI is disabled, which is judged to make user code more obvious.
 */
static __always_inline bool asi_is_tense(void)
{
	return !asi_is_relaxed();
}

static __always_inline pgd_t *asi_pgd(struct asi *asi)
{
	return asi ? asi->pgd : NULL;
}

#endif	/* CONFIG_ADDRESS_SPACE_ISOLATION */

#endif
