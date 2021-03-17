/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_ASI_H
#define __ASM_GENERIC_ASI_H

/* ASI class flags */
#define ASI_MAP_STANDARD_NONSENSITIVE	1

#ifndef CONFIG_ADDRESS_SPACE_ISOLATION

#define ASI_MAX_NUM_ORDER		0
#define ASI_MAX_NUM			0

#ifndef _ASSEMBLY_

struct asi_hooks {};
struct asi {};

static inline
int asi_register_class(const char *name, uint flags,
		       const struct asi_hooks *ops)
{
	return 0;
}

static inline void asi_unregister_class(int asi_index) { }

static inline void asi_init_mm_state(struct mm_struct *mm) { }

static inline int asi_init(struct mm_struct *mm, int asi_index) { return 0; }

static inline void asi_destroy(struct asi *asi) { }

static inline void asi_enter(struct asi *asi) { }

static inline void asi_set_target_unrestricted(void) { }

static inline bool asi_is_target_unrestricted(void) { return true; }

static inline void asi_exit(void) { }

static inline bool is_asi_active(void) { return false; }

static inline struct asi *asi_get_target(void) { return NULL; }

static inline struct asi *asi_get_current(void) { return NULL; }

#define static_asi_enabled() false

#endif  /* !_ASSEMBLY_ */

#endif /* !CONFIG_ADDRESS_SPACE_ISOLATION */

#endif
