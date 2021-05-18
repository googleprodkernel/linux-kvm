/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_ASI_H
#define __ASM_GENERIC_ASI_H

#include <linux/types.h>

/* ASI class flags */
#define ASI_MAP_STANDARD_NONSENSITIVE	1

#ifndef CONFIG_ADDRESS_SPACE_ISOLATION

#define ASI_MAX_NUM_ORDER		0
#define ASI_MAX_NUM			0

#define ASI_GLOBAL_NONSENSITIVE		NULL
#define ASI_LOCAL_NONSENSITIVE		NULL

#define VMALLOC_GLOBAL_NONSENSITIVE_START	VMALLOC_START
#define VMALLOC_GLOBAL_NONSENSITIVE_END		VMALLOC_END

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

static inline int asi_init_mm_state(struct mm_struct *mm) { return 0; }

static inline void asi_free_mm_state(struct mm_struct *mm) { }

static inline
int asi_init(struct mm_struct *mm, int asi_index, struct asi **out_asi)
{
	*out_asi = NULL;
	return 0;
}

static inline void asi_destroy(struct asi *asi) { }

static inline void asi_enter(struct asi *asi) { }

static inline void asi_set_target_unrestricted(void) { }

static inline bool asi_is_target_unrestricted(void) { return true; }

static inline void asi_exit(void) { }

static inline bool is_asi_active(void) { return false; }

static inline struct asi *asi_get_target(void) { return NULL; }

static inline struct asi *asi_get_current(void) { return NULL; }

static inline
int asi_map_gfp(struct asi *asi, void *addr, size_t len, gfp_t gfp_flags)
{
	return 0;
}

static inline int asi_map(struct asi *asi, void *addr, size_t len)
{
	return 0;
}

static inline
void asi_sync_mapping(struct asi *asi, void *addr, size_t len) { }

static inline
void asi_unmap(struct asi *asi, void *addr, size_t len, bool flush_tlb) { }


static inline
void asi_do_lazy_map(struct asi *asi, size_t addr) { }

static inline
void asi_flush_tlb_range(struct asi *asi, void *addr, size_t len) { }

#define INIT_MM_ASI(init_mm)

#define static_asi_enabled() false


#endif  /* !_ASSEMBLY_ */

#endif /* !CONFIG_ADDRESS_SPACE_ISOLATION */

#endif
