/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/types.h>
#include <linux/pgtable.h>

#include <asm/page.h>

#ifndef __X86_MM_ASI_INTERNAL_H
#define __X86_MM_ASI_INTERNAL_H

#ifdef CONFIG_KUNIT

bool follow_physaddr(
	pgd_t *pgd_table, unsigned long virt,
	phys_addr_t *phys, unsigned long *page_size, ulong *flags);

#endif /* CONFIG_KUNIT */

#endif /* __X86_MM_ASI_INTERNAL_H */
