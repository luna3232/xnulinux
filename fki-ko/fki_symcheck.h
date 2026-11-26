/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Check a caller-supplied address list against one kernel's link addresses.
 * There is no scan of kallsyms. Every runtime address must be the link
 * address plus the same slide (KASLR). A zero address or a broken slide is
 * rejected. The link addresses are from the RB5 System.map
 * 11d372fb432a22e0ea11b5a11cdda4935aa137ad3dfc12c5f300a5d29cf1bdbf
 * for 6.6.9-qcomlt-arm64-00188-g31f49428dc7d. They are not a general lookup.
 */
#ifndef _FKI_SYMCHECK_H
#define _FKI_SYMCHECK_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

#define FKI_SYM_N 11

/* Order is the module parameter order. Do not reorder. */
static const unsigned long fki_rb5_link[FKI_SYM_N] = {
	0xffff8000800383f0UL, /* set_memory_x */
	0xffff800080272a7cUL, /* alloc_contig_pages */
	0xffff80008026e2dcUL, /* free_contig_range */
	0xffff800082b91798UL, /* dma_contiguous_default_area */
	0xffff8000802c80bcUL, /* cma_alloc */
	0xffff8000802c8560UL, /* cma_release */
	0xffff8000800383ccUL, /* set_memory_nx */
	0xffff800080010000UL, /* _stext */
	0xffff800082c00000UL, /* _end */
	0xffff800081c57f30UL, /* kimage_voffset */
	0xffff800080e23f90UL, /* efi_mem_type */
};

static inline int fki_sym_one_slide(const unsigned long *link, const unsigned long *runtime,
				    unsigned n, unsigned long *slide)
{
	unsigned i;
	unsigned long s;

	if (!n || !link || !runtime || !slide)
		return 1;
	for (i = 0; i < n; i++) {
		if (!link[i] || !runtime[i])
			return 1;
	}
	s = runtime[0] - link[0];
	for (i = 1; i < n; i++) {
		if (runtime[i] - link[i] != s)
			return 1;
	}
	*slide = s;
	return 0;
}

#endif
