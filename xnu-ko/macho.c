// SPDX-License-Identifier: APSL-2.0
// Mach-O loading and threaded-rebase for the XNU image (APSL side).
#include "xrt.h"
#define ENOEXEC 8
#define ENOMEM 12
#include "macho.h"
#include "pauth_lower.h"

int xnu_nopauth_lower;
struct pauth_lower_stats xnu_lower_stats;

#define FOR_EACH_LC(img, l) \
	for (const struct lc *l = (const void *)((img)->file + sizeof(struct mh64)), *_e = (const void *)((img)->file + sizeof(struct mh64) + ((const struct mh64 *)(img)->file)->sizeofcmds); \
	     l < _e; l = (const void *)((const char *)l + l->cmdsize))

int macho_load(struct xnu_image *img, const void *file, unsigned long size, unsigned long extra)
{
	const struct mh64 *mh = file;
	int err;
	(void)err;

	img->file = file; img->file_size = size;
	if (size < sizeof(*mh) || mh->magic != MH_MAGIC_64)
		return -ENOEXEC;
	img->vmlow = ~0ULL; img->vmhigh = 0;
	FOR_EACH_LC(img, l) {
		if (l->cmd == LC_SEGMENT_64) {
			const struct seg64 *s = (const void *)l;
			if (!s->vmsize || !x_strncmp(s->segname, "__PAGEZERO", 16))
				continue;
			if (s->vmaddr < img->vmlow) img->vmlow = s->vmaddr;
			if (s->vmaddr + s->vmsize > img->vmhigh) img->vmhigh = s->vmaddr + s->vmsize;
			const struct sect64 *sc = (const void *)(s + 1);
			for (u32_t i = 0; i < s->nsects; i++)
				if (!x_strncmp(sc[i].sectname, "__thread_starts", 16)) {
					img->thread_starts = sc[i].addr;
					img->thread_starts_size = sc[i].size;
				}
		} else if (l->cmd == LC_SYMTAB) {
			img->symtab = (const void *)l;
		} else if (l->cmd == LC_UNIXTHREAD) {
			/* flavor, count, then arm_thread_state64: x[29], fp, lr, sp, pc */
			const u32_t *t = (const void *)(l + 1);
			img->entry = *(const u64_t *)(t + 2 + 2 * 32);
		}
	}
	if (img->vmhigh <= img->vmlow)
		return -ENOEXEC;
	img->filetype = mh->filetype;
	if (mh->filetype == MH_FILESET) {
		/*
		 * A kernel collection: a flat image (file offset = vmaddr - base) whose pointers are chained fixups that XNU's
		 * arm_init applies itself (kernel_collection_slide). The kernel's symbols are in its own entry's LC_SYMTAB.
		 */
		img->symtab = 0;
		FOR_EACH_LC(img, l) {
			if (l->cmd != LC_FILESET_ENTRY) continue;
			const struct fileset_entry_lc *fe = (const void *)l;
			if (fe->entry_id >= fe->cmdsize || x_strcmp((const char *)fe + fe->entry_id, "com.apple.kernel")) continue;
			if (fe->fileoff + sizeof(struct mh64) > size) return -ENOEXEC;
			img->kernel_mh = fe->vmaddr;
			const struct mh64 *kh = (const void *)((const char *)file + fe->fileoff);
			const struct lc *kl = (const void *)(kh + 1);
			for (u32_t i = 0; i < kh->ncmds; i++, kl = (const void *)((const char *)kl + kl->cmdsize))
				if (kl->cmd == LC_SYMTAB) img->symtab = (const void *)kl;
		}
		if (!img->kernel_mh || !img->symtab)
			return -ENOEXEC;
	}
	if (extra == ~0UL)		/* parse only: the caller places the image (macho_copy) */
		return 0;
	err = fki_region_alloc(img->vmhigh - img->vmlow + extra, &img->region);
	if (err)
		return err;
	img->slide = (u64_t)img->region.va - img->vmlow;
	return macho_copy(img, img->region.va);
}

/* Copy the segments to dst, which is where vmlow will live. */
int macho_copy(struct xnu_image *img, void *dst)
{
	FOR_EACH_LC(img, l) {
		if (l->cmd != LC_SEGMENT_64) continue;
		const struct seg64 *s = (const void *)l;
		if (!s->vmsize || !s->filesize || !x_strncmp(s->segname, "__PAGEZERO", 16)) continue;
		if (s->fileoff + s->filesize > img->file_size) return -ENOEXEC;
		x_memcpy((char *)dst + (s->vmaddr - img->vmlow), img->file + s->fileoff, s->filesize);
		if (xnu_nopauth_lower && (s->initprot & 4)) {
			const struct sect64 *sc = (const void *)(s + 1);
			u32_t i;
			for (i = 0; i < s->nsects; i++) {
				unsigned char *p;
				if (!(sc[i].flags & 0x80000400u)) continue;	/* pure or some instructions */
				if ((sc[i].addr | sc[i].size) & 3) continue;
				if (sc[i].size == 0) continue;
				if (sc[i].addr < img->vmlow || sc[i].addr + sc[i].size > img->vmhigh) continue;
				if ((u64_t)sc[i].offset < s->fileoff ||
				    (u64_t)sc[i].offset + sc[i].size > s->fileoff + s->filesize)
					continue;
				p = (unsigned char *)dst + (sc[i].addr - img->vmlow);
				pauth_lower_span((uint32_t *)p, (size_t)(sc[i].size / 4), &xnu_lower_stats);
			}
		}
	}
	return 0;
}

/* Non-HINT PACIA/PACIB/PACDA/PACDB. With nopauth the pointer is left raw; the guest's PAC/AUT were rewritten to NOP. */
static inline u64_t sign(u64_t v, unsigned key, u64_t disc)
{
	if (xnu_nopauth_lower)
		return v;
	switch (key) {
	case 0: asm volatile(".arch_extension pauth\n\tpacia %0, %1" : "+r"(v) : "r"(disc)); break;
	case 1: asm volatile(".arch_extension pauth\n\tpacib %0, %1" : "+r"(v) : "r"(disc)); break;
	case 2: asm volatile(".arch_extension pauth\n\tpacda %0, %1" : "+r"(v) : "r"(disc)); break;
	default: asm volatile(".arch_extension pauth\n\tpacdb %0, %1" : "+r"(v) : "r"(disc)); break;
	}
	return v;
}

/* Runs inside fki_enter() with the XNU kernel keys loaded. */
int macho_rebase(struct xnu_image *img)
{
	u64_t mh_vm = 0;
	FOR_EACH_LC(img, l) {
		if (l->cmd == LC_SEGMENT_64 && !x_strncmp(((const struct seg64 *)l)->segname, "__TEXT", 16) &&
		    ((const struct seg64 *)l)->fileoff == 0)
			mh_vm = ((const struct seg64 *)l)->vmaddr;
	}
	if (!img->thread_starts || !mh_vm)
		return -ENOEXEC;
	u32_t *ts = (u32_t *)(img->thread_starts + img->slide);
	u32_t *te = (u32_t *)((char *)ts + img->thread_starts_size);
	u64_t step = (ts[0] & 1) ? 8 : 4, n = 0;
	for (u32_t *o = ts + 1; o < te && *o != 0xffffffff; o++) {
		u64_t addr = mh_vm + img->slide + *o, delta;
		do {
			u64_t v = *(u64_t *)addr;
			if (!(v & (1ULL << 62))) {
				if (v & (1ULL << 63)) {
					u64_t nv = (v & 0xffffffffULL) + mh_vm + img->slide;
					u64_t disc = (v >> 32) & 0xffff;
					if (v & (1ULL << 48))
						disc = disc ? ((addr & 0x0000ffffffffffffULL) | (disc << 48)) : addr;
					*(u64_t *)addr = sign(nv, (v >> 49) & 3, disc);
				} else {
					u64_t top8 = v & 0x0007F80000000000ULL, b43 = v & 0x000007FFFFFFFFFFULL;
					u64_t t = (top8 << 13) | (((long long)(b43 << 21) >> 21) & 0x00FFFFFFFFFFFFFFULL);
					*(u64_t *)addr = t + img->slide;
				}
				n++;
			}
			delta = ((v & ~(1ULL << 62)) & 0x3FF8000000000000ULL) >> 51;
			addr += delta * step;
		} while (delta);
	}
	return (int)n;
}

u64_t macho_sym(struct xnu_image *img, const char *name)
{
	const struct symtab_lc *st = img->symtab;
	if (!st) return 0;
	const struct nlist64 *nl = (const void *)(img->file + st->symoff);
	const char *strs = (const char *)img->file + st->stroff;
	for (u32_t i = 0; i < st->nsyms; i++) {
		if ((nl[i].n_type & 0x0e) != 0x0e || nl[i].n_strx >= st->strsize) continue;	/* N_SECT */
		if (!x_strcmp(strs + nl[i].n_strx, name))
			return nl[i].n_value + img->slide;
	}
	return 0;
}

/* As iBoot does for a static kernelcache: slide the load commands of the in-memory Mach-O header. */
int macho_slide_header(struct xnu_image *img, u64_t *mh_unslid)
{
	u64_t mh_vm = 0;
	FOR_EACH_LC(img, l) {
		if (l->cmd == LC_SEGMENT_64 && !x_strncmp(((const struct seg64 *)l)->segname, "__TEXT", 16) &&
		    ((const struct seg64 *)l)->fileoff == 0)
			mh_vm = ((const struct seg64 *)l)->vmaddr;
	}
	if (!mh_vm)
		return -ENOEXEC;
	*mh_unslid = mh_vm;
	unsigned char *mh = (unsigned char *)(mh_vm + img->slide);
	const struct mh64 *h = (const void *)mh;
	struct lc *l = (void *)(mh + sizeof(struct mh64)), *e = (void *)(mh + sizeof(struct mh64) + h->sizeofcmds);
	int n = 0;
	for (; l < e; l = (void *)((char *)l + l->cmdsize)) {
		if (l->cmd != LC_SEGMENT_64) continue;
		struct seg64 *sg = (void *)l;
		if (!sg->vmsize) continue;
		sg->vmaddr += img->slide;
		struct sect64 *sc = (void *)(sg + 1);
		for (u32_t i = 0; i < sg->nsects; i++) sc[i].addr += img->slide;
		n++;
	}
	return n;
}
