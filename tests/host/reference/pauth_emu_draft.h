/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * REFERENCE ONLY, not compiled into fki.ko or xnu.ko.
 * Started on the remove-PAC branch (PR 1) before that work was split.
 * The software-emulation route belongs on a separate branch. This file is
 * left so that branch can copy it. Do not wire it into the host module here.
 *
 * Encodings below were checked with GNU assembler 2.42 (aarch64-linux-gnu-as),
 * for example pacia x2, x3 = 0xdac10062, retab = 0xd65f0fff, blraaz x2 = 0xd63f085f,
 * mrs x2, apiakeylo_el1 = 0xd5382102.
 *
 * Bug to fix before use: the PACIA-family test
 *   ((top10 >> 10) & 3) == ((top10 >> 10) & 7)
 * is true for PAC* (low two opcode bits) and false for AUT* (opcode bit 2 set),
 * so AUTIA/AUTIB/AUTDA/AUTDB fall through instead of being stepped.
 */
/*
 * Software stand-in for FEAT_PAuth instructions, for a host whose ID registers
 * report no PAC at all (so the non-HINT encodings are UNDEFINED).
 *
 * This is the architectural "authentication succeeded" result, not QARMA and
 * not Apple's implementation-defined algorithm:
 *   PAC*     leaves the pointer register unchanged (no tag is inserted);
 *   AUT*/XPAC replace bits [63:56] with the extension of bit 55, which is a
 *            no-op on a canonical kernel pointer (top byte already 0xff and
 *            bit 55 set) and on a canonical user pointer (top byte 0, bit 55
 *            clear), and drops a tag that was sitting in the top byte;
 *   RETAA/RETAB and BRA*/BLRA* branch to that stripped address;
 *   PACGA    is a deterministic mix of the pointer, the modifier and the
 *            shadow APGAKey, result in bits [63:32]. It is not a PAC of a
 *            return address and it is not cryptographically strong.
 * Key registers are a shadow. ERETAA/ERETAB are recognized and refused:
 * emulating an exception return would change host EL state.
 *
 * HINT-space PACIASP/AUTIASP and friends do not trap on this hardware; the
 * decoder still implements them so a test can step the same encodings.
 */
#ifndef _FKI_PAUTH_EMU_H
#define _FKI_PAUTH_EMU_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define FKI_PAUTH_STEP_OK		0
#define FKI_PAUTH_STEP_UNKNOWN		1	/* not a PAC instruction; CPU unchanged */
#define FKI_PAUTH_STEP_REFUSED		2	/* ERETAA/ERETAB; CPU unchanged */

/* Shadow keys: IA, IB, DA, DB, GA, each lo then hi. */
#define FKI_PAUTH_KEY_IA_LO	0
#define FKI_PAUTH_KEY_IA_HI	1
#define FKI_PAUTH_KEY_IB_LO	2
#define FKI_PAUTH_KEY_IB_HI	3
#define FKI_PAUTH_KEY_DA_LO	4
#define FKI_PAUTH_KEY_DA_HI	5
#define FKI_PAUTH_KEY_DB_LO	6
#define FKI_PAUTH_KEY_DB_HI	7
#define FKI_PAUTH_KEY_GA_LO	8
#define FKI_PAUTH_KEY_GA_HI	9
#define FKI_PAUTH_KEYS		10

struct fki_pauth_cpu {
	uint64_t x[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t key[FKI_PAUTH_KEYS];
};

static inline uint64_t fki_pauth_strip(uint64_t p)
{
	uint64_t ext = (p & (1ULL << 55)) ? 0xff00000000000000ULL : 0;

	return (p & 0x00ffffffffffffffULL) | ext;
}

/* Experimental PACGA. Not QARMA. Bits [31:0] of the result are 0. */
static inline uint64_t fki_pauth_pacga(uint64_t data, uint64_t modifier, uint64_t key_lo, uint64_t key_hi)
{
	uint64_t x = data + 0x9E3779B97F4A7C15ULL;

	x ^= modifier;
	x *= 0xBF58476D1CE4E5B9ULL;
	x ^= key_lo;
	x *= 0x94D049BB133111EBULL;
	x ^= key_hi;
	x ^= x >> 32;
	return x & 0xffffffff00000000ULL;
}

static inline uint64_t fki_pauth_xget(const struct fki_pauth_cpu *c, unsigned n)
{
	return n < 31 ? c->x[n] : 0;	/* XZR */
}

static inline void fki_pauth_xset(struct fki_pauth_cpu *c, unsigned n, uint64_t v)
{
	if (n < 31)
		c->x[n] = v;
}

static inline uint64_t fki_pauth_mod(const struct fki_pauth_cpu *c, unsigned n)
{
	return n < 31 ? c->x[n] : c->sp;	/* Xn|SP */
}

/* Pointer insert: the address is the value that later AUT/RET/BLR must keep. */
static inline uint64_t fki_pauth_sign_value(uint64_t pointer, unsigned key, uint64_t modifier)
{
	(void)key;
	(void)modifier;
	return pointer;
}

static inline int fki_pauth_apply(struct fki_pauth_cpu *c, uint32_t insn)
{
	unsigned rd = insn & 31u;
	unsigned rn = (insn >> 5) & 31u;
	unsigned rm = (insn >> 16) & 31u;
	uint32_t top10 = insn & 0xfffffc00u;
	uint64_t pointer, ret;

	if (insn == 0xd69f0bffu || insn == 0xd69f0fffu)
		return FKI_PAUTH_STEP_REFUSED;	/* ERETAA, ERETAB */

	/* PACIA/B PACDA/B AUTIA/B AUTDA/B  Xd, Xn|SP */
	if (top10 >= 0xdac10000u && top10 <= 0xdac11c00u && ((top10 >> 10) & 3u) == ((top10 >> 10) & 7u)) {
		unsigned op = (top10 >> 10) & 7u;

		(void)fki_pauth_mod(c, rn);
		if (op < 4)
			pointer = fki_pauth_xget(c, rd);		/* PAC*: keep the pointer */
		else
			pointer = fki_pauth_strip(fki_pauth_xget(c, rd));	/* AUT*: success, strip */
		fki_pauth_xset(c, rd, pointer);
		c->pc += 4;
		return FKI_PAUTH_STEP_OK;
	}

	/* Rd-only forms with Xn fixed as XZR (31): PACIZ*, AUTIZ*, XPAC. */
	if ((insn & 0xffffffe0u) == 0xdac123e0u || (insn & 0xffffffe0u) == 0xdac127e0u ||
	    (insn & 0xffffffe0u) == 0xdac12be0u || (insn & 0xffffffe0u) == 0xdac12fe0u) {
		fki_pauth_xset(c, rd, fki_pauth_xget(c, rd));
		c->pc += 4;
		return FKI_PAUTH_STEP_OK;
	}
	if ((insn & 0xffffffe0u) == 0xdac133e0u || (insn & 0xffffffe0u) == 0xdac137e0u ||
	    (insn & 0xffffffe0u) == 0xdac13be0u || (insn & 0xffffffe0u) == 0xdac13fe0u ||
	    (insn & 0xffffffe0u) == 0xdac143e0u || (insn & 0xffffffe0u) == 0xdac147e0u) {
		fki_pauth_xset(c, rd, fki_pauth_strip(fki_pauth_xget(c, rd)));
		c->pc += 4;
		return FKI_PAUTH_STEP_OK;
	}

	/* HINT space. Hardware will not trap these; the step is for tests and for a fetched encoding. */
	if (insn == 0xd503231fu || insn == 0xd503235fu || insn == 0xd503233fu || insn == 0xd503237fu) {
		c->pc += 4;	/* PACI*Z / PACI*SP: X30 unchanged */
		return FKI_PAUTH_STEP_OK;
	}
	if (insn == 0xd503239fu || insn == 0xd50323dfu || insn == 0xd50323bfu || insn == 0xd50323ffu ||
	    insn == 0xd50320ffu) {
		c->x[30] = fki_pauth_strip(c->x[30]);	/* AUTI*Z / AUTI*SP / XPACLRI */
		c->pc += 4;
		return FKI_PAUTH_STEP_OK;
	}

	if ((insn & 0xffe0fc00u) == 0x9ac03000u) {
		fki_pauth_xset(c, rd, fki_pauth_pacga(fki_pauth_xget(c, rn), fki_pauth_xget(c, rm),
						      c->key[FKI_PAUTH_KEY_GA_LO], c->key[FKI_PAUTH_KEY_GA_HI]));
		c->pc += 4;
		return FKI_PAUTH_STEP_OK;
	}

	if (insn == 0xd65f0bffu || insn == 0xd65f0fffu) {	/* RETAA, RETAB */
		pointer = fki_pauth_strip(c->x[30]);
		c->x[30] = pointer;
		c->pc = pointer;
		return FKI_PAUTH_STEP_OK;
	}

	if ((insn & 0xfffffc1fu) == 0xd61f081fu || (insn & 0xfffffc1fu) == 0xd61f0c1fu) {
		c->pc = fki_pauth_strip(fki_pauth_xget(c, rn));	/* BRAAZ, BRABZ */
		return FKI_PAUTH_STEP_OK;
	}
	if ((insn & 0xfffffc1fu) == 0xd63f081fu || (insn & 0xfffffc1fu) == 0xd63f0c1fu) {
		ret = c->pc + 4;
		c->pc = fki_pauth_strip(fki_pauth_xget(c, rn));	/* BLRAAZ, BLRABZ */
		c->x[30] = ret;
		return FKI_PAUTH_STEP_OK;
	}
	if ((insn & 0xfffffc00u) == 0xd71f0800u || (insn & 0xfffffc00u) == 0xd71f0c00u) {
		(void)fki_pauth_xget(c, rd);	/* modifier Xm; XZR if 31 */
		c->pc = fki_pauth_strip(fki_pauth_xget(c, rn));	/* BRAA, BRAB */
		return FKI_PAUTH_STEP_OK;
	}
	if ((insn & 0xfffffc00u) == 0xd73f0800u || (insn & 0xfffffc00u) == 0xd73f0c00u) {
		ret = c->pc + 4;
		(void)fki_pauth_xget(c, rd);
		c->pc = fki_pauth_strip(fki_pauth_xget(c, rn));	/* BLRAA, BLRAB */
		c->x[30] = ret;
		return FKI_PAUTH_STEP_OK;
	}

	/* MRS/MSR of the ten EL1 PAC key registers. Rt=31 is XZR, not SP. */
	{
		static const uint32_t mrs[] = {
			0xd5382100u, 0xd5382120u, 0xd5382140u, 0xd5382160u,
			0xd5382200u, 0xd5382220u, 0xd5382240u, 0xd5382260u,
			0xd5382300u, 0xd5382320u
		};
		unsigned i;

		for (i = 0; i < 10; i++) {
			if ((insn & ~31u) == mrs[i]) {
				fki_pauth_xset(c, rd, c->key[i]);
				c->pc += 4;
				return FKI_PAUTH_STEP_OK;
			}
			if ((insn & ~31u) == (mrs[i] ^ 0x00200000u)) {
				c->key[i] = fki_pauth_xget(c, rd);
				c->pc += 4;
				return FKI_PAUTH_STEP_OK;
			}
		}
	}
	return FKI_PAUTH_STEP_UNKNOWN;
}

static inline int fki_pauth_step(struct fki_pauth_cpu *c, uint32_t insn)
{
	struct fki_pauth_cpu next = *c;
	int rc = fki_pauth_apply(&next, insn);

	if (rc == FKI_PAUTH_STEP_OK)
		*c = next;
	return rc;
}

#endif
