/* SPDX-License-Identifier: APSL-2.0 */
/*
 * Rewrite AArch64 pointer-authentication instructions in place to ordinary
 * control flow. One instruction becomes one instruction. This is the
 * experimental "remove PAC" path, not a trap emulator:
 *   RETAA/RETAB     -> RET
 *   BLRAAZ/BLRABZ/BLRAA/BLRAB -> BLR Xn   (Xn is the target register)
 *   BRAAZ/BRABZ/BRAA/BRAB     -> BR Xn
 *   PAC* inserts, including HINT PACIASP/PACIBSP -> NOP
 *     (without FEAT_PAuth those hints already execute as NOP and never sign)
 *   AUT* and XPAC* -> SBFX Xd, Xd, #0, #56
 *     (sign-extend bit 55 through [63:56]; a canonical pointer is unchanged)
 *   MRS of a PAC key register -> MOV Xd, XZR
 *   MSR of a PAC key register -> NOP
 * If a PAC insert that writes Xn is the instruction immediately before a BLRA or BRA of Xn,
 * that slot becomes the SBFX and the branch becomes BLR or BR. A branch with no such
 * slot stays a raw BLR or BR: one instruction cannot both strip and branch.
 * If PACIBSP/PACIASP is immediately before RETAA/RETAB, that slot becomes
 * SBFX X30 and the return becomes RET. The hint did not sign X30.
 * ERETAA/ERETAB are left unchanged.
 */
#ifndef XNU_PAUTH_LOWER_H
#define XNU_PAUTH_LOWER_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

enum {
	PAUTH_LOWER_UNCHANGED = 0,
	PAUTH_LOWER_HINT,
	PAUTH_LOWER_RET,
	PAUTH_LOWER_BLR,
	PAUTH_LOWER_BR,
	PAUTH_LOWER_PAC_NOP,
	PAUTH_LOWER_CANON,
	PAUTH_LOWER_MRS,
	PAUTH_LOWER_MSR,
	PAUTH_LOWER_REFUSED
};

struct pauth_lower_stats {
	unsigned unchanged, hint, ret, blr, br, pac_nop, canon, branch_raw, mrs, msr, refused;
};

/* SBFX Xd, Xd, #0, #56: bits [63:56] become the extension of bit 55. */
static inline uint32_t pauth_sbfx_self(unsigned rd)
{
	return 0x9340dc00u | (rd << 5) | rd;
}

static inline int pauth_lower_is_sign_hint(uint32_t insn)
{
	switch (insn) {
	case 0xd503231fu: /* paciaz */
	case 0xd503233fu: /* paciasp */
	case 0xd503235fu: /* pacibz */
	case 0xd503237fu: /* pacibsp */
		return 1;
	default:
		return 0;
	}
}

static inline int pauth_lower_is_strip_hint(uint32_t insn)
{
	switch (insn) {
	case 0xd503239fu: /* autiaz */
	case 0xd50323bfu: /* autiasp */
	case 0xd50323dfu: /* autibz */
	case 0xd50323ffu: /* autibsp */
	case 0xd50320ffu: /* xpaclri */
		return 1;
	default:
		return 0;
	}
}

/* Non-hint PAC insert. *rd is the register that would have been signed. */
static inline int pauth_lower_is_pac_reg(uint32_t insn, unsigned *rd)
{
	uint32_t top = insn & 0xfffffc00u;

	*rd = insn & 31u;
	if (top >= 0xdac10000u && top <= 0xdac10c00u)
		return 1;
	if ((insn & 0xffffffe0u) == 0xdac123e0u || (insn & 0xffffffe0u) == 0xdac127e0u ||
	    (insn & 0xffffffe0u) == 0xdac12be0u || (insn & 0xffffffe0u) == 0xdac12fe0u)
		return 1;
	return 0;
}

static inline int pauth_lower_is_key_sys(uint32_t insn, int *is_msr, unsigned *rd)
{
	static const uint32_t mrs[] = {
		0xd5382100u, 0xd5382120u, 0xd5382140u, 0xd5382160u,
		0xd5382200u, 0xd5382220u, 0xd5382240u, 0xd5382260u,
		0xd5382300u, 0xd5382320u
	};
	unsigned i;

	*rd = insn & 31u;
	for (i = 0; i < 10; i++) {
		if ((insn & ~31u) == mrs[i]) {
			*is_msr = 0;
			return 1;
		}
		if ((insn & ~31u) == (mrs[i] ^ 0x00200000u)) {
			*is_msr = 1;
			return 1;
		}
	}
	return 0;
}

/* Rewrite one instruction. *out is the replacement; the class is the return value. */
static inline int pauth_lower_insn(uint32_t insn, uint32_t *out)
{
	unsigned rn = (insn >> 5) & 31u;
	unsigned rd = insn & 31u;
	uint32_t top = insn & 0xfffffc00u;
	int is_msr = 0;

	*out = insn;
	if (pauth_lower_is_sign_hint(insn)) {
		*out = 0xd503201fu;	/* hardware already executes this as NOP */
		return PAUTH_LOWER_HINT;
	}
	if (pauth_lower_is_strip_hint(insn)) {
		*out = pauth_sbfx_self(30);
		return PAUTH_LOWER_CANON;
	}
	if (insn == 0xd69f0bffu || insn == 0xd69f0fffu)
		return PAUTH_LOWER_REFUSED;
	if (insn == 0xd65f0bffu || insn == 0xd65f0fffu) {
		*out = 0xd65f03c0u;	/* RET X30 */
		return PAUTH_LOWER_RET;
	}
	if ((insn & 0xfffffc1fu) == 0xd63f081fu || (insn & 0xfffffc1fu) == 0xd63f0c1fu ||
	    top == 0xd73f0800u || top == 0xd73f0c00u) {
		*out = 0xd63f0000u | (rn << 5);	/* BLR Xn */
		return PAUTH_LOWER_BLR;
	}
	if ((insn & 0xfffffc1fu) == 0xd61f081fu || (insn & 0xfffffc1fu) == 0xd61f0c1fu ||
	    top == 0xd71f0800u || top == 0xd71f0c00u) {
		*out = 0xd61f0000u | (rn << 5);	/* BR Xn */
		return PAUTH_LOWER_BR;
	}
	/* PACIA/B/DA/DB and the zero-modifier PACIZ* forms. */
	if ((top >= 0xdac10000u && top <= 0xdac10c00u) ||
	    (insn & 0xffffffe0u) == 0xdac123e0u || (insn & 0xffffffe0u) == 0xdac127e0u ||
	    (insn & 0xffffffe0u) == 0xdac12be0u || (insn & 0xffffffe0u) == 0xdac12fe0u) {
		*out = 0xd503201fu;
		return PAUTH_LOWER_PAC_NOP;
	}
	/* AUT* and XPACI/XPACD: canonicalize the pointer register. The modifier is dropped. */
	if ((top >= 0xdac11000u && top <= 0xdac11c00u) ||
	    (insn & 0xffffffe0u) == 0xdac133e0u || (insn & 0xffffffe0u) == 0xdac137e0u ||
	    (insn & 0xffffffe0u) == 0xdac13be0u || (insn & 0xffffffe0u) == 0xdac13fe0u ||
	    (insn & 0xffffffe0u) == 0xdac143e0u || (insn & 0xffffffe0u) == 0xdac147e0u) {
		*out = pauth_sbfx_self(rd);
		return PAUTH_LOWER_CANON;
	}
	if (pauth_lower_is_key_sys(insn, &is_msr, &rd)) {
		if (is_msr) {
			*out = 0xd503201fu;
			return PAUTH_LOWER_MSR;
		}
		*out = 0xaa1f03e0u | rd;	/* MOV Xd, XZR (Rd=31 encodes XZR) */
		return PAUTH_LOWER_MRS;
	}
	return PAUTH_LOWER_UNCHANGED;
}

static inline void pauth_lower_tally(struct pauth_lower_stats *st, int kind)
{
	if (!st)
		return;
	switch (kind) {
	case PAUTH_LOWER_HINT: st->hint++; break;
	case PAUTH_LOWER_RET: st->ret++; break;
	case PAUTH_LOWER_BLR: st->blr++; break;
	case PAUTH_LOWER_BR: st->br++; break;
	case PAUTH_LOWER_PAC_NOP: st->pac_nop++; break;
	case PAUTH_LOWER_CANON: st->canon++; break;
	case PAUTH_LOWER_MRS: st->mrs++; break;
	case PAUTH_LOWER_MSR: st->msr++; break;
	case PAUTH_LOWER_REFUSED: st->refused++; break;
	default: st->unchanged++; break;
	}
}

/* nwords of code, rewritten in place. The tail of a span that is not a whole instruction is ignored. */
static inline void pauth_lower_span(uint32_t *code, size_t nwords, struct pauth_lower_stats *st)
{
	size_t i;
	uint32_t prev = 0;
	int have_prev = 0;

	for (i = 0; i < nwords; i++) {
		uint32_t in = code[i];
		uint32_t out;
		int kind = pauth_lower_insn(in, &out);
		unsigned rn = (in >> 5) & 31u;
		unsigned rd = 0;

		if (have_prev && kind == PAUTH_LOWER_RET && pauth_lower_is_sign_hint(prev)) {
			code[i - 1] = pauth_sbfx_self(30);
			if (st)
				st->canon++;
		}
		if (have_prev && (kind == PAUTH_LOWER_BLR || kind == PAUTH_LOWER_BR) &&
		    pauth_lower_is_pac_reg(prev, &rd) && rd == rn) {
			code[i - 1] = pauth_sbfx_self(rn);
			if (st)
				st->canon++;
		} else if (kind == PAUTH_LOWER_BLR || kind == PAUTH_LOWER_BR) {
			if (st)
				st->branch_raw++;
		}
		code[i] = out;
		pauth_lower_tally(st, kind);
		prev = in;
		have_prev = 1;
	}
}

#endif
