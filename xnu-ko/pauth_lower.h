/* SPDX-License-Identifier: APSL-2.0 */
/*
 * Rewrite AArch64 pointer-authentication instructions in place to ordinary
 * control flow. One instruction becomes one instruction. This is the
 * experimental "remove PAC" path, not a trap emulator:
 *   RETAA/RETAB     -> RET
 *   BLRAAZ/BLRABZ/BLRAA/BLRAB -> BLR Xn   (Xn is the target register)
 *   BRAAZ/BRABZ/BRAA/BRAB     -> BR Xn
 *   PAC* and AUT* and XPAC*   -> NOP
 *   MRS of a PAC key register -> MOV Xd, XZR
 *   MSR of a PAC key register -> NOP
 * HINT-space PACIASP/AUTIASP are architecturally NOPs without FEAT_PAuth. They are
 * still rewritten to the canonical NOP so the text contains no PAC encoding
 * (some decoders, including QEMU's cortex-a57, raise SIGILL on those hints).
 * ERETAA/ERETAB are left unchanged: turning them into
 * ERET would return from an exception on the host.
 *
 * Consistent only when every PAC insert is removed too, so registers hold the
 * raw address. A pointer that already has a PAC in its high bits is not fixed
 * by turning BLRAAZ into BLR; BLR uses those bits as the address.
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
	PAUTH_LOWER_AUT_NOP,
	PAUTH_LOWER_MRS,
	PAUTH_LOWER_MSR,
	PAUTH_LOWER_REFUSED
};

struct pauth_lower_stats {
	unsigned unchanged, hint, ret, blr, br, pac_nop, aut_nop, mrs, msr, refused;
};

static inline int pauth_lower_is_hint(uint32_t insn)
{
	switch (insn) {
	case 0xd503231fu: /* paciaz */
	case 0xd503233fu: /* paciasp */
	case 0xd503235fu: /* pacibz */
	case 0xd503237fu: /* pacibsp */
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
	if (pauth_lower_is_hint(insn)) {
		*out = 0xd503201fu;
		return PAUTH_LOWER_HINT;
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
	/* AUT* and XPACI/XPACD. Inserts are gone, so stripping here would be a second edit. */
	if ((top >= 0xdac11000u && top <= 0xdac11c00u) ||
	    (insn & 0xffffffe0u) == 0xdac133e0u || (insn & 0xffffffe0u) == 0xdac137e0u ||
	    (insn & 0xffffffe0u) == 0xdac13be0u || (insn & 0xffffffe0u) == 0xdac13fe0u ||
	    (insn & 0xffffffe0u) == 0xdac143e0u || (insn & 0xffffffe0u) == 0xdac147e0u) {
		*out = 0xd503201fu;
		return PAUTH_LOWER_AUT_NOP;
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
	case PAUTH_LOWER_AUT_NOP: st->aut_nop++; break;
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

	for (i = 0; i < nwords; i++) {
		uint32_t out;
		int kind = pauth_lower_insn(code[i], &out);

		code[i] = out;
		pauth_lower_tally(st, kind);
	}
}

#endif
