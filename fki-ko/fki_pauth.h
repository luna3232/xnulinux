/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Host FEAT_PAuth (CPU pointer authentication) from the ID registers only.
 *
 * Linux 6.6.9 arch/arm64/tools/sysreg, which matches the Arm ARM field layout:
 *   ID_AA64ISAR1_EL1  APA[7:4] API[11:8] GPA[27:24] GPI[31:28]
 *   ID_AA64ISAR2_EL1  GPA3[11:8] APA3[15:12]
 * Any non-zero field means that algorithm is implemented and the PAC key
 * registers are defined. All six zero means APIAKey*_EL1 (and the other four
 * key pairs) are UNDEFINED, as are the non-HINT PAC instructions (PACIA Xd,Xn,
 * RETAB, BLRAAZ, ...). The HINT-space forms (PACIASP, AUTIASP, XPACLRI, ...)
 * remain NOPs. Nothing in this header reads or writes a PAC key register.
 *
 * APA/GPA select QARMA5. API/GPI are implementation-defined (Apple arm64e).
 * APA3/GPA3 select QARMA3 (FEAT_PACQARMA3). QARMA3 is not Apple's algorithm,
 * and a software QARMA3 does not make the missing instructions defined.
 */
#ifndef _FKI_PAUTH_H
#define _FKI_PAUTH_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

struct fki_pauth_id {
	unsigned apa, api, gpa, gpi, apa3, gpa3;
	unsigned present;	/* address or generic authentication, including QARMA3 */
};

/* Packed for fki_pauth_status: one nibble each, low to high. */
#define FKI_PAUTH_PACK_APA	0
#define FKI_PAUTH_PACK_API	4
#define FKI_PAUTH_PACK_GPA	8
#define FKI_PAUTH_PACK_GPI	12
#define FKI_PAUTH_PACK_APA3	16
#define FKI_PAUTH_PACK_GPA3	20

static inline unsigned fki_pauth_nibble(uint64_t v, unsigned shift)
{
	return (unsigned)((v >> shift) & 0xf);
}

static inline void fki_pauth_decode(uint64_t isar1, uint64_t isar2, struct fki_pauth_id *id)
{
	id->apa = fki_pauth_nibble(isar1, 4);
	id->api = fki_pauth_nibble(isar1, 8);
	id->gpa = fki_pauth_nibble(isar1, 24);
	id->gpi = fki_pauth_nibble(isar1, 28);
	id->gpa3 = fki_pauth_nibble(isar2, 8);
	id->apa3 = fki_pauth_nibble(isar2, 12);
	id->present = (id->apa | id->api | id->gpa | id->gpi | id->apa3 | id->gpa3) != 0;
}

static inline uint64_t fki_pauth_pack(const struct fki_pauth_id *id)
{
	return (uint64_t)(id->apa & 15) << FKI_PAUTH_PACK_APA |
	       (uint64_t)(id->api & 15) << FKI_PAUTH_PACK_API |
	       (uint64_t)(id->gpa & 15) << FKI_PAUTH_PACK_GPA |
	       (uint64_t)(id->gpi & 15) << FKI_PAUTH_PACK_GPI |
	       (uint64_t)(id->apa3 & 15) << FKI_PAUTH_PACK_APA3 |
	       (uint64_t)(id->gpa3 & 15) << FKI_PAUTH_PACK_GPA3;
}

#endif
