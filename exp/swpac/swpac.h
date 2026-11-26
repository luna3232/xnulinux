/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Experimental software PAC model. Not a kernel emulator and not FEAT_PAuth hardware.
 *
 * swpac_computepac() is a local non-cryptographic mixer. It is not ComputePACQARMA,
 * not ComputePACIMPDEF, and not Apple silicon. Signatures from this model will not
 * authenticate on hardware PAC and hardware signatures will not authenticate here.
 *
 * The bit placement, enable-bit NOP behaviour, authentication-failure poison and
 * combined-branch PC update follow the !FEAT_PAuth2 paths of AddPAC/Authenticate
 * and D8.10.5 in Arm DDI 0487 (instruction pseudocode: Arm 111108, 2026-09).
 * See INTEGRATION.md for the implemented subset and the RB5 trap blockers.
 *
 * struct swpac_keys matches struct fki_pac_keys in fki-ko/fki.h field for field.
 * This header does not include fki.h, so a GPL module and the host test can share it.
 */
#ifndef SWPAC_H
#define SWPAC_H

#include <stdint.h>

#define SWPAC_MODEL_ID "swpac-experimental-1"

/* SCTLR_EL1 when FEAT_PAuth is implemented and FEAT_PAuth_EnhCtl is not.
 * Arm DDI 0601 (2026-09) SCTLR_EL1: EnIA [31], EnIB [30], EnDA [27], EnDB [13]. */
#define SWPAC_SCTLR_ENIA (1ull << 31)
#define SWPAC_SCTLR_ENIB (1ull << 30)
#define SWPAC_SCTLR_ENDA (1ull << 27)
#define SWPAC_SCTLR_ENDB (1ull << 13)
#define SWPAC_SCTLR_EN_MASK \
	(SWPAC_SCTLR_ENIA | SWPAC_SCTLR_ENIB | SWPAC_SCTLR_ENDA | SWPAC_SCTLR_ENDB)

/* ID_AA64ISAR1_EL1 / ID_AA64ISAR2_EL1 PAuth algorithm fields. DDI 0601. */
#define SWPAC_ISAR1_APA_SHIFT 4
#define SWPAC_ISAR1_API_SHIFT 8
#define SWPAC_ISAR1_GPA_SHIFT 24
#define SWPAC_ISAR1_GPI_SHIFT 28
#define SWPAC_ISAR2_GPA3_SHIFT 8
#define SWPAC_ISAR2_APA3_SHIFT 12

enum swpac_profile {
	/* Integer PAC encodings are UNDEFINED. HINT/system PAC encodings are NOP.
	 * This is the architectural result when APA, API, GPA, GPI, APA3 and GPA3 are zero. */
	SWPAC_PROFILE_ABSENT = 0,
	/* Virtual FEAT_PAuth only: no PAuth2, FPAC, FPACCOMBINE, PAuth_LR, CONSTPACFIELD, MTE. */
	SWPAC_PROFILE_EXPERIMENTAL = 1,
};

enum swpac_status {
	SWPAC_OK = 0,		/* experimental op performed; PC advanced or branched */
	SWPAC_UNDEF = 1,	/* not executed; register file unchanged */
	SWPAC_NOP = 2,		/* absent-profile HINT: PC += 4, nothing else changes */
	SWPAC_UNSUPPORTED = 3,	/* recognised PAC op this subset refuses; unchanged */
	SWPAC_NOT_PAC = 4,	/* not a PAC encoding; unchanged */
	SWPAC_BAD_CONFIG = 5,	/* TxSZ/TBI outside the subset; unchanged */
};

enum swpac_op {
	SWPAC_OP_NONE = 0,
	SWPAC_OP_ADD,
	SWPAC_OP_AUTH,
	SWPAC_OP_STRIP,
	SWPAC_OP_PACGA,
	SWPAC_OP_BRANCH,
	SWPAC_OP_LDRA,
	SWPAC_OP_ERET,
	SWPAC_OP_KEY_MRS,
	SWPAC_OP_KEY_MSR,
};

enum swpac_key_id {
	SWPAC_KEY_IA = 0,
	SWPAC_KEY_IB = 1,
	SWPAC_KEY_DA = 2,
	SWPAC_KEY_DB = 3,
	SWPAC_KEY_GA = 4,
};

/* Five 128-bit keys, lo then hi, then the SCTLR enable bits. 88 bytes. */
struct swpac_keys {
	uint64_t ia[2], ib[2], da[2], db[2], ga[2];
	uint64_t sctlr_en;
};

struct swpac_dec {
	enum swpac_op op;
	uint8_t key;		/* swpac_key_id; meaningful for ADD/AUTH/BRANCH/PACGA */
	uint8_t data;		/* 1: data pointer (DA/DB/XPACD); 0: instruction */
	uint8_t rd, rn, rm;	/* 31 is XZR or SP, depending on the field */
	uint8_t hint;		/* system/HINT encoding (NOP if PAuth is absent) */
	uint8_t unallocated;	/* in a PAC encoding space but not a defined variant */
	uint8_t modifier_sp;
	uint8_t modifier_zero;
	uint8_t link;		/* BLRAA/BLRAB family writes X30 */
	uint8_t ret;		/* RETAA/RETAB: source X30, modifier SP, X30 not written */
	uint8_t key_reg;	/* 0..9: ia.lo, ia.hi, ib.lo, ib.hi, da.lo, da.hi, db.lo, db.hi, ga.lo, ga.hi */
};

struct swpac_cpu {
	uint64_t x[31];
	uint64_t sp;
	uint64_t pc;
	struct swpac_keys keys;
	uint8_t t0sz, t1sz;		/* TCR_EL1.T0SZ/T1SZ; subset accepts 16..39 */
	uint8_t tbi0, tbi1;		/* TCR_EL1.TBI0/TBI1 */
	uint8_t tbid0, tbid1;		/* TCR_EL1.TBID0/TBID1 */
	uint8_t profile;		/* swpac_profile */
	struct {
		int status;
		int auth_failed;		/* Authenticate comparison failed; pointer poisoned */
		int fetch_noncanonical;		/* branch wrote a PC that is not a canonical VA */
		int enable_nop;			/* SCTLR enable clear: Add/Auth returned the input */
		uint32_t insn;
		enum swpac_op op;
	} last;
};

void swpac_cpu_init(struct swpac_cpu *c, int profile);
void swpac_keys_swap(struct swpac_cpu *c, const struct swpac_keys *load, struct swpac_keys *save);

/* 1 when every PAuth algorithm field listed above is zero. */
int swpac_id_pauth_absent(uint64_t isar1, uint64_t isar2);

/* Non-cryptographic stand-in for ComputePAC. Not hardware-compatible. */
uint64_t swpac_computepac(uint64_t data, uint64_t modifier, uint64_t key_hi, uint64_t key_lo);

int swpac_decode(uint32_t insn, struct swpac_dec *d);

/*
 * Execute one instruction word against the explicit register file.
 * Does not fetch, does not walk page tables, does not read system registers.
 * On SWPAC_UNDEF, SWPAC_UNSUPPORTED, SWPAC_NOT_PAC and SWPAC_BAD_CONFIG the
 * register file, including PC, is left unchanged.
 * On SWPAC_NOP only PC increases by 4.
 * On SWPAC_OK a branch may set PC to a poisoned non-canonical address and
 * last.auth_failed / last.fetch_noncanonical describe that result. This subset
 * does not raise a PAC Fail exception (that requires FEAT_FPAC or FEAT_FPACCOMBINE).
 */
int swpac_step(struct swpac_cpu *c, uint32_t insn);

int swpac_is_canonical(const struct swpac_cpu *c, uint64_t ptr, int data, int *yes);

int swpac_add(const struct swpac_cpu *c, int key, uint64_t ptr, uint64_t modifier, uint64_t *out);
int swpac_auth(const struct swpac_cpu *c, int key, uint64_t ptr, uint64_t modifier,
	       uint64_t *out, int *failed, int *enable_nop);
int swpac_strip(const struct swpac_cpu *c, int data, uint64_t ptr, uint64_t *out);
int swpac_pacga(const struct swpac_cpu *c, uint64_t data, uint64_t modifier, uint64_t *out);

#endif
