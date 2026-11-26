// SPDX-License-Identifier: GPL-2.0-only
/*
 * Software PAC subset. Host-testable. Not linked into fki.ko or xnu.ko.
 *
 * Placement and failure rules follow Arm 111108 (2026-09) AddPAC / Authenticate
 * for the !FEAT_PAuth2 path, and DDI 0487 D8.10.5 for combined branches without
 * FEAT_FPACCOMBINE. ComputePAC itself is swpac_computepac(), documented in the header.
 *
 * TxSZ outside 16..39 is rejected. That is the 4KB-granule, TCR_EL1.DS=0 range
 * (minimum 16 from DDI 0601 TCR_EL1.DS; maximum 39 when FEAT_TTST is not assumed).
 * The architecture allows a CONSTRAINED UNPREDICTABLE clamp for an out-of-range
 * TxSZ. This subset does not pick one of those behaviours.
 */
#include "swpac.h"
#include <string.h>

uint64_t swpac_computepac(uint64_t data, uint64_t modifier, uint64_t key_hi, uint64_t key_lo)
{
	uint64_t z = data ^ key_lo;

	z ^= modifier + 0x9E3779B97F4A7C15ull;
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
	z ^= key_hi;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
	z ^= modifier >> 17;
	z = (z ^ (z >> 31)) * 0xD6E8FEB86659FD93ull;
	z ^= z >> 32;
	return z;
}

void swpac_cpu_init(struct swpac_cpu *c, int profile)
{
	memset(c, 0, sizeof(*c));
	c->profile = (uint8_t)profile;
	c->t0sz = 16;
	c->t1sz = 16;
	c->keys.sctlr_en = SWPAC_SCTLR_EN_MASK;
}

void swpac_keys_swap(struct swpac_cpu *c, const struct swpac_keys *load, struct swpac_keys *save)
{
	if (save)
		*save = c->keys;
	if (load)
		c->keys = *load;
}

int swpac_id_pauth_absent(uint64_t isar1, uint64_t isar2)
{
	uint64_t apa = (isar1 >> SWPAC_ISAR1_APA_SHIFT) & 0xf;
	uint64_t api = (isar1 >> SWPAC_ISAR1_API_SHIFT) & 0xf;
	uint64_t gpa = (isar1 >> SWPAC_ISAR1_GPA_SHIFT) & 0xf;
	uint64_t gpi = (isar1 >> SWPAC_ISAR1_GPI_SHIFT) & 0xf;
	uint64_t gpa3 = (isar2 >> SWPAC_ISAR2_GPA3_SHIFT) & 0xf;
	uint64_t apa3 = (isar2 >> SWPAC_ISAR2_APA3_SHIFT) & 0xf;

	return apa == 0 && api == 0 && gpa == 0 && gpi == 0 && gpa3 == 0 && apa3 == 0;
}

static int txsz_ok(unsigned txsz)
{
	return txsz >= 16 && txsz <= 39;
}

static int flag01(unsigned v)
{
	return v == 0 || v == 1;
}

static int config_ok(const struct swpac_cpu *c)
{
	return txsz_ok(c->t0sz) && txsz_ok(c->t1sz) &&
		flag01(c->tbi0) && flag01(c->tbi1) && flag01(c->tbid0) && flag01(c->tbid1);
}

static int bottom_from_sel(const struct swpac_cpu *c, unsigned sel, int *bottom)
{
	unsigned txsz = sel ? c->t1sz : c->t0sz;

	if (!txsz_ok(txsz))
		return -1;
	*bottom = 64 - (int)txsz;
	/* !FEAT_PAuth2 Authenticate/InsertPAC assert bottom_PAC_bit <= 52. */
	if (*bottom > 52)
		return -1;
	return 0;
}

/* EffectiveTBI(ptr, is_instruction, EL1). data==0 means an instruction address. */
static int eff_tbi(const struct swpac_cpu *c, uint64_t ptr, int data)
{
	unsigned upper = (unsigned)((ptr >> 55) & 1);

	if (data)
		return upper ? c->tbi1 : c->tbi0;
	if (upper)
		return c->tbi1 && !c->tbid1;
	return c->tbi0 && !c->tbid0;
}

/* InsertPAC's selbit at EL1 with two ranges. Not used by Authenticate. */
static unsigned insert_selbit(const struct swpac_cpu *c, uint64_t ptr, int data)
{
	if (data) {
		if (c->tbi1 || c->tbi0)
			return (unsigned)((ptr >> 55) & 1);
		return (unsigned)((ptr >> 63) & 1);
	}
	if ((c->tbi1 && !c->tbid1) || (c->tbi0 && !c->tbid0))
		return (unsigned)((ptr >> 55) & 1);
	return (unsigned)((ptr >> 63) & 1);
}

static int range_uniform(uint64_t v, int hi, int lo)
{
	unsigned width;
	uint64_t field, ones;

	if (hi < lo)
		return 1;
	width = (unsigned)(hi - lo + 1);
	if (width >= 64)
		return 0;
	field = (v >> lo) & ((1ull << width) - 1);
	ones = (1ull << width) - 1;
	return field == 0 || field == ones;
}

static uint64_t low_bits(uint64_t v, int bottom)
{
	if (bottom <= 0)
		return 0;
	if (bottom >= 64)
		return v;
	return v & ((1ull << bottom) - 1);
}

static int key_is_data(int key)
{
	return key == SWPAC_KEY_DA || key == SWPAC_KEY_DB;
}

static unsigned key_number(int key)
{
	return (key == SWPAC_KEY_IB || key == SWPAC_KEY_DB) ? 1u : 0u;
}

static int key_enabled(const struct swpac_keys *k, int key)
{
	uint64_t bit;

	switch (key) {
	case SWPAC_KEY_IA: bit = SWPAC_SCTLR_ENIA; break;
	case SWPAC_KEY_IB: bit = SWPAC_SCTLR_ENIB; break;
	case SWPAC_KEY_DA: bit = SWPAC_SCTLR_ENDA; break;
	case SWPAC_KEY_DB: bit = SWPAC_SCTLR_ENDB; break;
	default:
		return 1;
	}
	return (k->sctlr_en & bit) != 0;
}

static void key_halves(const struct swpac_keys *k, int key, uint64_t *hi, uint64_t *lo)
{
	const uint64_t *p = k->ia;

	switch (key) {
	case SWPAC_KEY_IA: p = k->ia; break;
	case SWPAC_KEY_IB: p = k->ib; break;
	case SWPAC_KEY_DA: p = k->da; break;
	case SWPAC_KEY_DB: p = k->db; break;
	case SWPAC_KEY_GA: p = k->ga; break;
	}
	*lo = p[0];
	*hi = p[1];
}

static uint64_t gpr(const struct swpac_cpu *c, unsigned n)
{
	if (n >= 31)
		return 0;
	return c->x[n];
}

static void set_gpr(struct swpac_cpu *c, unsigned n, uint64_t v)
{
	if (n < 31)
		c->x[n] = v;
}

int swpac_is_canonical(const struct swpac_cpu *c, uint64_t ptr, int data, int *yes)
{
	unsigned sel;
	int bottom, tbi;
	unsigned width;
	uint64_t field, ext;

	if (!config_ok(c))
		return SWPAC_BAD_CONFIG;
	sel = (unsigned)((ptr >> 55) & 1);
	if (bottom_from_sel(c, sel, &bottom))
		return SWPAC_BAD_CONFIG;
	tbi = eff_tbi(c, ptr, data);
	if (tbi) {
		if (bottom > 54) {
			*yes = 1;
			return SWPAC_OK;
		}
		width = (unsigned)(54 - bottom + 1);
		field = (ptr >> bottom) & ((1ull << width) - 1);
		ext = sel ? ((1ull << width) - 1) : 0;
		*yes = field == ext;
		return SWPAC_OK;
	}
	width = (unsigned)(63 - bottom + 1);
	field = (ptr >> bottom) & ((1ull << width) - 1);
	ext = sel ? ((1ull << width) - 1) : 0;
	*yes = field == ext;
	return SWPAC_OK;
}

static uint64_t pc_fix_tbi(const struct swpac_cpu *c, uint64_t target)
{
	unsigned bit55 = (unsigned)((target >> 55) & 1);

	/* TCR_EL1.TBI*: a taken branch forces the top byte to the extension of bit 55
	 * when address tagging applies to instruction addresses. */
	if (!eff_tbi(c, target, 0))
		return target;
	if (bit55)
		return (target & 0x00ffffffffffffffull) | 0xff00000000000000ull;
	return target & 0x00ffffffffffffffull;
}

int swpac_add(const struct swpac_cpu *c, int key, uint64_t ptr, uint64_t modifier, uint64_t *out)
{
	int data, tbi, bottom, top;
	unsigned sel;
	uint64_t ext, low, ext_ptr, pac, hi, lo;
	unsigned pac_width, ext_width;

	if (key < SWPAC_KEY_IA || key > SWPAC_KEY_DB)
		return SWPAC_BAD_CONFIG;
	if (!config_ok(c))
		return SWPAC_BAD_CONFIG;
	if (!key_enabled(&c->keys, key)) {
		*out = ptr;
		return SWPAC_OK;
	}
	data = key_is_data(key);
	tbi = eff_tbi(c, ptr, data);
	sel = insert_selbit(c, ptr, data);
	if (bottom_from_sel(c, sel, &bottom))
		return SWPAC_BAD_CONFIG;
	low = low_bits(ptr, bottom);
	if (tbi) {
		ext_width = (unsigned)(55 - bottom + 1);
		ext = sel ? ((1ull << ext_width) - 1) : 0;
		ext_ptr = (ptr & 0xff00000000000000ull) | (ext << bottom) | low;
	} else {
		ext_width = (unsigned)(63 - bottom + 1);
		ext = sel ? ((1ull << ext_width) - 1) : 0;
		ext_ptr = (ext << bottom) | low;
	}
	key_halves(&c->keys, key, &hi, &lo);
	pac = swpac_computepac(ext_ptr, modifier, hi, lo);
	top = tbi ? 55 : 63;
	if (!range_uniform(ptr, top, bottom))
		pac ^= 1ull << (top - 1);
	pac_width = (unsigned)(54 - bottom + 1);
	if (tbi)
		*out = (ptr & 0xff00000000000000ull) |
			((uint64_t)sel << 55) |
			(((pac >> bottom) & ((1ull << pac_width) - 1)) << bottom) |
			low;
	else
		*out = (pac & 0xff00000000000000ull) |
			((uint64_t)sel << 55) |
			(((pac >> bottom) & ((1ull << pac_width) - 1)) << bottom) |
			low;
	return SWPAC_OK;
}

int swpac_auth(const struct swpac_cpu *c, int key, uint64_t ptr, uint64_t modifier,
	       uint64_t *out, int *failed, int *enable_nop)
{
	int data, tbi, bottom;
	unsigned sel, err, pac_width;
	uint64_t ext, low, original, pac, hi, lo, mask;

	if (failed)
		*failed = 0;
	if (enable_nop)
		*enable_nop = 0;
	if (key < SWPAC_KEY_IA || key > SWPAC_KEY_DB)
		return SWPAC_BAD_CONFIG;
	if (!config_ok(c))
		return SWPAC_BAD_CONFIG;
	if (!key_enabled(&c->keys, key)) {
		*out = ptr;
		if (enable_nop)
			*enable_nop = 1;
		return SWPAC_OK;
	}
	data = key_is_data(key);
	/* Authenticate selects the regime from bit 55, not from InsertPAC's selbit. */
	sel = (unsigned)((ptr >> 55) & 1);
	tbi = eff_tbi(c, ptr, data);
	if (bottom_from_sel(c, sel, &bottom))
		return SWPAC_BAD_CONFIG;
	low = low_bits(ptr, bottom);
	if (tbi) {
		unsigned ext_width = (unsigned)(55 - bottom + 1);

		ext = sel ? ((1ull << ext_width) - 1) : 0;
		original = (ptr & 0xff00000000000000ull) | (ext << bottom) | low;
	} else {
		unsigned ext_width = (unsigned)(63 - bottom + 1);

		ext = sel ? ((1ull << ext_width) - 1) : 0;
		original = (ext << bottom) | low;
	}
	key_halves(&c->keys, key, &hi, &lo);
	pac = swpac_computepac(original, modifier, hi, lo);
	pac_width = (unsigned)(54 - bottom + 1);
	mask = ((1ull << pac_width) - 1) << bottom;
	if (!tbi)
		mask |= 0xff00000000000000ull;
	if (((pac ^ ptr) & mask) == 0) {
		*out = original;
		return SWPAC_OK;
	}
	if (failed)
		*failed = 1;
	err = (key_number(key) << 1) | (key_number(key) ^ 1u);
	if (tbi)
		*out = (original & ~0x0060000000000000ull) | ((uint64_t)err << 53);
	else
		*out = (original & ~0x6000000000000000ull) | ((uint64_t)err << 61);
	return SWPAC_OK;
}

int swpac_strip(const struct swpac_cpu *c, int data, uint64_t ptr, uint64_t *out)
{
	unsigned sel;
	int tbi, bottom;
	uint64_t low, ext;

	if (!config_ok(c))
		return SWPAC_BAD_CONFIG;
	sel = (unsigned)((ptr >> 55) & 1);
	tbi = eff_tbi(c, ptr, data);
	if (bottom_from_sel(c, sel, &bottom))
		return SWPAC_BAD_CONFIG;
	low = low_bits(ptr, bottom);
	if (tbi) {
		unsigned ext_width = (unsigned)(55 - bottom + 1);

		ext = sel ? ((1ull << ext_width) - 1) : 0;
		*out = (ptr & 0xff00000000000000ull) | (ext << bottom) | low;
	} else {
		unsigned ext_width = (unsigned)(63 - bottom + 1);

		ext = sel ? ((1ull << ext_width) - 1) : 0;
		*out = (ext << bottom) | low;
	}
	return SWPAC_OK;
}

int swpac_pacga(const struct swpac_cpu *c, uint64_t data, uint64_t modifier, uint64_t *out)
{
	uint64_t hi, lo;

	key_halves(&c->keys, SWPAC_KEY_GA, &hi, &lo);
	/* AddPACGA: high 32 bits of ComputePAC, low 32 bits zero. No SCTLR enable. */
	*out = swpac_computepac(data, modifier, hi, lo) & ~0xffffffffull;
	return SWPAC_OK;
}

static void dec_clear(struct swpac_dec *d)
{
	memset(d, 0, sizeof(*d));
}

static void dec_add_family(struct swpac_dec *d, int opcode, int z, unsigned rn, unsigned rd)
{
	static const uint8_t keys[8] = {
		SWPAC_KEY_IA, SWPAC_KEY_IB, SWPAC_KEY_DA, SWPAC_KEY_DB,
		SWPAC_KEY_IA, SWPAC_KEY_IB, SWPAC_KEY_DA, SWPAC_KEY_DB,
	};

	d->op = opcode < 4 ? SWPAC_OP_ADD : SWPAC_OP_AUTH;
	d->key = keys[opcode & 7];
	d->data = key_is_data(d->key);
	d->rd = (uint8_t)rd;
	d->rn = (uint8_t)rn;
	if (z) {
		d->modifier_zero = 1;
		if (rn != 31)
			d->unallocated = 1;
	} else if (rn == 31) {
		d->modifier_sp = 1;
	}
}

int swpac_decode(uint32_t insn, struct swpac_dec *d)
{
	if (!d)
		return SWPAC_BAD_CONFIG;
	dec_clear(d);

	/* HINT space. Arm system encodings: CRm:op2 select PACIAZ/PACIASP/.../XPACLRI.
	 * Any other HINT (NOP, BTI, ...) is not a PAC instruction. */
	if ((insn & 0xfffff01fu) == 0xd503201fu) {
		unsigned crm = (insn >> 8) & 0xf;
		unsigned op2 = (insn >> 5) & 7;

		d->hint = 1;
		if (crm == 3 && op2 <= 7) {
			static const uint8_t k[8] = {
				SWPAC_KEY_IA, SWPAC_KEY_IA, SWPAC_KEY_IB, SWPAC_KEY_IB,
				SWPAC_KEY_IA, SWPAC_KEY_IA, SWPAC_KEY_IB, SWPAC_KEY_IB,
			};
			d->op = (op2 & 4) ? SWPAC_OP_AUTH : SWPAC_OP_ADD;
			d->key = k[op2];
			d->rd = 30;
			d->modifier_zero = (op2 & 1) ? 0 : 1;
			d->modifier_sp = (op2 & 1) ? 1 : 0;
			return SWPAC_OK;
		}
		if (crm == 1 && (op2 == 0 || op2 == 2 || op2 == 4 || op2 == 6)) {
			d->op = (op2 & 4) ? SWPAC_OP_AUTH : SWPAC_OP_ADD;
			d->key = (op2 & 2) ? SWPAC_KEY_IB : SWPAC_KEY_IA;
			d->rd = 17;
			d->rn = 16;
			return SWPAC_OK;
		}
		if (crm == 0 && op2 == 7) {
			d->op = SWPAC_OP_STRIP;
			d->rd = 30;
			return SWPAC_OK;
		}
		dec_clear(d);
		return SWPAC_OK;
	}

	/* Integer PACIA/AUTIA/XPACI family. Bits [31:15] of the PACIA encoding. */
	if ((insn & 0xffff8000u) == 0xdac10000u) {
		unsigned bit14 = (insn >> 14) & 1;
		unsigned z = (insn >> 13) & 1;
		unsigned opcode = (insn >> 10) & 7;
		unsigned rn = (insn >> 5) & 31;
		unsigned rd = insn & 31;

		if (!bit14) {
			dec_add_family(d, (int)opcode, (int)z, rn, rd);
			return SWPAC_OK;
		}
		d->rd = (uint8_t)rd;
		d->rn = (uint8_t)rn;
		if (!z && rn == 31 && opcode == 0) {
			d->op = SWPAC_OP_STRIP;
			return SWPAC_OK;
		}
		if (!z && rn == 31 && opcode == 1) {
			d->op = SWPAC_OP_STRIP;
			d->data = 1;
			return SWPAC_OK;
		}
		d->op = SWPAC_OP_ADD;
		d->unallocated = 1;
		return SWPAC_OK;
	}

	/* BLRAA/BLRAAZ/BLRAB/BLRABZ and BRAA/BRAAZ/BRAB/BRABZ.
	 * Bit 21 is the link bit (1 = BLR). Bit 24 is Z. Bit 10 is M (0 = key A). */
	if ((insn & 0xfedff800u) == 0xd61f0800u) {
		unsigned z = (insn >> 24) & 1;
		unsigned link = (insn >> 21) & 1;
		unsigned m = (insn >> 10) & 1;
		unsigned rn = (insn >> 5) & 31;
		unsigned rm = insn & 31;

		d->op = SWPAC_OP_BRANCH;
		d->key = m ? SWPAC_KEY_IB : SWPAC_KEY_IA;
		d->rn = (uint8_t)rn;
		d->rm = (uint8_t)rm;
		d->link = (uint8_t)link;
		if (!z) {
			d->modifier_zero = 1;
			if (rm != 31)
				d->unallocated = 1;
		} else if (rm == 31) {
			d->modifier_sp = 1;
		}
		return SWPAC_OK;
	}

	/* RETAA (M=0) / RETAB (M=1). Exact encoding apart from bit 10. */
	if ((insn & 0xfffffbffu) == 0xd65f0bffu) {
		d->op = SWPAC_OP_BRANCH;
		d->ret = 1;
		d->key = (insn & 0x400u) ? SWPAC_KEY_IB : SWPAC_KEY_IA;
		d->rd = 30;
		d->modifier_sp = 1;
		return SWPAC_OK;
	}

	/* ERETAA/ERETAB. Recognised and refused: exception return is not in this subset. */
	if ((insn & 0xfffffbffu) == 0xd69f0bffu) {
		d->op = SWPAC_OP_ERET;
		d->key = (insn & 0x400u) ? SWPAC_KEY_IB : SWPAC_KEY_IA;
		d->ret = 1;
		return SWPAC_OK;
	}

	/* PACGA Xd, Xn, Xm|SP. */
	if ((insn & 0xffe0fc00u) == 0x9ac03000u) {
		d->op = SWPAC_OP_PACGA;
		d->key = SWPAC_KEY_GA;
		d->rd = (uint8_t)(insn & 31);
		d->rn = (uint8_t)((insn >> 5) & 31);
		d->rm = (uint8_t)((insn >> 16) & 31);
		if (d->rm == 31)
			d->modifier_sp = 1;
		return SWPAC_OK;
	}

	/* LDRAA/LDRAB. Mask from the 111108 encoding table (bits 31:24, bit 21, bit 10). */
	if ((insn & 0xff200400u) == 0xf8200400u) {
		d->op = SWPAC_OP_LDRA;
		d->key = (insn & 0x00800000u) ? SWPAC_KEY_DB : SWPAC_KEY_DA;
		d->data = 1;
		d->modifier_zero = 1;
		d->rd = (uint8_t)(insn & 31);
		d->rn = (uint8_t)((insn >> 5) & 31);
		return SWPAC_OK;
	}

	/* MRS/MSR of the ten PAC key registers. op0=3, op1=0, CRn=2, CRm=1..3, op2=0..3. */
	if ((insn & 0xfff00000u) == 0xd5300000u || (insn & 0xfff00000u) == 0xd5100000u) {
		static const uint32_t fields[10] = {
			(3u << 19) | (2u << 12) | (1u << 8) | (0u << 5),
			(3u << 19) | (2u << 12) | (1u << 8) | (1u << 5),
			(3u << 19) | (2u << 12) | (1u << 8) | (2u << 5),
			(3u << 19) | (2u << 12) | (1u << 8) | (3u << 5),
			(3u << 19) | (2u << 12) | (2u << 8) | (0u << 5),
			(3u << 19) | (2u << 12) | (2u << 8) | (1u << 5),
			(3u << 19) | (2u << 12) | (2u << 8) | (2u << 5),
			(3u << 19) | (2u << 12) | (2u << 8) | (3u << 5),
			(3u << 19) | (2u << 12) | (3u << 8) | (0u << 5),
			(3u << 19) | (2u << 12) | (3u << 8) | (1u << 5),
		};
		uint32_t field = insn & 0x001fffe0u;
		int i;

		for (i = 0; i < 10; i++) {
			if (field != fields[i])
				continue;
			d->op = ((insn & 0xfff00000u) == 0xd5300000u) ? SWPAC_OP_KEY_MRS : SWPAC_OP_KEY_MSR;
			d->key_reg = (uint8_t)i;
			d->rd = (uint8_t)(insn & 31);
			return SWPAC_OK;
		}
	}
	return SWPAC_OK;
}

static uint64_t *key_word(struct swpac_keys *k, unsigned index)
{
	switch (index) {
	case 0: return &k->ia[0];
	case 1: return &k->ia[1];
	case 2: return &k->ib[0];
	case 3: return &k->ib[1];
	case 4: return &k->da[0];
	case 5: return &k->da[1];
	case 6: return &k->db[0];
	case 7: return &k->db[1];
	case 8: return &k->ga[0];
	default: return &k->ga[1];
	}
}

static uint64_t modifier_value(const struct swpac_cpu *c, const struct swpac_dec *d)
{
	if (d->modifier_zero)
		return 0;
	if (d->modifier_sp || d->ret)
		return c->sp;
	if (d->op == SWPAC_OP_ADD || d->op == SWPAC_OP_AUTH)
		return gpr(c, d->rn);
	return gpr(c, d->rm);
}

int swpac_step(struct swpac_cpu *c, uint32_t insn)
{
	struct swpac_dec d;
	struct swpac_cpu next;
	int st, failed = 0, enable_nop = 0, fetch_bad = 0;
	uint64_t value, modifier, ptr;

	memset(&c->last, 0, sizeof(c->last));
	c->last.insn = insn;
	swpac_decode(insn, &d);
	c->last.op = d.op;

	if (d.op == SWPAC_OP_NONE) {
		c->last.status = SWPAC_NOT_PAC;
		return SWPAC_NOT_PAC;
	}
	if (c->profile == SWPAC_PROFILE_ABSENT) {
		if (d.hint && !d.unallocated) {
			c->pc += 4;
			c->last.status = SWPAC_NOP;
			return SWPAC_NOP;
		}
		c->last.status = SWPAC_UNDEF;
		return SWPAC_UNDEF;
	}
	if (c->profile != SWPAC_PROFILE_EXPERIMENTAL) {
		c->last.status = SWPAC_BAD_CONFIG;
		return SWPAC_BAD_CONFIG;
	}
	if (d.unallocated) {
		c->last.status = SWPAC_UNDEF;
		return SWPAC_UNDEF;
	}
	if (d.op == SWPAC_OP_LDRA || d.op == SWPAC_OP_ERET) {
		c->last.status = SWPAC_UNSUPPORTED;
		return SWPAC_UNSUPPORTED;
	}

	next = *c;
	modifier = modifier_value(c, &d);
	switch (d.op) {
	case SWPAC_OP_ADD:
		ptr = gpr(c, d.rd);
		st = swpac_add(c, d.key, ptr, modifier, &value);
		if (st != SWPAC_OK)
			goto bad;
		set_gpr(&next, d.rd, value);
		next.pc = c->pc + 4;
		enable_nop = !key_enabled(&c->keys, d.key);
		break;
	case SWPAC_OP_AUTH:
		ptr = gpr(c, d.rd);
		st = swpac_auth(c, d.key, ptr, modifier, &value, &failed, &enable_nop);
		if (st != SWPAC_OK)
			goto bad;
		set_gpr(&next, d.rd, value);
		next.pc = c->pc + 4;
		break;
	case SWPAC_OP_STRIP:
		ptr = gpr(c, d.rd);
		st = swpac_strip(c, d.data, ptr, &value);
		if (st != SWPAC_OK)
			goto bad;
		set_gpr(&next, d.rd, value);
		next.pc = c->pc + 4;
		break;
	case SWPAC_OP_PACGA:
		ptr = gpr(c, d.rn);
		if (d.modifier_sp)
			modifier = c->sp;
		else
			modifier = gpr(c, d.rm);
		st = swpac_pacga(c, ptr, modifier, &value);
		if (st != SWPAC_OK)
			goto bad;
		set_gpr(&next, d.rd, value);
		next.pc = c->pc + 4;
		break;
	case SWPAC_OP_BRANCH: {
		int canonical = 0;

		if (d.ret)
			ptr = gpr(c, 30);
		else
			ptr = gpr(c, d.rn);
		st = swpac_auth(c, d.key, ptr, modifier, &value, &failed, &enable_nop);
		if (st != SWPAC_OK)
			goto bad;
		if (d.link)
			set_gpr(&next, 30, c->pc + 4);
		value = pc_fix_tbi(c, value);
		next.pc = value;
		if (swpac_is_canonical(c, value, 0, &canonical) != SWPAC_OK)
			goto bad;
		fetch_bad = !canonical;
		break;
	}
	case SWPAC_OP_KEY_MRS:
		value = *key_word(&c->keys, d.key_reg);
		set_gpr(&next, d.rd, value);
		next.pc = c->pc + 4;
		break;
	case SWPAC_OP_KEY_MSR:
		*key_word(&next.keys, d.key_reg) = gpr(c, d.rd);
		next.pc = c->pc + 4;
		break;
	default:
		c->last.status = SWPAC_UNSUPPORTED;
		return SWPAC_UNSUPPORTED;
	}
	next.last = c->last;
	next.last.status = SWPAC_OK;
	next.last.auth_failed = failed;
	next.last.enable_nop = enable_nop;
	next.last.fetch_noncanonical = fetch_bad;
	next.last.insn = insn;
	next.last.op = d.op;
	*c = next;
	return SWPAC_OK;
bad:
	c->last.status = SWPAC_BAD_CONFIG;
	c->last.op = d.op;
	c->last.insn = insn;
	return SWPAC_BAD_CONFIG;
}
