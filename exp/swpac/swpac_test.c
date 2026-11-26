// SPDX-License-Identifier: GPL-2.0-only
/*
 * Host tests for the software PAC model.
 * These do not boot a kernel, do not execute on an RB5, and do not run macOS.
 */
#include "swpac.h"
#include "fixtures.inc"
#include "../../fki-ko/fki.h"
#include "../../xnu-ko/world.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

static int g_pass, g_fail;
static const char *g_ctx;

static void check(int cond, const char *file, int line, const char *expr)
{
	if (cond) {
		g_pass++;
		return;
	}
	g_fail++;
	fprintf(stderr, "FAIL %s:%d: %s%s%s\n", file, line, expr, g_ctx ? " :: " : "", g_ctx ? g_ctx : "");
}

#define CHECK(c) check(!!(c), __FILE__, __LINE__, #c)

_Static_assert(sizeof(struct swpac_keys) == sizeof(struct fki_pac_keys), "key block size");
_Static_assert(__builtin_offsetof(struct swpac_keys, ia) == __builtin_offsetof(struct fki_pac_keys, ia), "ia");
_Static_assert(__builtin_offsetof(struct swpac_keys, ib) == __builtin_offsetof(struct fki_pac_keys, ib), "ib");
_Static_assert(__builtin_offsetof(struct swpac_keys, da) == __builtin_offsetof(struct fki_pac_keys, da), "da");
_Static_assert(__builtin_offsetof(struct swpac_keys, db) == __builtin_offsetof(struct fki_pac_keys, db), "db");
_Static_assert(__builtin_offsetof(struct swpac_keys, ga) == __builtin_offsetof(struct fki_pac_keys, ga), "ga");
_Static_assert(__builtin_offsetof(struct swpac_keys, sctlr_en) == __builtin_offsetof(struct fki_pac_keys, sctlr_en), "sctlr_en");
_Static_assert(sizeof(struct fki_pac_keys) == 88, "fki_pac_keys");
_Static_assert(__builtin_offsetof(struct xnu_world, linux_keys) == 240, "linux_keys");
_Static_assert(__builtin_offsetof(struct xnu_world, xnu_keys) == 328, "xnu_keys");

static int starts(const char *s, const char *pfx)
{
	size_t n = strlen(pfx);

	return strncmp(s, pfx, n) == 0 && (s[n] == 0 || s[n] == ' ' || s[n] == '\t');
}

static int parse_reg(const char **ps, int *rn)
{
	const char *s = *ps;

	while (*s == ' ' || *s == '\t' || *s == ',')
		s++;
	if (!strncmp(s, "sp", 2) && (s[2] == 0 || s[2] == ',' || s[2] == ' ' || s[2] == ']')) {
		*rn = 31;
		*ps = s + 2;
		return 1;
	}
	if (!strncmp(s, "xzr", 3)) {
		*rn = 31;
		*ps = s + 3;
		return 1;
	}
	if (s[0] == 'x' && isdigit((unsigned char)s[1])) {
		int n = 0;

		s++;
		while (isdigit((unsigned char)*s)) {
			n = n * 10 + (*s - '0');
			s++;
		}
		if (n > 31)
			return 0;
		*rn = n;
		*ps = s;
		return 1;
	}
	return 0;
}

static void expect_dec(const char *text, const struct swpac_dec *d)
{
	const char *rest = text;
	int rd = -1, rn = -1, rm = -1;

	g_ctx = text;

	if (starts(text, "nop") || starts(text, "ret") || starts(text, "bti") ||
	    starts(text, "ldr") || starts(text, "mrs x10,")) {
		CHECK(d->op == SWPAC_OP_NONE);
		return;
	}
	CHECK(d->op != SWPAC_OP_NONE);
	CHECK(!d->unallocated);

	if (starts(text, "pacia1716") || starts(text, "pacib1716") ||
	    starts(text, "autia1716") || starts(text, "autib1716")) {
		int auth = strncmp(text, "aut", 3) == 0;
		int b = text[4] == 'b' || text[3] == 'b';

		CHECK(d->hint && d->op == (auth ? SWPAC_OP_AUTH : SWPAC_OP_ADD));
		CHECK(d->key == (b ? SWPAC_KEY_IB : SWPAC_KEY_IA));
		CHECK(d->rd == 17 && d->rn == 16 && !d->modifier_zero && !d->modifier_sp);
		return;
	}
	if (starts(text, "paciasp") || starts(text, "pacibsp") || starts(text, "autiasp") || starts(text, "autibsp") ||
	    starts(text, "paciaz") || starts(text, "pacibz") || starts(text, "autiaz") || starts(text, "autibz")) {
		int auth = strncmp(text, "aut", 3) == 0;
		int b = text[4] == 'b' || text[3] == 'b';
		int sp = strstr(text, "sp") != NULL;

		CHECK(d->hint && d->rd == 30);
		CHECK(d->op == (auth ? SWPAC_OP_AUTH : SWPAC_OP_ADD));
		CHECK(d->key == (b ? SWPAC_KEY_IB : SWPAC_KEY_IA));
		CHECK(d->modifier_sp == sp);
		CHECK(d->modifier_zero == !sp);
		return;
	}
	if (starts(text, "xpaclri")) {
		CHECK(d->op == SWPAC_OP_STRIP && d->hint && d->rd == 30 && !d->data);
		return;
	}
	if (starts(text, "xpaci") || starts(text, "xpacd")) {
		CHECK(d->op == SWPAC_OP_STRIP && !d->hint);
		CHECK(d->data == starts(text, "xpacd"));
		rest = strchr(text, ' ');
		CHECK(rest && parse_reg(&rest, &rd) && d->rd == rd);
		return;
	}
	if (starts(text, "retaa") || starts(text, "retab")) {
		CHECK(d->op == SWPAC_OP_BRANCH && d->ret && d->modifier_sp && !d->link);
		CHECK(d->key == (starts(text, "retab") ? SWPAC_KEY_IB : SWPAC_KEY_IA));
		return;
	}
	if (starts(text, "eretaa") || starts(text, "eretab")) {
		CHECK(d->op == SWPAC_OP_ERET);
		CHECK(d->key == (starts(text, "eretab") ? SWPAC_KEY_IB : SWPAC_KEY_IA));
		return;
	}
	if (starts(text, "ldraa") || starts(text, "ldrab")) {
		CHECK(d->op == SWPAC_OP_LDRA && d->data && d->modifier_zero);
		CHECK(d->key == (starts(text, "ldrab") ? SWPAC_KEY_DB : SWPAC_KEY_DA));
		return;
	}
	if (starts(text, "blraaz") || starts(text, "blrabz") || starts(text, "braaz") || starts(text, "brabz") ||
	    starts(text, "blraa") || starts(text, "blrab") || starts(text, "braa") || starts(text, "brab")) {
		int link = strncmp(text, "bl", 2) == 0;
		int b = strstr(text, "brab") || strstr(text, "blrab");
		int zero = strstr(text, "z ") || text[strlen(text) - 1] == 'z';

		CHECK(d->op == SWPAC_OP_BRANCH && !d->ret && !d->hint);
		CHECK(d->link == link);
		CHECK(d->key == (b ? SWPAC_KEY_IB : SWPAC_KEY_IA));
		CHECK(d->modifier_zero == (zero && !strchr(text, ',')));
		rest = strchr(text, ' ');
		CHECK(rest && parse_reg(&rest, &rn) && d->rn == rn);
		if (strchr(text, ',')) {
			CHECK(parse_reg(&rest, &rm));
			if (rm == 31)
				CHECK(d->modifier_sp);
			else
				CHECK(d->rm == rm && !d->modifier_sp && !d->modifier_zero);
		}
		return;
	}
	if (starts(text, "pacga")) {
		CHECK(d->op == SWPAC_OP_PACGA && d->key == SWPAC_KEY_GA);
		rest = strchr(text, ' ');
		CHECK(rest && parse_reg(&rest, &rd) && parse_reg(&rest, &rn) && parse_reg(&rest, &rm));
		CHECK(d->rd == rd && d->rn == rn);
		if (rm == 31)
			CHECK(d->modifier_sp);
		else
			CHECK(d->rm == rm && !d->modifier_sp);
		return;
	}
	if (starts(text, "mrs") || starts(text, "msr")) {
		static const char *names[] = {
			"APIAKeyLo_EL1", "APIAKeyHi_EL1", "APIBKeyLo_EL1", "APIBKeyHi_EL1",
			"APDAKeyLo_EL1", "APDAKeyHi_EL1", "APDBKeyLo_EL1", "APDBKeyHi_EL1",
			"APGAKeyLo_EL1", "APGAKeyHi_EL1",
		};
		int i, found = -1;

		CHECK(d->op == (starts(text, "mrs") ? SWPAC_OP_KEY_MRS : SWPAC_OP_KEY_MSR));
		for (i = 0; i < 10; i++)
			if (strstr(text, names[i]))
				found = i;
		CHECK(found == d->key_reg);
		rest = strchr(text, 'x');
		CHECK(rest && parse_reg(&rest, &rd) && d->rd == rd);
		return;
	}
	if (starts(text, "paciza") || starts(text, "pacizb") || starts(text, "pacdza") || starts(text, "pacdzb") ||
	    starts(text, "autiza") || starts(text, "autizb") || starts(text, "autdza") || starts(text, "autdzb") ||
	    starts(text, "pacia") || starts(text, "pacib") || starts(text, "pacda") || starts(text, "pacdb") ||
	    starts(text, "autia") || starts(text, "autib") || starts(text, "autda") || starts(text, "autdb")) {
		int auth = strncmp(text, "aut", 3) == 0;
		int zero = strstr(text, "z") && !strchr(text, ',');
		int key = SWPAC_KEY_IA;

		if (strstr(text, "izb") || strstr(text, "ib"))
			key = SWPAC_KEY_IB;
		else if (strstr(text, "dzb") || strstr(text, "db"))
			key = SWPAC_KEY_DB;
		else if (strstr(text, "dza") || strstr(text, "da"))
			key = SWPAC_KEY_DA;
		CHECK(d->op == (auth ? SWPAC_OP_AUTH : SWPAC_OP_ADD));
		CHECK(d->key == key);
		CHECK(d->data == (key == SWPAC_KEY_DA || key == SWPAC_KEY_DB));
		CHECK(d->modifier_zero == zero);
		CHECK(!d->hint);
		rest = strchr(text, ' ');
		CHECK(rest && parse_reg(&rest, &rd) && d->rd == rd);
		if (!zero) {
			CHECK(parse_reg(&rest, &rn));
			if (rn == 31)
				CHECK(d->modifier_sp);
			else
				CHECK(d->rn == rn && !d->modifier_sp);
		}
		return;
	}
	CHECK(0 && "unclassified fixture");
}

static void test_fixtures(void)
{
	size_t i;
	int saw_retab = 0, saw_pacia = 0, saw_blraaz = 0;

	CHECK(sizeof(swpac_fixtures) / sizeof(swpac_fixtures[0]) > 40);
	for (i = 0; i < sizeof(swpac_fixtures) / sizeof(swpac_fixtures[0]); i++) {
		struct swpac_dec d;

		CHECK(swpac_decode(swpac_fixtures[i].insn, &d) == SWPAC_OK);
		expect_dec(swpac_fixtures[i].text, &d);
		if (!strcmp(swpac_fixtures[i].text, "retab")) {
			saw_retab = 1;
			CHECK(swpac_fixtures[i].insn == 0xd65f0fffu);
		}
		if (!strcmp(swpac_fixtures[i].text, "pacia x0, x1")) {
			saw_pacia = 1;
			CHECK(swpac_fixtures[i].insn == 0xdac10020u);
		}
		if (!strcmp(swpac_fixtures[i].text, "blraaz x16")) {
			saw_blraaz = 1;
			CHECK(swpac_fixtures[i].insn == 0xd63f0a1fu);
		}
	}
	CHECK(saw_retab && saw_pacia && saw_blraaz);
	g_ctx = NULL;
}

static void test_id(void)
{
	/* Handed-over cluster value. APA/API/GPA/GPI are zero; DPB and AES are not PAuth. */
	CHECK(swpac_id_pauth_absent(0x100001ull, 0));
	CHECK(swpac_id_pauth_absent(0, 0));
	CHECK(!swpac_id_pauth_absent(0x100001ull | (1ull << SWPAC_ISAR1_API_SHIFT), 0));
	CHECK(!swpac_id_pauth_absent(0x100001ull | (1ull << SWPAC_ISAR1_APA_SHIFT), 0));
	CHECK(!swpac_id_pauth_absent(0x100001ull | (1ull << SWPAC_ISAR1_GPA_SHIFT), 0));
	CHECK(!swpac_id_pauth_absent(0x100001ull | (1ull << SWPAC_ISAR1_GPI_SHIFT), 0));
	CHECK(!swpac_id_pauth_absent(0x100001ull, 1ull << SWPAC_ISAR2_APA3_SHIFT));
	CHECK(!swpac_id_pauth_absent(0x100001ull, 1ull << SWPAC_ISAR2_GPA3_SHIFT));
}

static void fill_keys(struct swpac_cpu *c, uint64_t seed)
{
	c->keys.ia[0] = seed ^ 0x1111111111111111ull;
	c->keys.ia[1] = seed ^ 0x2222222222222222ull;
	c->keys.ib[0] = seed ^ 0x3333333333333333ull;
	c->keys.ib[1] = seed ^ 0x4444444444444444ull;
	c->keys.da[0] = seed ^ 0x5555555555555555ull;
	c->keys.da[1] = seed ^ 0x6666666666666666ull;
	c->keys.db[0] = seed ^ 0x7777777777777777ull;
	c->keys.db[1] = seed ^ 0x8888888888888888ull;
	c->keys.ga[0] = seed ^ 0x9999999999999999ull;
	c->keys.ga[1] = seed ^ 0xaaaaaaaaaaaaaaaaull;
	c->keys.sctlr_en = SWPAC_SCTLR_EN_MASK;
}

static uint32_t enc_add(int opcode, int z, unsigned rn, unsigned rd)
{
	return 0xdac10000u | ((unsigned)z << 13) | ((unsigned)opcode << 10) | (rn << 5) | rd;
}

static int canonical(struct swpac_cpu *c, uint64_t ptr, int data)
{
	int yes = 0;

	CHECK(swpac_is_canonical(c, ptr, data, &yes) == SWPAC_OK);
	return yes;
}

static void test_sign_auth(void)
{
	struct swpac_cpu c;
	uint64_t ptr, signed_ptr, out;
	int failed = 0, nop = 0, i;
	const uint64_t kptr = 0xffff000000010000ull;
	const uint64_t uptr = 0x0000000000010000ull;
	const uint64_t k39 = 0xffffff8000001000ull;
	const uint64_t window = 0xffffffe000001000ull;
	unsigned pac_bits[] = { 63, 62, 61, 60, 59, 58, 57, 56, 54, 53, 52, 51, 50, 49, 48 };

	swpac_cpu_init(&c, SWPAC_PROFILE_EXPERIMENTAL);
	fill_keys(&c, 0xabcdu);
	CHECK(canonical(&c, kptr, 0));
	CHECK(canonical(&c, uptr, 0));
	CHECK(!canonical(&c, 0x8000000000001000ull, 0));

	CHECK(swpac_add(&c, SWPAC_KEY_IA, kptr, 0x1234, &signed_ptr) == SWPAC_OK);
	CHECK(signed_ptr != kptr);
	CHECK((signed_ptr & ((1ull << 48) - 1)) == (kptr & ((1ull << 48) - 1)));
	CHECK(((signed_ptr >> 55) & 1) == 1);
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr, 0x1234, &out, &failed, &nop) == SWPAC_OK);
	CHECK(!failed && !nop && out == kptr);

	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr, 0x1235, &out, &failed, &nop) == SWPAC_OK);
	CHECK(failed);
	CHECK((out & (1ull << 63)) && !(out & (1ull << 62)) && (out & (1ull << 61)));
	CHECK((out & ((1ull << 48) - 1)) == (kptr & ((1ull << 48) - 1)));
	CHECK(!canonical(&c, out, 0));

	CHECK(swpac_auth(&c, SWPAC_KEY_IB, signed_ptr, 0x1234, &out, &failed, &nop) == SWPAC_OK);
	CHECK(failed);
	CHECK((out & (1ull << 62)) && !(out & (1ull << 61)));

	for (i = 0; i < (int)(sizeof(pac_bits) / sizeof(pac_bits[0])); i++) {
		uint64_t tampered = signed_ptr ^ (1ull << pac_bits[i]);

		CHECK(swpac_auth(&c, SWPAC_KEY_IA, tampered, 0x1234, &out, &failed, &nop) == SWPAC_OK);
		CHECK(failed);
		CHECK(out != kptr);
	}
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr ^ 1ull, 0x1234, &out, &failed, &nop) == SWPAC_OK);
	CHECK(failed);
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr ^ (1ull << 47), 0x1234, &out, &failed, &nop) == SWPAC_OK);
	CHECK(failed);

	/* Unsigned canonical pointers are not treated as already authenticated. */
	for (i = 1; i <= 32; i++) {
		ptr = 0xffff000000000000ull | ((uint64_t)i << 12);
		CHECK(canonical(&c, ptr, 0));
		CHECK(swpac_auth(&c, SWPAC_KEY_IA, ptr, 0x1234, &out, &failed, &nop) == SWPAC_OK);
		CHECK(failed);
	}

	/* Same key bits in IA and IB produce the same PAC. Key id is not an extra mixer input. */
	c.keys.ib[0] = c.keys.ia[0];
	c.keys.ib[1] = c.keys.ia[1];
	{
		uint64_t a, b;

		CHECK(swpac_add(&c, SWPAC_KEY_IA, kptr, 7, &a) == SWPAC_OK);
		CHECK(swpac_add(&c, SWPAC_KEY_IB, kptr, 7, &b) == SWPAC_OK);
		CHECK(a == b);
		CHECK(swpac_auth(&c, SWPAC_KEY_IB, a, 7, &out, &failed, &nop) == SWPAC_OK);
		CHECK(!failed && out == kptr);
	}
	fill_keys(&c, 0xabcdu);

	/* User pointer, zero modifier, key DA with TBI off matches the instruction field width. */
	CHECK(swpac_add(&c, SWPAC_KEY_DA, uptr, 0, &signed_ptr) == SWPAC_OK);
	CHECK(swpac_auth(&c, SWPAC_KEY_DA, signed_ptr, 0, &out, &failed, &nop) == SWPAC_OK);
	CHECK(!failed && out == uptr);
	CHECK(swpac_auth(&c, SWPAC_KEY_DB, signed_ptr, 0, &out, &failed, &nop) == SWPAC_OK);
	CHECK(failed);

	/* 39-bit kernel VA (T1SZ=25) and a pointer inside the documented LINUX64 window. */
	c.t1sz = 25;
	CHECK(canonical(&c, k39, 0));
	CHECK(canonical(&c, window, 0));
	CHECK(!canonical(&c, kptr, 0));
	CHECK(swpac_add(&c, SWPAC_KEY_IA, window, 99, &signed_ptr) == SWPAC_OK);
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr, 99, &out, &failed, &nop) == SWPAC_OK);
	CHECK(!failed && out == window);
	c.t1sz = 16;

	/* TBI keeps the top byte in the register and widens the compared field differently. */
	c.tbi0 = 1;
	c.tbi1 = 1;
	ptr = 0xabff000000010000ull;
	CHECK(canonical(&c, ptr, 0));
	CHECK(swpac_add(&c, SWPAC_KEY_IA, ptr, 5, &signed_ptr) == SWPAC_OK);
	CHECK((signed_ptr >> 56) == 0xab);
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr, 5, &out, &failed, &nop) == SWPAC_OK);
	CHECK(!failed && out == ptr);
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr ^ (1ull << 53), 5, &out, &failed, &nop) == SWPAC_OK);
	CHECK(failed);
	CHECK(((out >> 53) & 3ull) == 1ull);
	CHECK((out >> 56) == 0xab);
	CHECK(!canonical(&c, out, 0));

	/* TBID1: instruction addresses lose TBI, data addresses keep it. Same key material.
	 * A tagged top byte is canonical for data and non-canonical for instructions, so
	 * InsertPAC corrupts the instruction PAC (!FEAT_PAuth2). */
	c.tbid1 = 1;
	c.keys.da[0] = c.keys.ia[0];
	c.keys.da[1] = c.keys.ia[1];
	{
		uint64_t plain = 0xffff000000010000ull;
		uint64_t ia, da, bad;

		CHECK(canonical(&c, plain, 0));
		CHECK(!canonical(&c, ptr, 0));
		CHECK(canonical(&c, ptr, 1));
		CHECK(swpac_add(&c, SWPAC_KEY_IA, plain, 5, &ia) == SWPAC_OK);
		CHECK(swpac_add(&c, SWPAC_KEY_DA, ptr, 5, &da) == SWPAC_OK);
		CHECK(ia != plain && ia != da);
		CHECK((ia & ((1ull << 48) - 1)) == (plain & ((1ull << 48) - 1)));
		CHECK(((ia >> 55) & 1) == 1);
		CHECK((da >> 56) == 0xab);
		CHECK(swpac_auth(&c, SWPAC_KEY_IA, ia, 5, &out, &failed, &nop) == SWPAC_OK);
		CHECK(!failed && out == plain);
		CHECK(swpac_auth(&c, SWPAC_KEY_DA, da, 5, &out, &failed, &nop) == SWPAC_OK);
		CHECK(!failed && out == ptr);
		CHECK(swpac_auth(&c, SWPAC_KEY_IA, da, 5, &out, &failed, &nop) == SWPAC_OK);
		CHECK(failed);
		CHECK(swpac_add(&c, SWPAC_KEY_IA, ptr, 5, &bad) == SWPAC_OK);
		CHECK(swpac_auth(&c, SWPAC_KEY_IA, bad, 5, &out, &failed, &nop) == SWPAC_OK);
		CHECK(failed);
	}

	/* !FEAT_PAuth2 corrupts the PAC of a non-canonical input, so auth cannot succeed.
	 * selbit is bit 63 when TBI is off, and that bit is written into bit 55. */
	c.tbi0 = c.tbi1 = c.tbid0 = c.tbid1 = 0;
	c.t0sz = 16;
	c.t1sz = 25;
	ptr = 0x8000000000001000ull;
	CHECK(swpac_add(&c, SWPAC_KEY_IA, ptr, 1, &signed_ptr) == SWPAC_OK);
	CHECK(((signed_ptr >> 55) & 1) == 1);
	CHECK((signed_ptr & ((1ull << 39) - 1)) == 0x1000);
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr, 1, &out, &failed, &nop) == SWPAC_OK);
	CHECK(failed);

	c.t0sz = 15;
	CHECK(swpac_add(&c, SWPAC_KEY_IA, kptr, 1, &out) == SWPAC_BAD_CONFIG);
	c.t0sz = 40;
	CHECK(swpac_add(&c, SWPAC_KEY_IA, kptr, 1, &out) == SWPAC_BAD_CONFIG);
	c.t0sz = 16;
	c.t1sz = 39;
	/* 25-bit upper VA: bits [63:25] all ones. 0xffffff8000001000 is canonical only for T1SZ<=25. */
	ptr = 0xfffffffffe001000ull;
	CHECK(canonical(&c, ptr, 0));
	CHECK(swpac_add(&c, SWPAC_KEY_IA, ptr, 1, &signed_ptr) == SWPAC_OK);
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr, 1, &out, &failed, &nop) == SWPAC_OK);
	CHECK(!failed && out == ptr);
}

static void test_enable_and_strip(void)
{
	struct swpac_cpu c;
	uint64_t signed_ptr, stripped, out;
	int failed = 0, nop = 0;
	const uint64_t kptr = 0xffff000000010000ull;

	swpac_cpu_init(&c, SWPAC_PROFILE_EXPERIMENTAL);
	fill_keys(&c, 3);
	CHECK(swpac_add(&c, SWPAC_KEY_IA, kptr, 8, &signed_ptr) == SWPAC_OK);
	c.keys.sctlr_en &= ~SWPAC_SCTLR_ENIA;
	CHECK(swpac_add(&c, SWPAC_KEY_IA, kptr, 8, &out) == SWPAC_OK);
	CHECK(out == kptr);
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr, 8, &out, &failed, &nop) == SWPAC_OK);
	CHECK(nop && !failed && out == signed_ptr);
	/* EnIB clear does not disable IA. */
	c.keys.sctlr_en = SWPAC_SCTLR_EN_MASK & ~SWPAC_SCTLR_ENIB;
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr, 8, &out, &failed, &nop) == SWPAC_OK);
	CHECK(!failed && !nop && out == kptr);

	CHECK(swpac_strip(&c, 0, signed_ptr, &stripped) == SWPAC_OK);
	CHECK(stripped == kptr);
	CHECK(swpac_strip(&c, 0, signed_ptr ^ (1ull << 50), &out) == SWPAC_OK);
	CHECK(out == kptr);
	CHECK(swpac_auth(&c, SWPAC_KEY_IA, signed_ptr ^ (1ull << 50), 8, &out, &failed, &nop) == SWPAC_OK);
	CHECK(failed);
}

static void test_keys_and_pacga(void)
{
	struct swpac_cpu a, b;
	struct swpac_keys saved, other;
	uint64_t s1, s2, g1, g2, out;
	int failed = 0, nop = 0;
	const uint64_t kptr = 0xffff000000010000ull;

	swpac_cpu_init(&a, SWPAC_PROFILE_EXPERIMENTAL);
	swpac_cpu_init(&b, SWPAC_PROFILE_EXPERIMENTAL);
	fill_keys(&a, 1);
	fill_keys(&b, 2);
	CHECK(swpac_add(&a, SWPAC_KEY_IA, kptr, 4, &s1) == SWPAC_OK);
	CHECK(swpac_add(&b, SWPAC_KEY_IA, kptr, 4, &s2) == SWPAC_OK);
	CHECK(s1 != s2);
	other = b.keys;
	swpac_keys_swap(&a, &other, &saved);
	CHECK(swpac_auth(&a, SWPAC_KEY_IA, s1, 4, &out, &failed, &nop) == SWPAC_OK);
	CHECK(failed);
	swpac_keys_swap(&a, &saved, NULL);
	CHECK(swpac_auth(&a, SWPAC_KEY_IA, s1, 4, &out, &failed, &nop) == SWPAC_OK);
	CHECK(!failed && out == kptr);
	/* The other context is unchanged by the swap. */
	CHECK(swpac_auth(&b, SWPAC_KEY_IA, s2, 4, &out, &failed, &nop) == SWPAC_OK);
	CHECK(!failed && out == kptr);

	CHECK(swpac_pacga(&a, kptr, 4, &g1) == SWPAC_OK);
	CHECK((g1 & 0xffffffffull) == 0);
	CHECK(g1 != 0);
	a.keys.sctlr_en = 0;
	CHECK(swpac_pacga(&a, kptr, 4, &g2) == SWPAC_OK);
	CHECK(g1 == g2);
	a.keys.ga[0] ^= 1;
	CHECK(swpac_pacga(&a, kptr, 4, &g2) == SWPAC_OK);
	CHECK(g1 != g2);
	CHECK(swpac_pacga(&a, kptr, 5, &out) == SWPAC_OK);
	CHECK(out != g2);
}

static uint32_t find_insn(const char *text)
{
	size_t i;

	for (i = 0; i < sizeof(swpac_fixtures) / sizeof(swpac_fixtures[0]); i++)
		if (!strcmp(swpac_fixtures[i].text, text))
			return swpac_fixtures[i].insn;
	return 0;
}

static void test_step_absent(void)
{
	struct swpac_cpu c;
	uint32_t pacia = find_insn("pacia x0, x1");
	uint32_t pacibsp = find_insn("pacibsp");
	uint32_t retab = find_insn("retab");
	uint32_t blraaz = find_insn("blraaz x16");
	uint32_t mrs = find_insn("mrs x0, APIAKeyLo_EL1");
	uint64_t x0, x30;

	CHECK(pacia && pacibsp && retab && blraaz && mrs);
	swpac_cpu_init(&c, SWPAC_PROFILE_ABSENT);
	c.x[0] = 0x1111;
	c.x[1] = 0x2222;
	c.x[30] = 0xffff000000010000ull;
	c.pc = 0x1000;
	x0 = c.x[0];
	x30 = c.x[30];
	CHECK(swpac_step(&c, pacia) == SWPAC_UNDEF);
	CHECK(c.x[0] == x0 && c.pc == 0x1000);
	CHECK(swpac_step(&c, retab) == SWPAC_UNDEF);
	CHECK(c.pc == 0x1000 && c.x[30] == x30);
	CHECK(swpac_step(&c, blraaz) == SWPAC_UNDEF);
	CHECK(swpac_step(&c, mrs) == SWPAC_UNDEF);
	CHECK(c.x[0] == x0);
	CHECK(swpac_step(&c, pacibsp) == SWPAC_NOP);
	CHECK(c.pc == 0x1004 && c.x[30] == x30 && !c.last.auth_failed);
	/* The arm64e pacibsp/retab pair cannot be trap-emulated: the sign is a NOP. */
	CHECK(swpac_step(&c, retab) == SWPAC_UNDEF);
	CHECK(c.x[30] == x30 && c.pc == 0x1004);
	CHECK(swpac_step(&c, find_insn("nop")) == SWPAC_NOT_PAC);
	CHECK(c.pc == 0x1004);
	CHECK(swpac_step(&c, find_insn("ldraa x0, [x1, #0]!")) == SWPAC_UNDEF);
	CHECK(c.x[0] == x0);
}

static void test_step_experimental(void)
{
	struct swpac_cpu c;
	uint64_t target = 0xffff000000020000ull;
	uint64_t signed_lr, signed_tgt, x16_before, link;
	uint32_t pacibsp = find_insn("pacibsp");
	uint32_t retab = find_insn("retab");
	uint32_t blraaz = find_insn("blraaz x16");
	uint32_t pacia = find_insn("pacia x0, x1");
	uint32_t autia;
	int failed = 0, nop = 0;

	swpac_cpu_init(&c, SWPAC_PROFILE_EXPERIMENTAL);
	fill_keys(&c, 9);
	c.sp = 0x4000;
	c.pc = 0x8000;
	c.x[30] = target;
	CHECK(swpac_step(&c, pacibsp) == SWPAC_OK);
	signed_lr = c.x[30];
	CHECK(signed_lr != target);
	CHECK(c.pc == 0x8004);
	CHECK(swpac_step(&c, retab) == SWPAC_OK);
	CHECK(!c.last.auth_failed && !c.last.fetch_noncanonical);
	CHECK(c.pc == target);
	CHECK(c.x[30] == signed_lr);

	c.sp ^= 0x10;
	c.x[30] = signed_lr;
	c.pc = 0x8004;
	CHECK(swpac_step(&c, retab) == SWPAC_OK);
	CHECK(c.last.auth_failed && c.last.fetch_noncanonical);
	CHECK(c.pc != target && c.x[30] == signed_lr);
	CHECK(!canonical(&c, c.pc, 0));

	c.sp ^= 0x10;
	CHECK(swpac_add(&c, SWPAC_KEY_IA, target, 0, &signed_tgt) == SWPAC_OK);
	c.x[16] = signed_tgt;
	x16_before = c.x[16];
	c.pc = 0x9000;
	CHECK(swpac_step(&c, blraaz) == SWPAC_OK);
	CHECK(!c.last.auth_failed && c.pc == target);
	CHECK(c.x[30] == 0x9004);
	CHECK(c.x[16] == x16_before);

	c.x[16] = signed_tgt ^ (1ull << 48);
	c.pc = 0x9000;
	link = 0x9004;
	CHECK(swpac_step(&c, blraaz) == SWPAC_OK);
	CHECK(c.last.auth_failed && c.last.fetch_noncanonical);
	CHECK(c.x[30] == link);
	CHECK(c.x[16] == (signed_tgt ^ (1ull << 48)));
	CHECK(c.pc != target);

	/* EnIA clear: BLRAAZ branches to the raw bits and does not report an auth failure. */
	c.keys.sctlr_en &= ~SWPAC_SCTLR_ENIA;
	c.x[16] = signed_tgt;
	c.pc = 0x9000;
	CHECK(swpac_step(&c, blraaz) == SWPAC_OK);
	CHECK(c.last.enable_nop && !c.last.auth_failed && c.last.fetch_noncanonical);
	CHECK(c.pc == signed_tgt && c.x[30] == 0x9004);
	c.keys.sctlr_en |= SWPAC_SCTLR_ENIA;

	c.x[0] = target;
	c.x[1] = 0x55;
	c.pc = 0x100;
	CHECK(swpac_step(&c, pacia) == SWPAC_OK);
	CHECK(c.x[0] != target && c.x[1] == 0x55 && c.pc == 0x104);
	autia = enc_add(4, 0, 1, 0);
	CHECK(swpac_step(&c, autia) == SWPAC_OK);
	CHECK(!c.last.auth_failed && c.x[0] == target);

	/* BRAAZ does not write X30. */
	{
		uint32_t braaz = find_insn("braaz x22");
		uint64_t old30;

		CHECK(swpac_add(&c, SWPAC_KEY_IA, target, 0, &signed_tgt) == SWPAC_OK);
		c.x[22] = signed_tgt;
		old30 = c.x[30];
		c.pc = 0x3000;
		CHECK(swpac_step(&c, braaz) == SWPAC_OK);
		CHECK(c.pc == target && c.x[30] == old30 && c.x[22] == signed_tgt);
	}

	/* Unallocated encodings are UNDEFINED even in the experimental profile. */
	CHECK(swpac_step(&c, enc_add(0, 1, 1, 0)) == SWPAC_UNDEF);
	CHECK(c.pc == target);
	CHECK(swpac_step(&c, 0xd63f0a00u) == SWPAC_UNDEF);
	CHECK(swpac_step(&c, find_insn("ldraa x0, [x1, #0]!")) == SWPAC_UNSUPPORTED);
	CHECK(swpac_step(&c, find_insn("eretaa")) == SWPAC_UNSUPPORTED);
	CHECK(c.pc == target);
	CHECK(swpac_step(&c, find_insn("ret")) == SWPAC_NOT_PAC);

	/* MRS/MSR of the key file, then a sign that observes the new IA key. */
	{
		uint32_t msr = find_insn("msr APIAKeyLo_EL1, x0");
		uint32_t mrs = find_insn("mrs x0, APIAKeyLo_EL1");
		uint64_t before, after;

		c.x[0] = 0xdeadbeefcafebabeull;
		c.pc = 0x10;
		CHECK(swpac_step(&c, msr) == SWPAC_OK);
		CHECK(c.keys.ia[0] == 0xdeadbeefcafebabeull && c.pc == 0x14);
		c.x[0] = 0;
		CHECK(swpac_step(&c, mrs) == SWPAC_OK);
		CHECK(c.x[0] == 0xdeadbeefcafebabeull);
		CHECK(swpac_add(&c, SWPAC_KEY_IA, target, 0, &before) == SWPAC_OK);
		c.keys.ia[0] ^= 0xff;
		CHECK(swpac_add(&c, SWPAC_KEY_IA, target, 0, &after) == SWPAC_OK);
		CHECK(before != after);
		CHECK(swpac_auth(&c, SWPAC_KEY_IA, before, 0, &signed_tgt, &failed, &nop) == SWPAC_OK);
		CHECK(failed);
	}

	/* XPACI strips a tampered code pointer without authenticating it. */
	{
		uint32_t xpaci = find_insn("xpaci x28");

		CHECK(swpac_add(&c, SWPAC_KEY_IA, target, 3, &signed_tgt) == SWPAC_OK);
		c.x[28] = signed_tgt ^ (1ull << 49);
		c.pc = 0x40;
		CHECK(swpac_step(&c, xpaci) == SWPAC_OK);
		CHECK(c.x[28] == target && !c.last.auth_failed);
	}
}

static void test_bad_config_step_preserves(void)
{
	struct swpac_cpu c;
	uint32_t pacia = find_insn("pacia x0, x1");

	swpac_cpu_init(&c, SWPAC_PROFILE_EXPERIMENTAL);
	fill_keys(&c, 1);
	c.t1sz = 15;
	c.x[0] = 0xffff000000010000ull;
	c.x[1] = 1;
	c.pc = 0x20;
	CHECK(swpac_step(&c, pacia) == SWPAC_BAD_CONFIG);
	CHECK(c.x[0] == 0xffff000000010000ull && c.pc == 0x20);
}

int main(void)
{
	printf("swpac model %s\n", SWPAC_MODEL_ID);
	printf("host model tests only; not a kernel emulator; not RB5 execution; not macOS boot\n");
	test_id();
	test_fixtures();
	test_sign_auth();
	test_enable_and_strip();
	test_keys_and_pacga();
	test_step_absent();
	test_step_experimental();
	test_bad_config_step_preserves();
	printf("swpac tests: %d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
