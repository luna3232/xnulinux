/* SPDX-License-Identifier: GPL-2.0-only */
/* Rewrite checks, plus on AArch64 a real call of the rewritten code. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../xnu-ko/pauth_lower.h"

#ifdef __aarch64__
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

static int fail;

static void expect(const char *what, int cond)
{
	if (cond)
		return;
	fprintf(stderr, "FAIL %s\n", what);
	fail = 1;
}

static void expect_lower(const char *what, uint32_t in, uint32_t want, int kind)
{
	uint32_t out = 0;
	int got = pauth_lower_insn(in, &out);

	if (got != kind || out != want) {
		fprintf(stderr, "FAIL %s in=%#x out=%#x kind=%d want=%#x kind=%d\n",
			what, in, out, got, want, kind);
		fail = 1;
	}
}

/* Framed call from aarch64-linux-gnu-ld -Ttext=0. stp saves the caller's x30. */
static uint32_t sample[] = {
	0xd503237fu, /* pacibsp */
	0xa9bf7bfdu, /* stp x29, x30, [sp, #-16]! */
	0x910003fdu, /* mov x29, sp */
	0x10000080u, /* adr x0, leaf */
	0xd63f081fu, /* blraaz x0 */
	0xa8c17bfdu, /* ldp x29, x30, [sp], #16 */
	0xd65f0fffu, /* retab */
	0xd503237fu, /* pacibsp */
	0xd2800540u, /* mov x0, #42 */
	0xd65f0fffu, /* retab */
};
static uint32_t mrs_fn[] = {
	0xd5382100u, /* mrs x0, apiakeylo_el1 */
	0xd65f0fffu, /* retab */
};
static uint32_t eret_fn[] = {
	0xd69f0bffu, /* eretaa */
	0xd65f03c0u, /* ret */
};
/* pacibsp; mov x0, #7; ret. The hint must not trap. */
static uint32_t hint_ok[] = { 0xd503237fu, 0xd28000e0u, 0xd65f03c0u };
/* pacibsp; mov x0, #7; retab. The hint does not sign; retab traps. */
static uint32_t hint_trap[] = { 0xd503237fu, 0xd28000e0u, 0xd65f0fffu };
/* adr + top-byte tag + paciza x16 + blraaz x16, leaf returns 42. */
static uint32_t tagged[] = {
	0xa9bf7bfdu, 0x100000d0u, 0xb2481e10u, 0xdac123f0u, 0xd63f0a1fu,
	0xa8c17bfdu, 0xd65f03c0u, 0xd2800540u, 0xd65f03c0u
};
/* same tag, no paciza before blraaz: one slot cannot strip and branch. */
static uint32_t bare_tag[] = {
	0xa9bf7bfdu, 0x100000b0u, 0xb2481e10u, 0xd63f0a1fu,
	0xa8c17bfdu, 0xd65f03c0u, 0xd2800540u, 0xd65f03c0u
};

#ifdef __aarch64__
static sigjmp_buf ill_jmp;

static void on_ill(int sig)
{
	siglongjmp(ill_jmp, sig == SIGALRM ? 2 : 1);
}

static int call_buf(uint32_t *code, size_t nwords, int lower, unsigned long *ret)
{
	size_t bytes = nwords * 4;
	void *page;
	unsigned long (*fn)(void);

	page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	memcpy(page, code, bytes);
	if (lower)
		pauth_lower_span(page, nwords, NULL);
	if (mprotect(page, 4096, PROT_READ | PROT_EXEC)) {
		perror("mprotect");
		munmap(page, 4096);
		return -1;
	}
	__builtin___clear_cache(page, (char *)page + bytes);
	fn = page;
	if (sigsetjmp(ill_jmp, 1) != 0) {
		munmap(page, 4096);
		return 1;	/* SIGILL */
	}
	*ret = fn();
	munmap(page, 4096);
	return 0;
}
#endif

int main(void)
{
	struct pauth_lower_stats st;
	uint32_t out = 0;
	uint32_t buf[10];

	expect_lower("retab", 0xd65f0fffu, 0xd65f03c0u, PAUTH_LOWER_RET);
	expect_lower("retaa", 0xd65f0bffu, 0xd65f03c0u, PAUTH_LOWER_RET);
	expect_lower("blraaz x0", 0xd63f081fu, 0xd63f0000u, PAUTH_LOWER_BLR);
	expect_lower("blraaz x2", 0xd63f085fu, 0xd63f0040u, PAUTH_LOWER_BLR);
	expect_lower("blraa x2, x3", 0xd73f0843u, 0xd63f0040u, PAUTH_LOWER_BLR);
	expect_lower("braaz x2", 0xd61f085fu, 0xd61f0040u, PAUTH_LOWER_BR);
	expect_lower("braa x2, x3", 0xd71f0843u, 0xd61f0040u, PAUTH_LOWER_BR);
	expect_lower("pacia x2, x3", 0xdac10062u, 0xd503201fu, PAUTH_LOWER_PAC_NOP);
	expect_lower("pacib x2, sp", 0xdac107e2u, 0xd503201fu, PAUTH_LOWER_PAC_NOP);
	expect_lower("autia x2, x3", 0xdac11062u, 0x9340dc42u, PAUTH_LOWER_CANON);
	expect_lower("xpaci x2", 0xdac143e2u, 0x9340dc42u, PAUTH_LOWER_CANON);
	expect_lower("autiasp", 0xd50323bfu, 0x9340dfdeu, PAUTH_LOWER_CANON);
	expect_lower("mrs x0 apiakeylo", 0xd5382100u, 0xaa1f03e0u, PAUTH_LOWER_MRS);
	expect_lower("mrs x2 apiakeylo", 0xd5382102u, 0xaa1f03e2u, PAUTH_LOWER_MRS);
	expect_lower("msr apiakeylo x2", 0xd5182102u, 0xd503201fu, PAUTH_LOWER_MSR);
	expect_lower("pacibsp to nop", 0xd503237fu, 0xd503201fu, PAUTH_LOWER_HINT);
	expect_lower("eretaa kept", 0xd69f0bffu, 0xd69f0bffu, PAUTH_LOWER_REFUSED);
	expect_lower("eretab kept", 0xd69f0fffu, 0xd69f0fffu, PAUTH_LOWER_REFUSED);
	expect_lower("add kept", 0x91000400u, 0x91000400u, PAUTH_LOWER_UNCHANGED);
	expect_lower("adr kept", 0x10000080u, 0x10000080u, PAUTH_LOWER_UNCHANGED);
	expect("ret not rewritten", pauth_lower_insn(0xd65f03c0u, &out) == PAUTH_LOWER_UNCHANGED && out == 0xd65f03c0u);

	memcpy(buf, sample, sizeof(sample));
	memset(&st, 0, sizeof(st));
	pauth_lower_span(buf, 10, &st);
	expect("span blr", buf[4] == 0xd63f0000u);
	expect("span ret", buf[6] == 0xd65f03c0u && buf[9] == 0xd65f03c0u);
	expect("span mov", buf[8] == 0xd2800540u);
	expect("span adr", buf[3] == 0x10000080u);
	expect("span stp", buf[1] == 0xa9bf7bfdu && buf[5] == 0xa8c17bfdu);
	expect("span hint", buf[0] == 0xd503201fu && st.hint == 2);
	expect("span counts", st.blr == 1 && st.ret == 2 && st.unchanged == 5 && st.branch_raw == 1);
	printf("span: hint=%u blr=%u ret=%u unchanged=%u branch_raw=%u\n",
	       st.hint, st.blr, st.ret, st.unchanged, st.branch_raw);

	{
		uint32_t pair[2] = { 0xd503237fu, 0xd65f0fffu };
		memset(&st, 0, sizeof(st));
		pauth_lower_span(pair, 2, &st);
		expect("pacibsp before retab is sbfx x30", pair[0] == 0x9340dfdeu && pair[1] == 0xd65f03c0u && st.canon == 1);
	}
	{
		uint32_t tagged[2] = { 0xdac123f0u, 0xd63f0a1fu }; /* paciza x16; blraaz x16 */
		memset(&st, 0, sizeof(st));
		pauth_lower_span(tagged, 2, &st);
		expect("paciza x16 before blraaz is sbfx", tagged[0] == 0x9340de10u && tagged[1] == 0xd63f0200u && st.canon == 1 && st.branch_raw == 0);
	}
	{
		uint32_t bare[1] = { 0xd63f0a1fu };
		memset(&st, 0, sizeof(st));
		pauth_lower_span(bare, 1, &st);
		expect("bare blraaz stays raw blr", bare[0] == 0xd63f0200u && st.branch_raw == 1 && st.canon == 0);
	}
	printf("lower: retab->RET blraaz->BLR pacia->NOP autia->SBFX mrs->MOV XZR eretaa kept\n");

#ifdef __aarch64__
	{
		struct sigaction sa;
		unsigned long ret = 0;
		int rc;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_ill;
		sigaction(SIGILL, &sa, NULL);
		sigaction(SIGSEGV, &sa, NULL);
		sigaction(SIGALRM, &sa, NULL);
		setvbuf(stdout, NULL, _IOLBF, 0);
		alarm(3);
		rc = call_buf(sample, 10, 0, &ret);
		alarm(0);
		expect("unlowered entry SIGILL", rc == 1);
		printf("CLOUD EMULATION: unlowered entry rc=%d (1 means SIGILL)\n", rc);
		alarm(3);
		rc = call_buf(sample, 10, 1, &ret);
		alarm(0);
		expect("lowered entry returns 42", rc == 0 && ret == 42);
		printf("CLOUD EMULATION: lowered entry rc=%d x0=%lu\n", rc, ret);
		alarm(3);
		rc = call_buf(mrs_fn, 2, 1, &ret);
		alarm(0);
		expect("lowered mrs returns 0", rc == 0 && ret == 0);
		printf("CLOUD EMULATION: lowered mrs apiakeylo rc=%d x0=%lu\n", rc, ret);
		alarm(3);
		rc = call_buf(mrs_fn, 2, 0, &ret);
		alarm(0);
		expect("unlowered mrs SIGILL", rc == 1);
		printf("CLOUD EMULATION: unlowered mrs rc=%d (1 means SIGILL)\n", rc);
		alarm(3);
		rc = call_buf(hint_ok, 3, 0, &ret);
		alarm(0);
		expect("raw pacibsp then ret returns 7", rc == 0 && ret == 7);
		printf("CLOUD EMULATION: raw pacibsp+ret rc=%d x0=%lu\n", rc, ret);
		alarm(3);
		rc = call_buf(hint_trap, 3, 0, &ret);
		alarm(0);
		printf("CLOUD EMULATION: raw pacibsp+retab rc=%d x0=%lu\n", rc, ret);
		printf("CLOUD EMULATION: this qemu does not trap RETAB when ISAR1 has no PAC; the architecture leaves RETAB UNDEFINED. The rewrite still replaces it with RET.\n");
		alarm(3);
		rc = call_buf(tagged, 9, 1, &ret);
		alarm(0);
		expect("tagged pointer canonicalized to 42", rc == 0 && ret == 42);
		printf("CLOUD EMULATION: paciza+blraaz lowered rc=%d x0=%lu\n", rc, ret);
		alarm(3);
		rc = call_buf(bare_tag, 8, 1, &ret);
		alarm(0);
		printf("CLOUD EMULATION: bare tagged blraaz lowered rc=%d x0=%lu\n", rc, ret);
		printf("CLOUD EMULATION: EL0 qemu-user ignores a top-byte tag (TBI), so a raw BLR still reaches the leaf. SBFX matters where bit 55's extension is part of the address.\n");
		(void)eret_fn;
	}
#else
	printf("host is not aarch64: encoding checks only, no executed call\n");
	(void)mrs_fn;
	(void)eret_fn;
	(void)hint_ok;
	(void)hint_trap;
	(void)tagged;
	(void)bare_tag;
#endif
	return fail ? EXIT_FAILURE : EXIT_SUCCESS;
}
