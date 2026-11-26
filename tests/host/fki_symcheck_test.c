/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../fki-ko/fki_symcheck.h"

static int fail;

static void expect(const char *what, int cond)
{
	if (cond)
		return;
	fprintf(stderr, "FAIL %s\n", what);
	fail = 1;
}

int main(void)
{
	unsigned long run[FKI_SYM_N];
	unsigned long slide = 1;
	unsigned i;
	const unsigned long delta = 0x12345000UL;

	expect("identity", fki_sym_one_slide(fki_rb5_link, fki_rb5_link, FKI_SYM_N, &slide) == 0 && slide == 0);
	for (i = 0; i < FKI_SYM_N; i++)
		run[i] = fki_rb5_link[i] + delta;
	expect("one slide", fki_sym_one_slide(fki_rb5_link, run, FKI_SYM_N, &slide) == 0 && slide == delta);
	run[3] += 8;
	expect("broken slide", fki_sym_one_slide(fki_rb5_link, run, FKI_SYM_N, &slide) != 0);
	run[3] -= 8;
	run[7] = 0;
	expect("zero rejected", fki_sym_one_slide(fki_rb5_link, run, FKI_SYM_N, &slide) != 0);
	expect("set_memory_x before nx in the map", fki_rb5_link[0] > fki_rb5_link[6]);
	expect("_end above _stext", fki_rb5_link[8] > fki_rb5_link[7]);
	printf("symcheck: identity slide 0, shifted slide %#lx, mismatch and zero rejected\n", delta);
	return fail ? EXIT_FAILURE : EXIT_SUCCESS;
}
