/* SPDX-License-Identifier: GPL-2.0-only */
/* Userspace check of the FEAT_PAuth ID decode. No kernel, no PAC registers. */
#include <stdio.h>
#include <stdlib.h>
#include "../../fki-ko/fki_pauth.h"

static int fail;

static void expect(const char *what, int cond)
{
	if (cond)
		return;
	fprintf(stderr, "FAIL %s\n", what);
	fail = 1;
}

static void show(const char *name, uint64_t isar1, uint64_t isar2)
{
	struct fki_pauth_id id;

	fki_pauth_decode(isar1, isar2, &id);
	printf("%s isar1=%#llx isar2=%#llx apa=%u api=%u gpa=%u gpi=%u apa3=%u gpa3=%u present=%u pack=%#llx\n",
	       name, (unsigned long long)isar1, (unsigned long long)isar2,
	       id.apa, id.api, id.gpa, id.gpi, id.apa3, id.gpa3, id.present,
	       (unsigned long long)fki_pauth_pack(&id));
}

int main(void)
{
	struct fki_pauth_id id;

	/* RB5 Kryo 585, both clusters: DPB=1 (bit 0) and LRCPC=1 (bit 20). Not APA. */
	fki_pauth_decode(0x100001, 0, &id);
	expect("rb5 present", id.present == 0);
	expect("rb5 apa", id.apa == 0);
	expect("rb5 api", id.api == 0);
	expect("rb5 gpa", id.gpa == 0);
	expect("rb5 gpi", id.gpi == 0);
	expect("rb5 apa3", id.apa3 == 0);
	expect("rb5 gpa3", id.gpa3 == 0);
	expect("rb5 pack", fki_pauth_pack(&id) == 0);

	fki_pauth_decode(0x100, 0, &id);	/* API=1, implementation-defined address auth */
	expect("api present", id.present == 1 && id.api == 1 && id.apa == 0);

	fki_pauth_decode(0x10, 0, &id);		/* APA=1, QARMA5 address auth */
	expect("apa present", id.present == 1 && id.apa == 1);

	fki_pauth_decode(0x01000000, 0, &id);	/* GPA=1 */
	expect("gpa present", id.present == 1 && id.gpa == 1 && id.api == 0);

	fki_pauth_decode(0x10000000, 0, &id);	/* GPI=1 */
	expect("gpi present", id.present == 1 && id.gpi == 1);

	fki_pauth_decode(0, 0x1000, &id);	/* APA3=1, QARMA3 address auth */
	expect("apa3 present", id.present == 1 && id.apa3 == 1 && id.apa == 0 && id.api == 0);

	fki_pauth_decode(0, 0x100, &id);	/* GPA3=1, QARMA3 generic auth */
	expect("gpa3 present", id.present == 1 && id.gpa3 == 1);

	/* LRCPC at [23:20] must not be read as APA ([7:4]). */
	fki_pauth_decode(0x100000, 0, &id);
	expect("lrcpc alone", id.present == 0 && id.apa == 0);

	show("rb5", 0x100001, 0);
	show("api", 0x100, 0);
	show("qarma3", 0, 0x1000);
	return fail ? EXIT_FAILURE : EXIT_SUCCESS;
}
