# SPDX-License-Identifier: GPL-2.0-only
# Host build of the experimental PAC model. This is not fki.ko or xnu.ko.
CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2
LDFLAGS ?=

.PHONY: test test-asan fixtures fixtures-check clean

# fixtures.inc is committed. `make test` does not reassemble it.
# `make fixtures` refreshes it with clang's AArch64 assembler; `make fixtures-check` fails if they differ.

test: swpac_test
	./swpac_test

test-ubsan: swpac.c swpac_test.c fixtures.inc swpac.h
	gcc -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=undefined -fno-omit-frame-pointer \
		-o swpac_test_ubsan swpac.c swpac_test.c $(LDFLAGS)
	./swpac_test_ubsan

swpac_test: swpac.c swpac_test.c fixtures.inc swpac.h
	$(CC) $(CFLAGS) -o $@ swpac.c swpac_test.c $(LDFLAGS)

fixtures: fixtures.s gen_fixtures.py
	clang --target=aarch64-linux-gnu -c fixtures.s -o fixtures.o
	python3 gen_fixtures.py fixtures.s fixtures.o > fixtures.inc

fixtures-check: fixtures.s gen_fixtures.py fixtures.inc
	clang --target=aarch64-linux-gnu -c fixtures.s -o fixtures.o
	python3 gen_fixtures.py fixtures.s fixtures.o > fixtures.inc.check
	cmp fixtures.inc fixtures.inc.check

clean:
	rm -f swpac_test swpac_test_asan swpac_test_ubsan fixtures.o fixtures.inc.check
