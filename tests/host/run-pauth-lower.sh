#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Encoding checks on the host, then the same program under qemu-aarch64 -cpu cortex-a57.
# That CPU has no FEAT_PAuth. CLOUD EMULATION, not the RB5 and not macOS.
set -euo pipefail
cd "$(dirname "$0")/../.."
gcc -std=c11 -Wall -Wextra -Werror -O2 -o /tmp/pauth_lower_test tests/host/pauth_lower_test.c
echo "=== host encoding test ==="
/tmp/pauth_lower_test
echo "=== CLOUD EMULATION qemu-aarch64 -cpu cortex-a57 ==="
aarch64-linux-gnu-gcc -std=c11 -static -Wall -Wextra -Werror -O2 -o /tmp/pauth_lower_test.aarch64 tests/host/pauth_lower_test.c
qemu-aarch64 -cpu cortex-a57 /tmp/pauth_lower_test.aarch64
echo "=== sha256 ==="
sha256sum /tmp/pauth_lower_test /tmp/pauth_lower_test.aarch64 tests/host/pauth_lower_test.c xnu-ko/pauth_lower.h
