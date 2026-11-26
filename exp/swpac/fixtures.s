// SPDX-License-Identifier: GPL-2.0-only
// Encodings for the host decoder test. Assembled with:
//   clang --target=aarch64-linux-gnu -c fixtures.s
// The .word values in fixtures.inc come from that object file.
.arch armv8.3-a
.globl _start
_start:
pacia x0, x1
paciza x2
pacib x3, x4
pacda x5, x6
pacdb x7, sp
autia x8, x9
autiza x10
autda x11, x12
autdb x13, x14
autib x3, x4
autizb x5
pacizb x0
pacdza x1
pacdzb x2
pacga x15, x16, x17
pacga x0, x1, sp
blraaz x16
blraa x17, x18
blrabz x19
blrab x20, x21
braaz x22
braa x23, sp
brabz x25
brab x26, x27
retaa
retab
paciasp
paciaz
pacibsp
pacibz
autiasp
autiaz
autibsp
autibz
pacia1716
pacib1716
autia1716
autib1716
xpaci x28
xpacd x29
xpaclri
ldraa x0, [x1, #0]!
ldrab x2, [x3, #32]!
eretaa
eretab
mrs x0, APIAKeyLo_EL1
mrs x1, APIAKeyHi_EL1
mrs x2, APIBKeyLo_EL1
mrs x3, APIBKeyHi_EL1
mrs x4, APDAKeyLo_EL1
mrs x5, APDAKeyHi_EL1
mrs x6, APDBKeyLo_EL1
mrs x7, APDBKeyHi_EL1
mrs x8, APGAKeyLo_EL1
mrs x9, APGAKeyHi_EL1
msr APIAKeyLo_EL1, x0
msr APIBKeyHi_EL1, x3
msr APGAKeyLo_EL1, x8
nop
ret
bti c
ldr x0, [x1]
mrs x10, SCTLR_EL1
