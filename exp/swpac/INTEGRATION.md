# Experimental software PAC model

This directory is a host-side model of a **subset** of AArch64 pointer authentication. It is the first increment that can be tested without an RB5, without kernel headers, and without a macOS image.

It is **not** a kernel emulator, **not** wired into `fki.ko` or `xnu.ko`, and **not** evidence that XNU or macOS runs. Production world-switch behaviour is unchanged: this branch does not modify `fki-ko/`, `xnu-ko/`, or `linux/drivers/fki/`.

`swpac_computepac()` is a non-cryptographic mixer. It is not QARMA3, not QARMA5, and not an Apple implementation-defined PAC. A pointer signed here will not pass hardware authentication, and a pointer signed by hardware or by an arm64e binary will not pass this model.

## Where the repo stands today

Verified by reading this tree at `e494f257`:

| Site | What it does |
|---|---|
| `fki-ko/fki_mod.c` `keys_read` / `keys_write` | MRS/MSR of `APIAKey`, `APIBKey`, `APDAKey`, `APDBKey`, `APGAKey` (lo and hi), then the four `SCTLR_EL1` enable bits. `isb` after the write. |
| `fki-ko/fki.h` `struct fki_pac_keys` | Five 128-bit keys, lo then hi, then `sctlr_en`. 88 bytes. |
| `xnu-ko/world.S` | `fki_enter` loads XNU keys at offset 328 and saves Linux keys at 240. `fki_pac_swap` swaps them on the upcall and on the fault abort. `fki_leave` restores Linux keys. |
| `xnu-ko/xnu_main.c` | Fills `xnu_keys` from `fki_random` and sets `sctlr_en = ~0`. `keys_write` masks that to EnIA, EnIB, EnDA, EnDB. |
| `xnu-ko/macho.c` `sign()` | Integer `pacia` / `pacib` / `pacda` / `pacdb` (not the HINT forms) while XNU keys are live. Used for threaded rebase. |
| `fki-ko/fki_mod.c` `fki_die_pre` | Best-effort kprobe on `die()`. This is the existing offer path for a foreign-kernel undefined instruction. It is not a PAC emulator. |

`linux/drivers/fki/` is the legacy in-tree copy. The module that is built is `fki-ko/`.

The other PAC-removal work is independent. This branch does not take it over and does not add a shared removal interface.

## What “no hardware PAC” means

Handed-over ID register values, **not** re-read from the board: `ID_AA64ISAR1_EL1 = 0x100001`, `ID_AA64ISAR2_EL1 = 0`.

DDI 0601 field positions used by `swpac_id_pauth_absent()`:

| Field | Register | Bits |
|---|---|---|
| APA | ISAR1 | 7:4 |
| API | ISAR1 | 11:8 |
| GPA | ISAR1 | 27:24 |
| GPI | ISAR1 | 31:28 |
| GPA3 | ISAR2 | 11:8 |
| APA3 | ISAR2 | 15:12 |

All six are zero in `0x100001` / `0`. The set bits in `0x100001` are AES `[3:0] = 1` and DPB `[23:20] = 1`. Those are not pointer authentication. `swpac_id_pauth_absent(0x100001, 0)` is true. A non-zero value in any of the six fields makes it false.

When those fields are zero, FEAT_PAuth is not implemented. From the Arm A64 description (111108, 2026-09):

- **Integer** encodings (`PACIA`, `AUTIA`, `BLRAAZ`, `RETAB`, `PACGA`, `LDRAA`, `ERETAA`, the `XPACI` register form, …) decode as **UNDEFINED**.
- **System / HINT** encodings (`PACIASP`, `PACIBSP`, `PACIAZ`, `PACIA1716`, `XPACLRI`, and the AUT counterparts) decode as **NOP**. They do not trap.

`ESR_ELx.EC` for an undefined instruction is `0b000000`. This model does not invent an ISS.

There is no architectural “emulate PAC at EL1” trap on a CPU that does not implement the feature. `HCR_EL2.API` exists only when FEAT_PAuth is implemented, and this host is EL1, not EL2.

## Stock-kernel undef hook is closed

RB5主管 reported the following for the exact running kernel `6.6.9-qcomlt-arm64-00188-g31f49428dc7d`. This note records that handover. It does not claim an independent hash of the qcom tree.

| File | Supervisor's report |
|---|---|
| `arch/arm64/kernel/traps.c` | Byte-for-byte match of Linux v6.6.9. SHA-256 `edc9b0ed19c1602906db6b17358823559135727df749053ec3f1e1542e55bd57`. |
| `arch/arm64/kernel/entry-common.c` | Byte-for-byte match of Linux v6.6.9. SHA-256 `0d4c8e4c7b004122baa19b20fafd4c0bcd94cfcd825c4dd8d251f1cd76c8529e`. |

From that same report:

- `do_el1_undef` (`traps.c` 475–487) calls `try_emulate_el1_ssbs` and otherwise `die("Oops - Undefined instruction")`. There is no `register_undef_hook`.
- `do_el0_undef` ends in `SIGILL`.
- `el1h_64_sync_handler` sends `EC_SYS64` and `EC_UNKNOWN` to `el1_undef`. Only `EC_FPAC` goes to `do_el1_fpac`.
- Without FEAT_PAuth, `RETAB` is an undefined instruction and takes `EC_UNKNOWN`, not FPAC.
- `PACIBSP` is a HINT. It does not enter `do_el1_undef`.
- `try_emulate_el1_ssbs` recognizes only the SSBS `MSR` and is not exported.
- A rebuild `System.map` did not match the board map. `do_el1_undef` is `ffff800080020bc8` on the board and `ffff800080020ac0` in that rebuild. Rebuilt addresses are not board addresses.
- Upstream 6.6 also has no general `register_undef_hook`.

Conclusion from that handover: a stock-kernel undefined-instruction hook is not an integration path. `do_el1_undef` has no registration point a module can attach, `try_emulate_el1_ssbs` is not an exported PAC hook, and EL0 undefined instructions become `SIGILL`.

HINT sign points stay outside `do_el1_undef`. A handler that saw only `RETAB` would observe an LR that `PACIBSP` had already left unsigned. The absent-profile test records the same split in the model:

1. `PACIBSP` (HINT `0xd503237f`) returns `SWPAC_NOP`. X30 is unchanged. PC advances by 4.
2. `RETAB` (integer `0xd65f0fff`) returns `SWPAC_UNDEF`. PC and X30 stay put.

In the experimental profile the same pair signs X30 with key IB and SP, then `RETAB` branches to the authenticated address and leaves X30 holding the signed value. That is virtual-FEAT_PAuth behaviour inside this model. It is not what the RB5 executes, and it is not macOS execution.

This branch does not modify `fki_die_pre` or `keys_read`. `fki_die_pre` remains the existing best-effort `die()` probe described above. It is not a PAC emulator.

## Software-only options

These are records of what could be done later in software. None of them is implemented on this branch. None of them is macOS execution, an RB5 load, a module build, or a hook registration.

1. **Current deliverable.** The host model and `make test` / `make test-ubsan` / `make fixtures-check` stay the result of this branch. `swpac_step` does not fetch, does not walk page tables, and does not run on the board.
2. **A future EL1 undefined-instruction emulator.** That would be a change to kernel source plus a rebuild that matches the running `6.6.9-qcomlt-arm64-00188-g31f49428dc7d` image. It would still miss HINT sign points, because `PACIBSP` does not enter `do_el1_undef`. It is out of scope until RB5主管 decides to do it. The board and rebuild addresses above already disagree, so a rebuilt symbol address is not a board address.
3. **Guest instruction interpretation or binary translation.** That is a separate design. It is not this model, and it is not macOS execution.

Host API the tests call, layout-compatible with `struct fki_pac_keys` (`xnu_world.linux_keys` at 240, `xnu_keys` at 328):

```c
void swpac_cpu_init(struct swpac_cpu *c, int profile);
void swpac_keys_swap(struct swpac_cpu *c, const struct swpac_keys *load, struct swpac_keys *save);
int  swpac_decode(uint32_t insn, struct swpac_dec *d);
int  swpac_step(struct swpac_cpu *c, uint32_t insn);
```

`swpac_step` updates X0–X30, SP, and PC only for `SWPAC_OK` and `SWPAC_NOP`. On `SWPAC_UNDEF`, `SWPAC_UNSUPPORTED`, `SWPAC_NOT_PAC`, and `SWPAC_BAD_CONFIG` those registers stay unchanged. `cpu->last` is diagnostic and is updated either way. `swpac.c` is GPL-2.0-only. The header carries the Linux-syscall exception.

## Subset that is implemented

Profile `SWPAC_PROFILE_ABSENT` matches the ID-register result above.

Profile `SWPAC_PROFILE_EXPERIMENTAL` is a virtual FEAT_PAuth **without** FEAT_PAuth2, FEAT_FPAC, FEAT_FPACCOMBINE, FEAT_PAuth_LR, FEAT_CONSTPACFIELD, or MTE. It is opt-in. Nothing in the kernel selects it.

EL1 only, two VA ranges. `TCR_EL1.T0SZ` / `T1SZ` must be 16..39 (4KB granule, `TCR_EL1.DS=0`: minimum 16 from DDI 0601; maximum 39 without assuming FEAT_TTST). Out of range returns `SWPAC_BAD_CONFIG`. The architecture’s CONSTRAINED UNPREDICTABLE clamp is **not** implemented; the model refuses instead of picking one.

`bottom_PAC_bit = 64 - TxSZ`, selected by:

- Insert: the `selbit` from the !FEAT_PAuth2 `InsertPAC` EL1 path (bit 55 if either half has the relevant TBI, otherwise bit 63).
- Authenticate and Strip: **bit 55**, as in `Authenticate` / `Strip`. These are not the same selector. A test covers a pointer whose bit 63 and bit 55 differ.

TBI0/TBI1 and TBID0/TBID1 follow `EffectiveTBI`: TBID drops instruction tagging and leaves data tagging. On a taken branch, if instruction TBI applies, bits `[63:56]` of the new PC are forced to the extension of bit 55 (DDI 0601 `TCR_EL1.TBI0/TBI1`). `AUT*` does not do that force; it returns the stripped register value, tag included.

SCTLR enables, FEAT_PAuth and not FEAT_PAuth_EnhCtl (DDI 0601 `SCTLR_EL1`):

| Bit | Key |
|---|---|
| 31 EnIA | APIAKey |
| 30 EnIB | APIBKey |
| 27 EnDA | APDAKey |
| 13 EnDB | APDBKey |

Clear means `AddPAC*` / `Auth*` return the input unchanged (a NOP of the operation, not of the instruction). `PACGA` has no enable bit in `AddPACGA`. EL2 `HCR_EL2.API` traps are not modelled.

Authentication failure (!FEAT_PAuth2 `Authenticate`, no FEAT_FPAC):

- Key number bit is 0 for A and 1 for B. `error = key_number :: NOT(key_number)`.
- TBI: `error` replaces bits `[54:53]`.
- No TBI: `error` replaces bits `[62:61]`.
- The instruction does **not** raise EC `0b011100`. Combined branches store the poisoned address in PC (DDI 0487 D8.10.5, FEAT_FPACCOMBINE not implemented). `last.auth_failed` and `last.fetch_noncanonical` record that. `X30` is still set to `PC+4` for `BLR*`, because the ASL writes `X30` after `Auth` returns. `RETAA`/`RETAB` do not write LR.

A non-canonical input flips `PAC[top-1]` before insertion, so a later auth fails. That is the !FEAT_PAuth2 rule, not an extra check invented here.

`XPACI` / `XPACD` / `XPACLRI` strip. They do not check the PAC. A tampered pointer strips to the same canonical address as the original. That is architectural `Strip`, and a test locks it so it cannot be confused with authentication.

### ComputePAC stand-in

```
z = data XOR key_lo
z = z XOR (modifier + 0x9E3779B97F4A7C15)
z = (z XOR (z >> 30)) * 0xBF58476D1CE4E5B9
z = z XOR key_hi
z = (z XOR (z >> 27)) * 0x94D049BB133111EB
z = z XOR (modifier >> 17)
z = (z XOR (z >> 31)) * 0xD6E8FEB86659FD93
z = z XOR (z >> 32)
```

Only the bits that the architectural compare looks at are significant. Narrow PAC fields collide. The key **register** selects which 128-bit value is used. The key id is not mixed in: identical bits loaded into IA and IB produce the same code when the TBI view matches. Poison still differs (the error code depends on A vs B).

### Encodings

Masks come from the 111108 encoding tables and were checked against `clang --target=aarch64-linux-gnu` (see `fixtures.s` / `fixtures.inc`). The test decodes every assembled word.

Executed in the experimental profile: integer and HINT `PACIA/B/DA/DB`, `AUTIA/B/DA/DB` (including zero-modifier and SP forms, and the `*1716` hints), `XPACI/XPACD/XPACLRI`, `PACGA`, `BLRAA/BLRAAZ/BLRAB/BLRABZ`, `BRAA/BRAAZ/BRAB/BRABZ`, `RETAA/RETAB`, and MRS/MSR of the ten key registers.

Refused with `SWPAC_UNSUPPORTED` (state unchanged): `LDRAA/LDRAB`, `ERETAA/ERETAB`.

`SWPAC_UNDEF` (state unchanged): unallocated variants in those spaces (PACIZA with Rn not 31, BLRAAZ with Rm not 31, other XPAC opcodes), and every non-HINT PAC op in the absent profile.

`SWPAC_NOT_PAC`: NOP, BTI, plain `RET`, plain `LDR`, `MRS SCTLR_EL1`. State unchanged. The model does not execute generic instructions.

Not implemented, and not silently accepted: FEAT_PAuth_LR’s second modifier, PSTATE.BTYPE / BTI landing-pad checks on `PACIASP`, GCS, MTE field placement, EL0-vs-EL1 enable splitting, EL2/EL3, a guest page-table walk, instruction fetch. `swpac_step` does not read memory. The caller supplies the instruction word.

## Tests and what they are not

| | Result |
|---|---|
| Host model tests (`make test`) | **825 passed, 0 failed** on this x86_64 cloud VM. See the log. |
| UBSan (`make test-ubsan`) | **825 passed, 0 failed**. |
| ASan | Not run. The ASan runtime library is not installed in this VM. |
| Fixture assemble (`make fixtures-check`) | `clang --target=aarch64-linux-gnu` encodings match `fixtures.inc`. This is assembly, not execution on an ARM CPU. |
| `fki.ko` / `xnu.ko` build | **Not built.** Exact 6.6.9-qcomlt headers and `Module.symvers` are not here. No approximate vermagic. |
| Native RB5 execution | **Untested.** No device access, no SSH, no module load, no reboot. |
| macOS / XNU boot | **Untested.** No image. A passing model test does not boot macOS. |

Commands, from `exp/swpac`:

```
make test
make test-ubsan
make fixtures-check
```

`make test` needs a C11 compiler. `make fixtures-check` also needs `clang` with the AArch64 target, which is what produced `fixtures.inc`.

Covered by the 825 checks: assembled decode of the ops above; absent-profile UNDEF vs HINT NOP; sign/auth round trip; tampered PAC bit, tampered address bit, wrong modifier, wrong key; unsigned pointer is not “already authenticated”; IA/IB isolation by key **value** (not a hidden key id); key swap and a second CPU context; SCTLR enable NOP and “EnIB clear does not disable IA”; TBI tag kept by `AUT`, forced off on a taken branch; TBID instruction vs data; non-canonical input corruption and bit-55 vs bit-63 selector; T1SZ 16, 25 (39-bit kernel VA, including `0xffffffe000001000` in the documented LINUX64 window), and 39; TxSZ 15 and 40 rejected with registers preserved; `BLRAAZ` / `BRAAZ` / `RETAB` success and failure, including X30 writeback rules; `PACGA` low 32 bits zero and no enable bit; MRS/MSR of the key file then a sign that observes the new key; `XPACI` strips a tampered pointer without authenticating; `LDRAA` / `ERETAA` refused; layout match with `fki_pac_keys` and `xnu_world`.
