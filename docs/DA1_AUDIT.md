# DA1 Audit (2710EX01) — full command-surface closure

Date: 2026-10-25. Binary: `DA1_extracted.bin` (431,140 B = 0x69424, extracted
from DA_BR.bin at 0x0000BC..0x0694E0, sha256
`6c49eba0cea6d966539d2cb9bfe029eec4b3c772a11616c6ade2452aa8426e20`). Ghidra
ARM:LE:32:v7 (**never v5t** — the CPS instruction at 0x20012C kills v5t
analysis), project `GhidraProj_DA1_v7`, 980 functions at ~79% body coverage.

**Verdict: all 11 XML commands audited across three batches (plus the
dispatcher and the host-file read path). 0 candidates ≥ 2/5. DA1 is hardened
like DA2 — no memory-corruption or logic-bypass surface found anywhere in the
XML attack surface.**

## Command map (FUN_00200F10 registrar)

NOTIFY-INIT-HW (0x2019D4) · SET-HOST-INFO (0x201A28) · BOOT-TO (0x20112C) ·
REBOOT (0x2026B4) · GET-HW-INFO (0x202890) · SET-RUNTIME-PARAMETER (0x2016F0)
· HOST-SUPPORTED-COMMANDS (0x202CF8) · RAM-TEST (0x2014FC) · WRITE-FLASH
(0x201AF4) · ERASE-FLASH (0x20218C) · READ-FLASH (0x201F5C)

No hidden/extra `CMD:*` strings exist in DA1 beyond these 11.

## Hardened patterns found everywhere (same as DA2)

- 64-bit subtract-with-borrow range checks (`SUBS`/`SBCS`)
- strlcpy-style bounded copies (`if (param_3-1 < uVar1) uVar1 = param_3-1`)
- snprintf-with-cap output (`if (iVar7 == param_2) goto end` at every emit
  site) into malloc'd 0x800
- strtoull with strict hex/dec validation (FUN_00205668)
- fixed-table string compares (FUN_00205C60, tables @0x263DAC.., max 0x20)
- The host-file read path (FUN_002505C4, 916 B) carries the same clamp as
  DA2's patched version (`cmp r0,r1 / cpycs r0,r1` @0x2508EC-F0 = min(
  remaining, packet_max)) — **no over-delivery primitive in DA1 either.**

## Batch highlights

- **RAM-TEST (FUN_002014FC):** the static gate analysis is sound (64-bit
  bounds vs the DRAM window globals 0x2DE558/55C), but the full verdict
  needed device work — see the RAM-TEST section below. This is the only DA1
  command whose *runtime* behavior is more interesting than its static gate.
- **READ-FLASH (FUN_00201F5C):** two 64-bit range checks sound; copy via the
  proven-clamped uploader; partition name via the strlcpy bound (0x40).
- **HOST-SUPPORTED-COMMANDS (FUN_00202CF8):** one bounded copy (0xFF into the
  0x100 tail of a lazily-malloc'd 0x180 buffer); no length-derived math.
- **REBOOT (FUN_002026B4):** the only watchlist item (2/5) — a deferred-call
  global (0x2DF7A4) exists, but its value domain is five fixed function
  pointers; no host-controlled value can land there. `OPLUS_REBOOT_TO_EDL`
  is operationally interesting (reboots to EDL/BROM) but BROM is efuse-locked
  on this generation, so it is a state transition, not a bypass.
- **BOOT-TO (FUN_0020112C)** — the DA1 DAA hash gate: HACC-driven hash
  (FUN_00252878 → FUN_00253BD0 → FUN_00253D34, HACC @0x10210000, 0xFFFFF0
  chunking) compared against the expected hash @0x2692F4 with a fixed-32
  bounded loop. No parse flaw.
- **SET-RUNTIME-PARAMETER (0x2016F0):** all host values go through
  fixed-table lookups writing only fixed pointers to globals — no
  host-length copies. (This handler's log channel is separately notable: it
  is what made the in-band allocator trace possible in the DA2 heapbait
  work.)

## RAM-TEST — the honest correction trail (write-up included on purpose)

This surface is the reason our methodology rules (R-A..R-D) exist. Summary:

1. **First static verdict ("read-only", 1/5) was WRONG.** The flagged MMU
   mapper pair (FUN_00200908/FUN_0020062C) is just a mapper; the actual
   tester (FUN_002031CC) contains the stores: `*(param_1+i*4) = pattern`,
   `*(param_2+i*4) = pattern` — walking-bit patterns (`1<<n`, `~(1<<n)`)
   into the host-chosen window and its mirror, with NO auth in DA1. The
   error was caught because the user asked "are you sure?" (R-D) before a
   wrong public reply went out.
2. **Device-verified primitive (5 handshakes, 3 configs, zero storage
   writes):** `FLIP(start, len)` writes real patterns into any PA inside the
   declared DRAM window, host-controlled PA+len, no auth. Top-scratch
   (`0x1FFF00000`) is mapped and writable — verified on device.
3. **The read oracle was FALSIFIED (by us, on device):** the comparator
   walks FORWARD (`[r0,-r7]` with r7 decreasing = `r0+4`); compare pairs are
   (A[i] vs B[i]) on identically written dwords — always equal, always
   SUCCESSED. No planted-mismatch abort, no freeze trigger. An earlier
   "backward compare" claim was our own asm sign error, retracted before
   building anything on it.
4. **The final value is parity-dependent (host-controllable, both sides
   verified instruction-for-instruction):** pass 1 re-runs `mvn` with r5
   already complemented, so even k lands `0x80000000`, odd k lands
   `0x7FFFFFFF` — two selectable constants per dword, alignment-chosen.
5. **No reachable consumer:** the WRITE-FLASH deny gate (FUN_00251374)
   hardcodes the deny flag (`strh 0x100,[r1,#2]` puts 0x01 into byte+3),
   and the flags live in the caller's per-command stack frame — sequential
   commands cannot reach another command's frame. FUN_00251364 (skip branch)
   is dead code (`*param_1 = 1; return 0`).
6. **LR-corruption angle = one-way crash, not control flow** (both parties'
   independent conclusion).

**Net: a real, no-auth, data-only write primitive with two selectable
constants and no consumer. Surface closed.**

## Impact on the campaign

Both DAs fully audited. The complete 2710EX01 attack surface is closed:
heapbait (transport-clamped) + extension bootstrap (rejected on stock) +
RPMB (dead code on stock) + DA1 (hardened) + preloader (see
`PRELOADER_AUDIT.md` — real RSA-PSS gate + whitelist) + ram_size (structural
no-op). The only theoretical layer above is TEE/tbase.

## Artifacts

Working-tree artifacts (not committed, binary-free policy): `da1_batch3_audit_out.md`
(57 KB decompiles), `da1_batch3_report.md`, `ramtest_deepdive.md` (the full
correction trail), `ramtest_write_audit_out.md`, `ramtest_worker_audit_out.md`,
`ramtest_final_verify_out.md`, `ramtest_max_ufs_session10.md`, and the probe
logs (`probe_ramtest.py`, hash-verified). DA1 remains proprietary and is not
shipped here.
