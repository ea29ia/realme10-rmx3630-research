# Preloader Audit (2710EX01) — usbdl state machine, whitelist, and the DAA signature verifier

Date: 2026-10-25. Binary: `preloader_k6789v1_64.bin` (391,380 B, sha256
`677d1feb…`). Ghidra ARM:LE:32:v7, base derived **0x200F00** from the binary
itself (225/300 sampled string literals matching absolute references; a
different 200EX01 copy of the same file uses 0x200F10 — the delta is the
container header size). 1276 functions.

**Verdict: the preloader pre-auth surface is engineered tight and fully
mapped. The signature check is a genuine RSA-2048 verify, not a shape check.
0x7024 (DAA rejection of unsigned AllInOne containers) originates here and is
unforgeable without the MTK/OPLUS private key.**

All addresses below are VAs on our base; add +0x10 for the 200EX01 mapping.
ea29ia's 200EX01 preloader independently confirmed the same whitelist
literals, the same DAA-flag global (their `0x2F3158` ≡ our `0x2F3158` minus
base delta), and the same verifier structure — so the model is build-wide,
not a 2710EX01 tightening.

## 1. The usbdl state machine (FUN_00208150)

The host protocol is a token-synced command loop. Sync on the 0xA0 token
(matches a 4-byte magic from a boot table), then dispatch per command byte
(read into `bStack_99`). The full map:

| Cmd | Function | Behavior |
|---|---|---|
| 0xD7 | DA download | addr limit 0x400000, len limit 0x100001; writes into the download buffer; XOR-16 checksum reported to host; then **signature verify (FUN_00237938)** — any failure → 0x7024 and the buffer is zeroed |
| 0xD5 | Jump to DA | refuses 0x7024 unless the DAA flag byte (set only by a successful 0xD7) is 1; no jump without a verified DA |
| 0xD1 | Memory write | 4-byte-aligned, length ≤ len<<2, gated by **write whitelist** (FUN_00237E34) |
| 0xD4 | Memory read | same alignment/length gates, gated by **read whitelist** |
| 0xC4 | read32 helper | via FUN_002089AC (4-byte read with per-call table dispatch) |
| 0xC6 | mailbox bitfield read | FUN_00233CF4: read32 → extract field |
| 0xC7 | mailbox bitfield write | FUN_00233D38: read-modify-write32 |
| 0xD0/D2/D3 | mode toggles | FUN_00208850 / FUN_002088D6(1)/(0) |
| 0xE1/0xE7 | random/data out | 0x10/0x20-byte buffers via FUN_0023F29E/FUN_0023F2D2 |
| 0xF0 | magic compare | host dword vs DAT_002085FC |
| 0xFD | stack readout | sends `*(0x08000000)` |
| 0xFE | flush/exit | FUN_002087D8(0x42) |

## 2. The memory R/W whitelist (raw .data, verified from file bytes)

FUN_00237E34 rejects any (addr, len) that fails the region match, and the two
whitelist tables (pointers at 0x237E2C/0x237E30) contain exactly:

- **READ:** `0x10007000..+0x1000` (watchdog timer block), `0x1001A080..+4`
  (one register), `0x11F10000..+0x1000` (one MMIO page)
- **WRITE:** the first two only — no MMIO page, no DRAM, no SRAM, no DA1 image

That is the entire pre-auth memory capability: watchdog control and a single
register. The `0xD4`-write-DA1-into-DRAM-then-`0xD5`-jump bypass is closed
twice: the whitelist forbids DRAM access, and the signature gate would reject
unsigned payloads anyway.

## 3. FUN_00237938 — the DA signature verifier (374 B)

Full decompile and the crypto chain in the artifacts (see §5). The chain:

1. **Gate:** `param_4 != 0x100` → immediate `0xffffffff`. The signature
   length is a fixed constant (256 B = RSA-2048 modulus size), so
   `sig_len == 0` short-circuits are impossible.
2. **pubk_initialized check:** `DAT_002F9F28` (boot-populated .bss beyond the
   file image) must be non-zero, else error 0x10100c.
3. **Digest:** FUN_00241770(image, `da_len − sig_len`, out, algo) → HACC
   engine @`0x10210000` (same hardware engine as the DA1 DAA hash gate,
   0xFFFFF0 chunking). **The digest covers `da_len − sig_len` only — the
   signature trailer is excluded, i.e. a correct PSS layout with no
   self-covering bug.**
4. **Modexp:** FUN_0024178E(algo 0) → FUN_00244508 (HACC RSA setup, keylen
   0x100<<3 = 2048 bits) + FUN_00244566 (op 0x13). The exponent slot is the
   hardcoded constant `0x10001` (e = 65537, FUN_00244566 `local_24`). The
   modulus comes from the runtime key blob at `0x2F9F38` — boot-populated
   SRAM beyond the file end (0x260774), and outside the 0xD4 whitelist, so
   not writable pre-auth. Byte-reversal (FUN_0024126E) = big-endian operand
   prep.
5. **Verify:** FUN_002417AE(algo 0) → FUN_002414B8 (PSS-SHA256, salt 0x20):
   `EM[0xFF] == 0xBC` → MGF1-SHA256 unmask (FUN_002413FA) → DB[0xBE] == 0x01
   → `H' = SHA256(0^8 || digest || salt)` → **FUN_0023874C = full 32-byte
   byte-by-byte memcmp, no early-accept** (store/compare inventory of every
   leaf done — HACC hash, MGF1, SHA init/update/final, memcmp: 30 B, pure
   compare, zero stores).
6. **Success** sets the DAA flag byte (what 0xD5 checks); any failure
   propagates 0x7024.

The algo-1 PSS-SHA384 variant (FUN_00241C58) and the algo-2 software
Montgomery path (FUN_002420F2, 4096-bit) exist in the binary but are
unreachable here — the `sig_len != 0x100` gate forces the 2048-bit path.

**⇒ The compare is `modexp-recovered EM` vs `PSS-recompute`, not a raw hash
vs trailer. Computing SHA-256 over a patched DA1 does not forge it. 0x7024
is unforgeable without the MTK/OPLUS private key.**

## 4. ram_size cross-check — resolved offline (structural no-op)

The question ea29ia asked (GET-HW-INFO vs NOTIFY-INIT-HW dram_size) resolves
without a device session:

- NOTIFY-INIT-HW (FUN_002019D4 → FUN_00200E24) fills the DRAM globals
  `0x2DE558/0x2DE55C` from the DA's own DRAM probe FUN_00202F7C — a 16 MB-step
  walk with 3 GB-window MMU aliasing, magic-pattern write/verify per step,
  counting verified steps (loop-detection guard "MEMORY ADDRESS LOOP
  DETECTED!"). The declared 8 GB (`0x200000000`) is the probe's measured
  result, not a hardcoded constant.
- GET-HW-INFO (FUN_00202890) reads the **same** globals in its snprintf args.
- The RAM-TEST bound check (0x2016DC "Start address + length overflow. max
  DRAM size[0x%llx]") reads the **same** globals.

⇒ The three "sources" are one source formatted three ways; the device-side
comparison cannot disagree. The top-scratch derivation (maxDRAM − 0x100000 =
`0x1FFF00000`) used in the RAM-TEST experiments was correct by construction.

## 5. Artifacts (this repo does not ship binaries)

Raw decompiles and scripts live in the working tree (not committed here to
keep the repo binary-free): `preloader_import.py`, `preloader_triage*.py`,
`preloader_gate_out.md`, `preloader_rw32_out.md`, `preloader_whitelist*.py`,
`preloader_usbdl_cmds_out.md`, `preloader_sigverifier_out.md` (target +
caller + callees), `preloader_sigcrypto_out.md` (crypto chain incl. the
modexp core and both PSS helpers), `preloader_sigchain2_out.md` (SHA/MGF1/
memcmp leaves), `preloader_ramsize.py` / `da1_ramsize_out.md` (the ram_size
chain). Key hashes: preloader blob sha256 `677d1feb…` (full hash in the
project log); DA_BR.bin and all firmware blobs remain proprietary and
excluded.

## 6. What remains (for anyone continuing)

- TEE/tbase — a different order of project entirely; the only theoretical
  layer left above this one.
- The RPMB mirror map (LK blocks 0x1DC–0x1DF, `+0xC` lock field, `+0x20`
  "RMX3630RU", `+0x3E0` SHA-256) is the reusable result: the unlock recipe
  is model-wide and waits only on any authenticated RPMB write primitive.
