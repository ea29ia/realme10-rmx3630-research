# Realme 10 4G (RMX3630) — Bootloader Research

Static analysis and exploitation research for MT6789 (Helio G99) on Realme 10
4G, build 2710EX01 (Dec-2025 security patch).

## Status (2026-10-25, final)

**Every audited surface is closed. No viable vector found anywhere.**

- DA2 XML attack surface: fully audited (14 functions, 0 candidates ≥ 3/5)
- heapbait: patched at the transport layer (clamp + callback refusal)
- **DA1: fully audited (11 commands, 0 candidates ≥ 2/5) — hardened like DA2**
- **Preloader: fully mapped (usbdl state machine + whitelist) and the DAA
  gate is a genuine RSA-2048/PSS-SHA256 verify — 0x7024 unforgeable**
- **RAM-TEST: real write primitive (device-verified) but data-only — two
  parity-selected constants, no read oracle, no reachable consumer**
- **ram_size cross-check: structural no-op (all readers share one runtime
  DRAM-probe global)**

## What's in this repo

- `docs/` — full audit reports, log, and handoff docs
  - `TRIPLE_FINAL_SUMMARY.md` — DA2 XML audit (14 functions)
  - `DA1_AUDIT.md` — full DA1 command-surface closure + the RAM-TEST
    correction trail
  - `PRELOADER_AUDIT.md` — usbdl map, whitelist, RSA-PSS verifier, ram_size
  - `REASONING_TRAIL.md` — the complete investigation story
- `scripts/` — trace decoder and deploy tooling
  - **Note:** the two heapbait `_vm_deploy_block_{trigger,sweep4200}.sh` patches
    are **historical** — the transport-layer closure (see `docs/TRIPLE_FINAL_SUMMARY.md`)
    supersedes them on 2710EX01, and running them yields the stock NAK envelope.
    `trace_decode_logprobe.py` (allocator free-list decoder) and the logprobe config
    (`_vm_deploy_block_logprobe.sh` — in-band USB logging) remain genuinely useful
    on any build where the log channel is reachable.
- `analysis/` — raw JSON data (reachability, 3-way diff)

## What remains (for anyone continuing)

- **TEE/tbase** — a different order of project; the only theoretical layer
  above everything audited here.
- The RPMB mirror map (LK blocks 0x1DC–0x1DF, `+0xC` lock field, `+0x20`
  "RMX3630RU", `+0x3E0` SHA-256) is the reusable result: the unlock recipe
  is model-wide (byte-identical LK path across builds) and waits only on any
  authenticated RPMB write primitive — which is exactly what this firmware
  generation does not offer.

## Related links

- mtkclient issue #409: https://github.com/bkerler/mtkclient/issues/409
- Penumbra issue #134 (same device, different user)
- ea29ia's PR #410 (DA2 pre-patching research)
- ea29ia's notes (cross-linked): `ea29ia/mtkclient` — `docs/notes/da2_static_audit.py`, `docs/notes/reverse/re-da2-2710-audit-2026-10-25.md`, branch `oplus-mt6789-unlock` (the 200EX01 unlock + root write-up)

## Methodology notes

- Ghidra `.data` section unreliable — verify globals from raw bytes at
  `offset = DA2_base + (VA - 0x40000000)`
- "Same pattern" is not proof — get assembly evidence for every check
- Cross-command state: always verify globals are fresh-zeroed per command
- `set_configuration()` unconditionally on configured devices = USB
  "lightweight device reset" — this bug cost us 3 days of false "firmware
  sabotage" investigation

## NOT included (proprietary)

DA_BR.bin, export zips, and any Realme/Oplus binaries are deliberately excluded.
The research relies on their SHA-256 hashes and byte-level analysis only.

## How to continue

Read `docs/HOW_TO_CONTINUE.md` first (5 min). Then `docs/REASONING_TRAIL.md`
for the complete investigation story (why each hypothesis failed or succeeded,
with evidence). For the audit verdict only, `docs/TRIPLE_FINAL_SUMMARY.md`.

The raw chronological log (with daily notes, battery levels, VM crashes) is
not included in this repo — it's a personal working document. `REASONING_TRAIL.md`
is the cleaned, self-contained version.
