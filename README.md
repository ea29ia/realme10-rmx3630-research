# Realme 10 4G (RMX3630) — Bootloader Research

Static analysis and exploitation research for MT6789 (Helio G99) on Realme 10
4G, build 2710EX01 (Dec-2025 security patch).

## Status (2026-10-25)

**DA2 XML attack surface: fully audited. No viable vector found.**

- heapbait is patched at the transport layer (clamp + callback refusal)
- 14 DA2 functions audited (assembly-level evidence)
- 3-way diff against 420EX01 and generic MTK → 20 OPLUS-added candidates
- 0 candidates ≥ 3/5

## What's in this repo

- `docs/` — full audit reports, log, and handoff docs
- `scripts/` — trace decoder and deploy tooling
- `analysis/` — raw JSON data (reachability, 3-way diff)

## Untested surfaces (for future work)

1. **DA1** (0x69424 bytes) — never audited. Strongest candidate (~30-40% est.)
2. Preloader — outside this project's binaries
3. EFUSE handlers (0x4003184a..0x40032dc4)
4. Cert chain verification (FUN_40037fc8, 0x4003ce28, 0x4003e110)
5. RPMB suite (0x40025d4c..0x40026eb0)
6. oplus_security_verify_sec_policy state machine (0x4001033c)

## Related links

- mtkclient issue #409: https://github.com/bkerler/mtkclient/issues/409
- Penumbra issue #134 (same device, different user)
- ea29ia's PR #410 (DA2 pre-patching research)

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
