# How to continue this research

## Read first (30 min)
1. `README.md` — overview and current status
2. `docs/TRIPLE_FINAL_SUMMARY.md` — the audit verdict (14 functions, 0 candidates)
3. `docs/REASONING_TRAIL.md` — the complete investigation story (every hypothesis, why it failed or held)

## What's already proven (don't re-audit)
- `fp_read_host_file` — transport-layer patched (clamp + callback refusal)
- mxml parser — safe (bounds-checked growth)
- escape function — safe (not on our failing paths)
- command loop — safe (result-mux from DA1 handoff, magic-verified)
- scatter parser — safe (count guard 0xbf, bounded copies)
- 11 more DA2 XML functions — see `TRIPLE_FINAL_SUMMARY.md`

## UPDATE (2026-10-25, late) — DA1 + Preloader now audited; this list is historical

The original priority list below was written when only DA2 was audited.
Since then (see `DA1_AUDIT.md` and `PRELOADER_AUDIT.md`):

- **Priority 1 (DA1): DONE — closed.** All 11 commands audited, 0 candidates
  ≥ 2/5. Includes the full RAM-TEST correction trail (write primitive real
  but data-only, no oracle, no consumer).
- **Priority 2 (Preloader): DONE — closed.** usbdl state machine mapped,
  whitelist = WDT + 1 reg + 1 MMIO page only, and the DAA gate is a genuine
  RSA-2048/e=65537/PSS-SHA256 verify with a boot-populated SRAM modulus.
  0x7024 unforgeable. The ram_size cross-check resolved offline as a
  structural no-op.
- **Priority 6 (oplus_security state machine): DONE — closed.** Byte-audited on both
  builds: the accept requires a genuine RSA-2048 PKCS#1 v1.5 verify (e=0x10001) whose
  256-byte modulus is byte-identical in 200EX01 and 2710EX01 (`sha256 c58002ae…`); no
  unsigned/fallback/efuse path. One captured vendor blob is replayable with an arbitrary
  policy body (device-level authorization), but grants flash-write registration only —
  it does not touch AVB/LK/RPMB. See `DA2_POLICY_SIGNATURE.md`.
- **Intermediate-DA idea: RESOLVED by device experiment.** 400EX01 and 1900EX01 DA_BR
  containers (properly signed) are both refused with 0x7024 — together with the 420EX01
  and 200EX01 data points, the DAA key material was rolled once, before 2025-01.
- **Priority 3-5 (EFUSE/cert-chain/RPMB): unchanged** — all assessed low-probability;
  RPMB primitives exist but are XML-unreachable on stock 2710EX01 (session 7-9 work).

**The only remaining theoretical layer is TEE/tbase — a different order of
project.** The reusable positive result is the RPMB mirror map (LK blocks
0x1DC–0x1DF): the unlock recipe is model-wide and waits on any authenticated
RPMB write primitive.

---

## Untested surfaces (original list, kept for context)

### Priority 1 — DA1 (strongest candidate, ~30-40% est.) [DONE — closed]
- Size: 0x69424 bytes (431,140 B = 421 KiB)
- Location: extracted at `research/da_offline_analysis/DA1_extracted.bin` (not in this repo — proprietary)
- Why: parses its own host commands before DA2 runs. Never audited in this project.
- Approach: same methodology as DA2 (3-way diff vs 420EX01/generic, reachability, gate/assembly)

### Priority 2 — Preloader (~15-20%) [DONE — closed]
- Outside this project's binaries
- Handshake protocol audited (descriptor bug was tooling-side, not firmware)
- Suggests looking at preloader command handling in the generic MTK preloader if available

### Priority 3 — EFUSE handlers (0x4003184a..0x40032dc4 + 0x40007ea8/07f58) (~10-15%)
- Reachable via CMD:WRITE-EFUSE / CMD:READ-EFUSE
- Only structural review done, never deep-dived
- If EFUSE write has a logic bypass → could flip SLA/DAA enables

### Priority 4 — Cert chain verification (~10-15%)
- FUN_40037fc8, 0x4003ce28, 0x4003e110, 0x400401c8
- Never audited
- If cert validation has a logic bug → DAA bypass possible

### Priority 5 — RPMB suite (0x40025d4c..0x40026eb0) (~3-5%)
- HMAC frame handling
- Lower priority (needs RPMB key session)

### Priority 6 — oplus_security state machine (0x4001033c) (~5-8%)
- Internal transitions (status 1/2/3/4) never byte-audited
- Mapped by ea29ia in PR #410

## Methodology notes (from our experience)
1. **Ghidra `.data` is unreliable** — values that look zero in Ghidra often exist in raw bytes. Verify globals from `DA_BR.bin` at `offset = DA2_base + (VA - 0x40000000)`. Writer-tracing is unaffected.
2. **"Same pattern" is not proof** — get assembly (CMP/SUBS/SBCS) for every size check. The decompiler sometimes renders `if (a <= b)` as `(uint)(a <= b)` misleadingly.
3. **Cross-command state = critical** — always verify globals are fresh-zeroed per command, not persistent.
4. **Fall-through defects** (error path without return) are code smells — check if the caller has a memset/init that neutralizes them.
5. **Reachability first** — build the call graph from XML handlers, audit reachable functions first.

## Tools used
- Ghidra 12.1 headless with PyGhidra (JDK 21)
- `scripts/trace_decode_logprobe.py` — decoder for the heap trace
- `scripts/_vm_deploy_block_*.sh` — deploy scripts for mtkclient patches

## What NOT to do
- Don't attempt to flash anything without explicit understanding of the anti-downgrade (DAA 0x7024) — loading older DA builds is refused at the signature gate.
- Don't trust "Successfully wrote" output in mtkclient's write paths — see ea29ia's PR #410 incidents (silent-fake writes, seccfg zeroing).

## Related links
- mtkclient issue #409: https://github.com/bkerler/mtkclient/issues/409
- Penumbra issue #134 (same device, different user)
- ea29ia's PR #410 (DA2 pre-patching research, closed)
- This repo's license: MIT
