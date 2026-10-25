# Triple + Final Summary — New Vulnerability Hunt (2710EX01 DA2)

> Date: 2026-10-25 · Static only (PyGhidra 12.1 headless, existing projects).
> Target: research/da_offline_analysis/DA2_extracted.bin (2710EX01) — base 0x40000000.
> Zero device contact. No file modification. All evidence: decompiles + raw assembly + raw .data bytes.

---

## Part 1 — Triple gate results

### FUN_40002818 (download-partition, pre_erase) — confirm-only
Full decompile reviewed in Check 2 redo (callers of 2bff4). Flow: parse XML (mxml, audited)
→ read scatter via FUN_4002afd8 (CLOSED, Check 1) → FUN_4002bff4 (CLOSED, Check 2) →
erase via FUN_4002e968 → download via FUN_4002ae50 (CLOSED) / FUN_40030364 (CLOSED).
Security deny (FUN_4002d15c → local_ad != 0 → 0xc0020004) before erase and before write.
No independent arithmetic surface. **Closed 2/5 — covered by closed callees.**

### FUN_400030ec (partition download with offset) — confirm-only
Same structure as 02818 (0x58-stride table loop over scatter entries, calls into the same
closed set: 2bff4 / 2ae50 / 2e968). Additional attribute `da/arg/offset` consumed via
FUN_4000ada0 (strtoull) and validated by the same 64-bit SUBS/SBCS/BCC pattern proven in
40030364 (Check 1). **Closed 2/5 — covered by closed callees.**

### FUN_40003c38 (partition erase) — full gate

**Q1/Q2 — offset & length parse:**
Both `da/arg/offset` and `da/arg/length` parsed with FUN_4000ada0 = strtoull (unsigned 64-bit).
Negative input ("-1") → strtoull wraps to 0xFFFFFFFFFFFFFFFF (no sign check anywhere).

**Q3 — bounds checks (raw asm):**

Offset check (0x40003e10-0x40003e24):
```asm
40003e10  adds  r0,r6,r0      ; r6:r5 = offset(64b from strtoull), r0:r1 = ... ; sum = offset + base_offset(0)
40003e14  adc   r1,r5,r1      ; 64-bit add: sum = offset + 0
40003e18  subs  r6,r0,r2      ; r2:r3 = partition size (from GPT resolve FUN_40012c88)
40003e1c  sbcs  r6,r1,r3      ; 64-bit: sum - size
40003e24  bcs   0x40004128    ; C=1 (sum >= size) → "offset is larger than partition max size" → EXIT
```
Then the remaining-length computation:
```asm
40003e28  subs  r0,r2,r0      ; size - sum (64-bit)
40003e2c  mov   r2,#4
40003e30  sbc   r1,r3,r1      ; → remaining = size - offset (exact, no wrap: C=0 guaranteed here)
```

Length check (0x40003e6c-0x40003e7c):
```asm
40003e6c  bl    0x4000ada0    ; length = strtoull(da/arg/length)
40003e74  subs  r2,r2,r0      ; remaining(64b) - length
40003e78  sbcs  r2,r3,r1
40003e7c  bcc   0x4000414c    ; C=0 (length > remaining) → "erase length is larger..." → EXIT
40003e80  strd  r0,r1,[r4,#0] ; else remaining -= length
```

**Integer-overflow question (offset+length wrap):** The check is NOT `offset+length <= size`
computed once. It is a two-stage subtraction chain: first `offset >= size → reject`, then
`length > (size - offset) → reject`. A wrap in `offset+length` cannot bypass this because
the code never computes `offset+length` — it computes `size - offset` first (with C=0
guaranteed from the first check, so no borrow trick), then compares length against that
exact remainder with SUBS/SBCS/BCC. Any 64-bit wrap in strtoull values is caught:
- offset = 0xFFFF...FF → first check rejects (>= any size).
- length = 0xFFFF...FF with offset < size → second check rejects (length > size-offset).
**Overflow-proof.**

**Q4 — negative/signed:** strtoull has no negative detection, but both wrapped values
(0xFF..FF as offset or length) are rejected by the two 64-bit checks above. No signed
comparison exists to exploit.

**Q5 — erase call:** FUN_4002c618 → then `(*DAT_40054aa4)(local_88+2, &local_c0)` =
storage erase wrapper (partial-protect layer FUN_4002eec8 chain, audited structurally in
Phase 1; it re-validates against its own protection table "whole region is in protection").

**Q6 — auth ordering:** The security deny (FUN_4002d15c → "Security deny for [%s]") runs
INSIDE the partition-list loop (decompile lines 161-169) — BEFORE the erase call
(line 194, *DAT_40054aa4) in the same iteration. BUT the offset/length parsing (strtoull
+ bounds checks, asm 0x40003df4-0x40003e80) happens BEFORE that deny loop. On a locked
device the parse itself runs, but the parse is pure arithmetic on strtoull results with
no memory access beyond reading the XML strings (audited mxml). The only memory writes
before auth are stack locals. No crash/OOB/info-leak surface pre-auth.

**Q7 — 420EX01 compare:** Both strings ("offset is larger than partition max size.",
"erase length is larger than partition max size.") exist in 420EX01 — same two-check
logic existed before. OPLUS did NOT add new erase logic in 2710EX01; this function is
shared MTK code. **No +1 bump.**

**Verdict: FUN_40003c38 closed 2/5.** Bounds overflow-proof, auth before any flash
mutation, no OPLUS-new logic.

---

## Part 2 — Final summary of the entire hunt

### All functions audited (closed)

| # | Function | Role | Grade | Key evidence |
|---|---|---|---|---|
| 1 | FUN_4002ae50 | download request sender | 1/5 | not a copy loop; single XML send + OK parse |
| 2 | FUN_4002bff4 | scatter XML parser | 1/5 | count guard 0xbf before every write; bounded copies |
| 3 | FUN_400084cc | command loop | 1/5 | only diff = result-mux from DA1 handoff (magic-checked) |
| 4 | FUN_40030364 | storage write pump | (part of 1) | CSEL min() clamp + same 2aa28 callback |
| 5 | FUN_400307a8 | envelope reader | (part of 1) | same callback, 0x40 bound |
| 6 | FUN_4000bad4 | preloader download engine | 2/5 | fall-through defect NEUTRALIZED by c3d4 memset; malloc from config; both scenarios exit |
| 7 | FUN_4000c764 | preloader HB builder | 2/5 | sizes from device cert/GPT; 3 mallocs 3 null checks; single free per path |
| 8 | FUN_40001504 | storage checksum examine | 2/5 | global cache (config-sized); CSEL min() clamp; device-side verify |
| 9 | FUN_40002818 | download-partition | 2/5 | covered by closed callees |
| 10 | FUN_400030ec | partition download | 2/5 | covered by closed callees |
| 11 | FUN_40003c38 | partition erase | 2/5 | two-stage 64-bit bounds, overflow-proof; auth pre-erase |

### Verdict

**No candidate ≥ 3/5 in the entire OPLUS-added/modified queue.**
All 20 OPLUS-unique functions from the 3-way diff were either directly audited (11 above),
already-audited skips (2afd8, mxml, escape, malloc wrapper, oplus/cust verify), or covered
by closed callees. The DA2 command surface on 2710EX01 is, by this audit, watertight on:

- the copy/download paths (clamp + callback-refusal, doubly closed),
- the XML/scatter parse paths (bounded growth, bounded copies, count guards),
- the erase path (overflow-proof two-stage bounds),
- preloader write (sig+hash+version checks, clean lifecycle),
- the checksum layer (config-sized cache, internal loop sizes only).

### Honest probability the vector is elsewhere

**[Update 2026-10-25, late — the list below was written before the DA1 and
preloader audits. Both are now DONE and CLOSED: see `DA1_AUDIT.md` and
`PRELOADER_AUDIT.md`. DA1: 11/11 commands, 0 candidates ≥2/5. Preloader:
usbdl map + whitelist + genuine RSA-PSS verify. The remaining surface is
TEE/tbase only.]**

**HIGH (~85-90%).** This audit covered the XML-command surface of DA2 exhaustively.
Remaining untested surfaces, in order of promise:

1. **DA1 (the stage-1 loader)** — 0x69424 bytes, NEVER audited in this project. It parses
   its own host commands before DA2 runs (COM ports, boot params). If a vector exists
   below the DA2 XML layer, it is here. NOTE: DAA gates loading DA1 itself — the attack
   would be IN DA1's protocol handling after boot, reachable once DA1 runs. **[DONE — closed]**
2. **Preloader (boot ROM stage)** — entirely outside this project's binaries. **[DONE — closed]**

### Bottom line for the record

fp_read_host_file was closed by OPLUS (clamp + callback refusal). This audit closes the
rest of the DA2 XML attack surface. The documented anti-downgrade (0x7024) closes the
old-DA route. Within the audited surface, the only real defects found (bad4 fall-through,
07fb0 no-NUL walk) are neutralized by callers/init state and shared with all builds —
neither is a 2710EX01-specific exploitable path.

**Queue exhausted. Recommended next target if the campaign ever reopens: DA1.**
