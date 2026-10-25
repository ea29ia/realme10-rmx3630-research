# mxml parser audit — the XML command parser's realloc/growth chain (read-only, our build)

> Date: 2026-10-24 night · Static: PyGhidra on the existing DA2proj (Ghidra 12.1, headless) +
> instruction-level disasm (capstone-equivalent via Ghidra listing).
> Scripts: mxml_audit1/2/3.py — outputs mxml_audit{1,2,3}_out.md alongside.
> Companion: stage3_mechanism_audit.md (fp_read_host_file = watertight), log continued 74-75.
> No device contact. No file modification. Pure static.

## 1) Parser entry point (task 1 — located from known anchors)

The command loop **FUN_400084cc** (audited in usb_read_audit_out.md) reads the host
command XML into the 0x80000 command buffer (`_DAT_4006a610`, memset 0 every
iteration) and calls **FUN_4000cfec(0, xml_text, &DAT_4000ed18)** — the mxml-style
parser. Confirmed by its structure: tokenizer FUN_4000e278 (char source with BOM +
UTF-8/UTF-16 handling), entity decoder FUN_4000e5c4 (`&#x…;`/named entities),
string-growth helper FUN_4000e790, element/attribute walkers, and the mxml error
strings ("Unable to allocate string buffer", "Bare < in element", "Early EOF in
CDATA node", "Duplicate attribute", …).

`FUN_400020ac` (the attribute extractor used by command handlers) is a thin lookup:
node child by name → text value. No parsing of its own.

## 2) The realloc chain (task 2 — identified and decompiled)

All text growth goes through ONE helper: **FUN_4000e790(ch, &cur, &base, &alloc)**
— called by the parser for element text, attribute names, and attribute values
(the parser's local buffers start at 0x40 via FUN_4000a390).

Growth condition (instruction-verified, 0x4000e7a0-0x4000e7c0):

```asm
r2 = alloc; r0 = base; r3 = cur
r1 = base + alloc - 4
cmp cur, r1
bcc no_grow            ; unsigned: grow only when cur >= base+alloc-4
```

Growth law (0x4000e7c4-0x4000e7d0):

```asm
r1 = alloc + 0x400
cmp alloc, 0x400
movlt r1, alloc, lsl 1 ; if alloc < 0x400: r1 = alloc*2
str r1, [r7]           ; *alloc = new
```

The realloc call (0x4000e7d4): `bl 0x4000a3e8` → B-thunk → **FUN_40008c70** =
realloc(old_base, new_size). Instruction-level, r0 = old base (loaded 0x4000e7a8,
untouched before the BL) and r1 = new size (set in the growth-law chain). The
decompiler's argument-less call was cosmetic. Cursor is repositioned by delta
(new_base + (cur − old_base)) — correct.

**The chain matches the device trace EXACTLY** (allocs 0x40→…, chunk =
round_up(alloc+12,4)): 76, 140, 268, 524, 1036, 2060, 3084, 4108, **5132** —
identical to the measured 140→268→…→5132 sequence from the logprobe run. The
final 4200A text buffer = alloc 0x1400, chunk 5132, usable 0x1400. Same helper,
same law, no separate path.

## 3) Bounds analysis of each growth step (task 3)

**(a) Integer overflow in the size computation:** none reachable. alloc starts at
0x40; doubling occurs only while alloc < 0x400 (max new = 0x200·2 = 0x400, no
overflow); afterwards linear +0x400. The only way to reach a 32-bit overflow is an
allocation above 2^30 bytes — malloc (FUN_40008b10) would fail first (no chunk that
large in the DA2 heap), returning 0 → the helper's error path (0x4000e864: free +
"Unable to expand string buffer to 0x%x" + abort). No overflow window.

**(b) Copy bound in realloc:** FUN_40008c70 copies `min(new, [old_base−4])` where
`[old_base−4]` is the OLD chunk's stored chunk_total (written by malloc at carve
time). chunk_total ≥ alloc always → the copy never reads past the old chunk's
boundary (any tail read stays INSIDE the allocated chunk). Then free(old). Safe.

**(c) Length cap before parsing:** there is no per-attribute length check, but the
INPUT itself is capped twice upstream: the command-loop read is a single envelope
read with requested = 0x80000 (the read callback refuses any packet whose payload
exceeds the request — the same 0xc0010006 gate proven in stage3_mechanism_audit.md),
and the 0x80000 buffer is memset-0 before every read, so the parser's NUL-
terminated input is ≤ 0x80000−1 bytes. Worst-case allocation ≈ 0x80000-class
(1:1 ASCII) — comfortably within the heap.

**Write margin (the critical invariant):** growth triggers when remaining space
drops below 4 bytes; the maximum single write is a 4-byte UTF-8 sequence. The
trailing NUL (*cur = 0) also fits inside that margin. Edge check: alloc ≥ 0x40
always → `base + alloc − 4` cannot underflow the unsigned comparison.

**Entity decoder (FUN_4000e5c4):** builds the entity name in `local_64[64]` with an
explicit bound (`local_64 + 0x3f <= pcVar6 → break` + "Entity name too long"
error). `&#…;` numeric values are parsed with strtol-style base 10/16; values
> 0x7fffffff for named entities are rejected. No bound bypass: even a huge numeric
entity (e.g. `&#x7fffffff;`) becomes a 4-byte write in the growth helper (the
strb chain truncates to bytes) — still inside the 4-byte margin.

**UTF-16 surrogate/UTF-8 validation (FUN_4000e278):** malformed sequences return
0xffffffff (parse abort); overlong encodings rejected. No write path affected.

## 4) Reachability with attacker-controlled data BEFORE fp_read_host_file (task 4)

Yes — structurally the parse is the FIRST thing that happens to attacker data:
command loop envelope-read (≤ 0x80000) → **FUN_4000cfec parse** (grows buffers from
attacker-controlled XML, all attribute values) → dispatch → handler (e.g. the
ALLINONE handler) → only then fp_read_host_file. A long XML attribute value
exercises the growth chain purely in the parse stage, independent of any
file-download mechanics.

But per §3, exercising it is safe: every growth step is bounded, the margin equals
the maximum write, and the input itself is envelope-capped at 0x80000.

## 5) Verdict (task 5)

**SAFE — no plausible overflow in the mxml parse path on 2710EX01.**

- Growth helper: margin-4 growth, max-write-4 invariant, correct realloc args,
  bounded copy, overflow-free size law, failure path frees + aborts. 
- Entity decoder: hard 63-char name bound; numeric entities cannot expand beyond
  4 UTF-8 bytes.
- Input: single-envelope 0x80000 cap + memset + NUL termination.
- The measured trace law (76→…→5132) matches this helper exactly — the audited
  code IS the observed chain; no hidden second path.

The one structural caveat: this audit covers FUN_4000cfec's own growth logic and
its direct helpers. It does NOT re-audit the node-allocation paths
(FUN_4000eba4/FUN_4000cda4 node/attribute allocators — fixed-size 0x40 nodes in
the decompile) beyond confirming they use the same malloc/free pair with no
attacker-sized single allocation. If a future vector hunt continues, node-linkage
integrity (not buffer bounds) would be the next place to look — but nothing in
this audit suggests a defect there.

## 6) Summary table

| Surface | Check | Result |
|---|---|---|
| Growth size law (e790) | doubling <0x400 then +0x400; no overflow window (malloc fails first) | SAFE |
| Realloc copy (FUN_40008c70) | min(new, old chunk_total), never past old chunk | SAFE |
| Write margin vs UTF-8 write | margin exactly 4B = max 4B write; NUL inside margin | SAFE |
| Unsigned edge (base+alloc−4) | alloc ≥ 0x40 always → no underflow | SAFE |
| Entity name buffer (e5c4) | hard 63-char bound + error | SAFE |
| Numeric entity magnitude | truncates to ≤4-byte UTF-8 write in e790 | SAFE |
| Input cap before parse | envelope gate (request 0x80000, cb refuses larger) + memset | SAFE |
| Cursor reposition after realloc | delta-correct (instruction-verified) | SAFE |
| Node/attribute allocators | fixed 0x40 nodes, same malloc/free | SAFE (no attacker-sized alloc) |

**Campaign consequence:** with fp_read_host_file (stage3_mechanism_audit.md) and now
the mxml growth chain both bounds-safe on 2710EX01, the two attacker-reachable
allocation surfaces in the command path are audited clean. heapbait's vector class
(over-delivery overflow) is absent on this build, and no replacement bug surfaced
in the parser. Next decisive step remains the #409 question to ea29ia (does his
200EX01 callback over-deliver?).
