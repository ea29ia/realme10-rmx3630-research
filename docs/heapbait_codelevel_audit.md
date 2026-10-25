# Heapbait code-level audit — DA2_extracted.bin (2710EX01) — static, read-only, Ghidra

> Date: 2026-10-24 · Tool: Ghidra 12.1 (PyGhidra, headless) on the pre-existing project
> `research/da_offline_analysis/GhidraProj/DA2proj` (program `/DA2_extracted.bin`, 951 functions, pre-analyzed).
> Binary: `research/da_offline_analysis/DA2_extracted.bin` (358,160 B, DA2 of DA_BR.bin 2710EX01, sha256 f95f2b82...de47).
> No device contact. No file modification. Scripts: `heapbait_ghidra_audit{,2,3,4}.py`; raw outputs `heapbait_ghidra_out{,2,3,4}.md`.

## Question

Is the heapbait heap-overflow vulnerability in OUR DA2 actually fixed at code level, or was only
the `"Dest XML file name buffer overflow"` string added as a cosmetic marker (tripping
`heapbait.is_vulnerable()`) while the real logic stayed vulnerable?

Two independent primitives must both exist for heapbait to work:
1. **No bounds/length validation** tying the incoming transfer size to the destination buffer's
   allocated size before/during the copy (so a 0x1410-byte send into a 0x1400-byte buffer overflows).
2. **Heap-chunk header magic (0x68656170 `'heap'`) written but never validated in free()** —
   a corrupted neighbor chunk header is not caught on deallocation.

## Findings

### A) fp_read_host_file = FUN_4002afd8 @ 0x4002afd8 (identity confirmed by its own error strings)

Strings compiled into it: `s_Download host file: %s_4004e1f1`, `s_ReadHostFile: %s_4004e212`,
**`s_fp_read_host_file buffer is too s_4004e224`** (= the xref'd symbol string), `s_fp_read_host_file malloc fail_4004e24c`.

Decompiled control flow (abridged, addresses from Ghidra):

```
uVar7 = thunk_FUN_4000ace8(local_48c);            // FILE-SIZE parsed from host (hex)
if (*param_3 != 0 && uVar3 != 0) {                // CASE 1: caller supplied a buffer
    if (uVar7 < uVar3) { *param_4 = uVar7; goto copy; }   // fits -> OK
    else -> "buffer is too small" -> error 0xc0010001     // oversized -> REFUSED
} else {                                          // CASE 2: no buffer -> allocate
    *param_4 = uVar7;
    *param_3 = FUN_4000a390(uVar7 + 4);           // malloc(size + 4)  ← +4 ONLY
    if (*param_3 != 0) FUN_4000b2c8(buf, 0, uVar7 + 4);   // memset
}
copy loop (LAB_4002b250):
    do {
        read = min(remaining, uVar1);             // uVar1 = _DAT_4006819c (packet max, 0x200000/0x2000-class)
        (*(code *)*param_1)(buf + done, &read);   // USB read callback (indirect!)
        done += actual;
    } while (done < uVar7);
*(buf + uVar7) = 0;
```

**Bounds check status:**
- CASE 1 (caller-provided buffer): a REAL bounds check exists — `uVar7 < uVar3` else refuse
  (string proves it's compiled in). This is NOT the path heapbait uses.
- CASE 2 (allocate path — the heapbait path): allocation is `malloc(size + 4)`. The +4 cannot
  absorb a 12-byte chunk header (magic/ptr/size at `piVar4[-3..-1]`, written by malloc
  FUN_40008b10), and the header of the NEXT chunk sits immediately after `buf + size`.
- The per-chunk clamp is `min(remaining, uVar1)` where `uVar1 = _DAT_4006819c` is the
  **packet/transfer max** (set 0x200000 by FUN_4002f66c; USB chunking class 0x2000), **NOT**
  `min(remaining, allocated)`. There is no clamp tying the copy to the allocated size.
- The read is an INDIRECT call `(*(code *)*param_1)(buf+done, &read)` — the final USB-side
  handler is resolved at runtime; per ea29ia's runtime notes, this callback honors
  `packet_length` over the requested length (the documented 0x2000-vs-0x1400 overflow). Static
  closure of that single indirect call was not completed in this pass, but nothing in
  fp_read_host_file itself re-validates the count returned: `done += actual` accumulates
  whatever the callback reports, and no check compares it against the allocation.
- **There is NO total-size-vs-allocated clamp anywhere in the copy loop.** Structure matches
  the documented unpatched behavior exactly.

### B) Heap allocator (LK-style miniheap)

- **malloc = FUN_40008b10 @ 0x40008b10.** Chunk layout returned to caller: header lives
  immediately BELOW the returned pointer — `piVar4[-3] = 0x68656170` (magic),
  `piVar4[-2] = chunk ptr`, `piVar4[-1] = size`. The magic write is the ONLY
  `0x68656170` constructor in the whole binary: single movw/movt pair at **0x40008c44**
  (movw imm16=0x6170, movt imm16=0x6865) inside FUN_40008b10. Raw 32-bit word 0x68656170:
  ZERO occurrences elsewhere in the file.
- **free = FUN_40008cdc @ 0x40008cdc** (thunk_FUN_40008cdc call sites in error paths confirm
  it's the deallocator; FUN_4000a390 = malloc wrapper, FUN_40008cdc = free wrapper).
  Decompiled free:
  ```
  size = *(p - 4); chunk = *(p - 8);
  *(chunk + 8) = size;            // restore free-list size
  FUN_40008d74(chunk);            // insert + coalesce with neighbors
  ```
  **NO comparison against 0x68656170 anywhere. No magic read. No integrity check.**
- Exhaustive decompiled-body scan across all 951 functions: `0x68656170` appears in exactly
  ONE function — FUN_40008b10 (the malloc write). The magic is written once and never read.

### C) The marker string

`"Dest XML file name buffer overflow"` — single occurrence @ DA2 offset 0x4e0a3
(VA 0x4004e0a3), inside the error-string cluster; **no live xref** (earlier pass: no
literal-pool entry, no Thumb ADR hit; the single 32-bit byte-pattern hit decodes as
mid-instruction coincidence). It is an orphaned diagnostic string. `heapbait.is_vulnerable()`
does a plain `in` substring check — presence alone blocks the exploit, regardless of live code.

## Verdict

**W1 — the vulnerability is NOT fixed at code level; the marker string is cosmetic.**

| Check | Result | Evidence |
|---|---|---|
| Bounds: caller-buffer path | present (irrelevant to heapbait) | `uVar7 < uVar3` else refuse, FUN_4002afd8 |
| Bounds: allocate path (heapbait's) | **ABSENT** — `malloc(size+4)`, clamp is vs packet max (0x2000-class), no clamp vs allocation, no validation of callback's actual count | FUN_4002afd8 copy loop |
| Magic integrity in free() | **ABSENT** — magic written once in malloc (0x40008c44), never read/compared; free (0x40008cdc) reads size+chunk ptr only | FUN_40008b10 / FUN_40008cdc / 951-function scan |

Both primitives heapbait needs are intact in our 2710EX01 DA2. The NAK 0xc0010001 we observed
is caused solely by `heapbait.is_vulnerable()` refusing to run on the orphaned marker string —
a client-side refusal in mtkclient, not a device-side protection.

**Caveat (honest boundary of static analysis):** the final copy is an indirect call; the
claim "callback honors packet_length over requested length" comes from ea29ia's runtime
documentation, cross-checked here only structurally. If he ever doubts W1, the one decisive
runtime bit is whether the USB read callback in our build clamps to `local_484` — a one-line
debug print on his side would settle it. For our purposes, W1 stands: nothing in OUR binary
implements a fix.

## Implication (for the ea29ia thread)

A client-side override (`OPLUS_FORCE_HEAPBAIT=1`-style, ~3 lines in mtkclient) would restore
the exploit attempt on our unit. The exploit would then either work (W1 confirmed at runtime)
or fail with a device-side error — which would itself be new, decisive information. No offline
or runtime action taken beyond this document; nothing was executed against the device.
