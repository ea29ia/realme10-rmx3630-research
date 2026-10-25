# get_node semantics audit — the malloc-core substitution was WRONG (and here's the correct fix)

> Date: 2026-10-24 · Read-only static analysis (Ghidra outputs + payload disassembly + capstone).
> Companion to: `heapbait_codelevel_audit_2710EX01.md`, `stream_reader_failure_analysis.md`, log continued 23/29.

## Question

We substituted `get_node := FUN_40008b10` (malloc core) in the get_node fallback. Did that
substitution change the calling semantics the shellcode assumes — enough to break the
DPC hijack and explain the GETBAITED failure?

## Answer: YES — the substitution has a real signature bug. Found the correct substitute.

### 1) The true signature of FUN_40008b10 (from the Ghidra decompile)

```
int * FUN_40008b10(int param_1, uint param_2)
{
  if ((param_2 & param_2 - 1) == 0) {        // param_2 MUST be a power of 2 (or 0)
      uVar7 = param_2;
      if (param_2 < 0x11) uVar7 = 0x10;      // alignment floor = 16
      uVar6 = param_1 + 0xc;                 // raw size + 12-byte header
      if (param_2 == 0) uVar7 = param_2;     // alignment 0 => natural (4B)
      ...
      uVar6 = (uVar6 + 3 & 0xfffffffc) + uVar7;   // chunk size = align(size+12) + alignment
      ...
      piVar4[-3] = 0x68656170; ...           // header write, return chunk+12 aligned to param_2
```

**True signature: `FUN_40008b10(size /*r0*/, alignment /*r1, power-of-2 or 0*/)`.**
My earlier reading ("r0=alignment, r1=size") was inverted; the wrapper proves it:

### 2) The wrapper settles it

`FUN_4000a390` (entry 0x4000a390): `FUN_40008b10(param_1, 0)` — called everywhere as
**malloc(size)** (e.g. `fp_read_host_file`: `FUN_4000a390(uVar7 + 4)`).
⇒ r0 = size, r1 = alignment (0 = natural). The wrapper guarantees r1 = 0.

### 3) The bug in our substitution

The shellcode calls `get_node` with the classic **`get_node(size)`** convention (r0 = size).
With our substitution, r1 = **whatever leftover value the shellcode has in r1**:
- r1 = 0 or any power of 2 → allocation works (accidentally correct),
- r1 = anything else (garbage — the common case) → the outer power-of-2 check FAILS →
  **returns NULL** → the shellcode's node allocation fails silently → DPC hijack chain
  never completes → **GETBAITED never answered with "ERR"**.

This is exactly the observed failure: Stage 2/3 load fine (host-side), then the probe dies.
The failure is DETERMINISTIC per shellcode code path (r1's leftover value), consistent with
our identical logs across runs.

### 4) The correct substitute (statically proven, same dynamic derivation style)

**`get_node := FUN_4000a390` (the malloc WRAPPER, VA 0x4000a390).**
- Signature: `wrapper(size)` — exactly the shellcode's assumed `get_node(size)` convention.
- The wrapper itself sets r1 = 0 before calling the core — no garbage dependency.
- Semantics: allocate a chunk of `size` bytes from the same free list with the same header
  layout (the shellcode's node math stays valid).
- Dynamic derivation (no hardcoding): find the malloc core via the 0x68656170 writer
  (as we already do), then find the function containing a `BL` targeting the core whose
  body is the tiny `(*, 0)` wrapper — or equivalently, scan for `BL <core>` and take the
  caller function with the smallest footprint. Fallback: `OPLUS_GET_NODE_ADDR` env override
  (already supported) can pin `0x4000a390` directly for our build.

### 5) Impact assessment

- The Stage 2/3 phases load fine because they are HOST-side mechanics (upload + overflow
  write); the get_node value only matters when the shellcode EXECUTES and allocates.
- With the buggy substitute, the shellcode (if it even executed) died at its first node
  allocation with a NULL return — matching "probe never gets ERR" even if the DPC jump
  itself landed.
- With the wrapper substitute, the shellcode's allocation path becomes correct; GETBAITED
  should answer — **this is the strongest single explanation for the GETBAITED failure
  discovered so far, and it's fully offline-verified at the signature level.**

### 6) Honest caveats

- "get_node(size)" as the shellcode's convention is inferred from upstream heapbait's
  design (node allocation during command processing) — the actual call sites inside the
  binary payload are position-independent and were not fully traced (the table is consumed
  via runtime-computed bases). The signature MISMATCH, however, is proven: whatever the
  shellcode passes in r1, the core requires pow-2-or-0, and only the wrapper guarantees it.
- The DPC jump itself may ALSO have issues (heap layout class) — the wrapper fix removes
  one failure layer; the next live attempt (new config) is the test.

## Recommended change (for the next deployment round)

In `find_get_node`'s fallback: replace `get_node := malloc core` with
`get_node := malloc-wrapper (caller of the core with signature (size, 0))` —
derive dynamically via `BL <core>` scan; keep `OPLUS_GET_NODE_ADDR` override.
Our build's concrete value: **0x4000a390**.
