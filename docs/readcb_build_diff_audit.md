# Build-difference audit: the read-callback/loop shape in ea29ia's test DA vs our 2710EX01

> Date: 2026-10-24 night · Static PyGhidra (Ghidra 12.1 headless), read-only.
> Binary: ea29ia's tree test DA `Library/Exploit/test/DA_BR.bin` (882,704 B,
> sha256 c4201a85...473a) — byte-identical to UPSTREAM bkerler's test DA (verified),
> i.e. a GENERIC (non-OPLUS) MTK DA. DA2 extracted: file 0x865FC len 0x51214
> (332,308 B), mem base 0x40000000, sha256 e20cf2a5...dea9.
> Project: research/ea29ia_da2_analysis/DA2proj_ea29ia (ARM:LE:32:v7, BinaryLoader).
> No device contact. No modification of any project file outside this new analysis dir.

## 1) What this binary is (and is not)

- It is NOT ea29ia's own 200EX01 device DA — it is the upstream test vector shipped
  in every mtkclient clone (hash match with our 20/10 upstream clone).
- No OPLUS strings (`oplus_version`, `Server is not authenticated`, … are absent);
  it carries the generic MTK command set (`ReadHostFile`, `Download host file`,
  `Host notice error`, `DA.SLA`).
- Its value: it shows what the GENERIC MTK fp_read_host_file looks like — the
  baseline OPLUS forked from.

## 2) fp_read_host_file — GENERIC build (FUN_40025490 @ 0x40025490)

Structure identical to ours: strnlen(name, 0x200) → XML-escape (0x200 buffer,
cached at _DAT_40067a60) → snprintf the DOWNLOAD-FILE request → OK handshake →
FILE-SIZE parse → malloc(size+4) → copy loop.

The copy loop (the decisive part):

```c
iVar1 = _DAT_400611fc;               // packet max (0x200000-class)
...
local_484 = iVar1;                   // request = FULL packet max, UNCLAMPED
iVar8 = (*read)(iVar4 + uVar2, &local_484);
uVar2 = local_484 + uVar2;           // done += actual
} while (uVar2 != uVar6);            // terminate on EXACT equality with size
*(iVar4 + uVar6) = 0;
```

- The per-iteration request is the packet max WITHOUT clamping to the remaining
  budget — the last read necessarily asks for more than remains.
- Termination is exact-equality (`!=`), not `>=`: the loop tolerates the callback
  returning a full packet on the final iteration, so the over-read lands in the
  buffer tail and past it.
- Same strnlen(0x200) filename truncation as ours (so the trigger-side truncation
  is generic; his filenames ≤ 512 too).

## 3) fp_read_host_file — OUR 2710EX01 build (FUN_4002afd8, for contrast)

```c
local_484 = uVar7 - uVar3;                     // request = REMAINING
if (uVar1 <= uVar7 - uVar3) local_484 = uVar1; // clamp to packet max
...
} while (uVar3 < uVar7);                       // terminate on >= size
```

- Request is clamped to the remaining budget every iteration → over-delivery is
  never even requested; our read callback additionally REFUSES packets larger than
  the request (0xc0010006, stage3_mechanism_audit.md §3).
- Termination `>=` instead of `!=`.

## 4) Verdict

**The build difference is real, structural, and located:** heapbait's over-delivery
primitive requires the GENERIC loop shape (unclamped request + exact-equality
termination). OPLUS's 2710EX01 fork replaced both:

| Property | GENERIC (ea29ia/upstream test DA) | OUR 2710EX01 (OPLUS fork) |
|---|---|---|
| Loop request | full packet max, unclamped | min(remaining, packet max) |
| Termination | `done != size` (exact) | `done < size` (>=) |
| Callback on oversized packet | reads it (over-delivery) | refuses 0xc0010006 |
| Escape buffer | 0x200, cached | 0xC00, cached (bigger but irrelevant — input still ≤512) |
| strnlen filename cap | 0x200 | 0x200 (same) |

Caveat (honest): this proves the DIFFERENCE EXISTS between the generic baseline and
our unit's DA. It does not yet prove ea29ia's own 200EX01 DA has the generic shape —
his device DA is a different file we still haven't seen. But since heapbait works on
his unit, his DA must preserve the generic loop shape (or an equivalent primitive);
the OPLUS fork is the variant that broke it.

## 5) Implications for the campaign

1. The #409 question to ea29ia can now be sharper: not "does your callback
   over-deliver?" but "your 200EX01 DA must have the GENERIC copy loop (unclamped
   request, `!=` termination) — our OPLUS 2710EX01 fork clamps the request to
   remaining and the callback refuses oversized packets (0xc0010006). Confirm on
   your build."
2. No re-derivation of heapbait can fix 2710EX01 through this path: the clamp +
   refusal are both present; the overflow primitive is doubly closed.
3. Any future vector hunt on 2710EX01 must look OUTSIDE fp_read_host_file (the mxml
   parser was already audited clean — mxml_parser_audit.md).

## 6) Artifacts

- ea29ia_readcb_audit_out.md — full decompile of FUN_40025490 + callees
- DA2proj_ea29ia — importable Ghidra project (ARM:LE:32:v7, base 0x40000000)
- This note.
