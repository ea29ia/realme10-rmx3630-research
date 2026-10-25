# Stage-3 mechanism audit — the escape-cap theory is WRONG; the real blockers are
# the USB read callback's length gate + the b600 512-char truncation (read-only, our build)

> Date: 2026-10-24 night · Static: PyGhidra on the existing DA2proj (Ghidra 12.1, headless).
> Scripts: escape_caller_audit.py (+2/3/4), usb_read_audit.py (+2/3/4) — outputs *_out.md alongside.
> Companion: heapbait_codelevel_audit_2710EX01.md, log continued 72-73.

## 1) Caller identification (task 1 — DONE, definitive)

The stage-3 route fires through **FUN_4002afd8 (fp_read_host_file)** — proven by two facts:

- The trace's stage-3 print `Download host file:%s` (0x4004e1f1) has EXACTLY ONE xref:
  0x4002b010 inside FUN_4002afd8 (Ghidra reference scan, escape_caller_audit_out.md §xrefs).
- The ALLINONE-SIGNATURE handler FUN_4000695c calls FUN_4002afd8 directly with the
  parsed source_file (decompiled, heapbait_ghidra_out.md §2).

The other 5 callers of the escape function (0x40007b8c, 0x4002ae50, 0x4002b378,
0x4002b49c, 0x4002b9e0) belong to the DOWNLOAD-FILE/UPLOAD-FILE/FILE-SYS-OPERATION
device→host request family — none is on our stage-3 path. FUN_4002ae50
(`Download [%s] with file:%s`) is a DIFFERENT print that never appeared in our trace.

## 2) The escape-cap theory is DISPROVEN (mechanism correction)

log continued 72 claimed: escaped length > 0xBFA trips `Dest XML file name buffer
overflow` at the escape function 0x4002ac9c. The decompile of the caller shows the
escape input is NOT the raw filename:

```c
uVar4 = FUN_4000b600(param_2, 0x200);   // FUN_4000b600 = BOUNDED strlen (decompiled:
uVar4 = FUN_4002ac9c(param_2, uVar4);   //   walks at most param_2 chars to find NUL)
```

- **FUN_4000b600(src, n) = strnlen(src, n)** — verified from its own decompile
  (usb path audit 2, first entry). It returns ≤ 0x200 = 512 always.
- A filename of 'A'*4200 enters the escape function as **512 chars** (truncated scan
  length), escapes 1:1 (A needs no escaping), so the escaped output is 512 bytes —
  2.5KB BELOW the 0xBFA cap. The cap is untrippable from this caller.
- Consistent with the trace: `'Dest XML file name buffer overflow'` never printed;
  the failure message was `'USB error or buffer is too small to contain all data.'`
  (0x4004e006), which is `DAT_400566d0` — the default error pointer in
  fp_read_host_file's USB-read error path (byte-verified in .data).

## 3) THE REAL STAGE-3 BLOCKER: the USB read callback's length gate

The IO chain (byte-exact, from .data pointers + decompiles):

```
fp_read_host_file copy loop  →  read cb @0x40007ea4 (thunk)  →  FUN_4002aa28 (real)
FUN_4002aa28:
    read 12-byte envelope header via DAT_40054a60(hdr, 0xc)
    if hdr.word1 != 0xFEEEEEEEF          → 0xc0010005 (sync loss)
    if requested < hdr.word3             → 0xc0010006  ← THE GATE
    else: *requested = hdr.word3 (clamp down); read payload
```

- 0xFEEEEEEEF matches mtkclient's `MAGIC = 0xFEEEEEEF` (xml_cmd.py:15) — envelope confirmed.
- word3 = the payload length the HOST declared in its packet header (xsend writes
  `pack('<III', MAGIC, datatype, length)` — the true payload size).

**Consequence: the callback refuses to over-deliver.** The documented heapbait
mechanism (USB callback honors packet_length over the requested remainder) does NOT
exist on 2710EX01. On the first payload read:

- request = remaining = 0x13FC (advertised FILE-SIZE)
- host packet payload = 0x140C (USB_DATA_SIZE 0x1400 + 12 pointer bytes)
- 0x13FC < 0x140C → **0xc0010006 → the exact trace failure at line 2334.**

Even a request ≥ packet size cannot overflow: the loop's total accepted bytes ≤
advertised, and the allocation is `malloc(advertised + 4)` whose usable space is
`round_up(advertised+16, 4) ≥ advertised + 4`. **fp_read_host_file is watertight
against this overflow on our build.** The exploit's core primitive is absent here.

## 4) The 60KB trigger also cannot work (secondary confirmation)

The trigger command (`filename='A'*60000`) parses fine as XML, but the extracted
filename then hits the same `strnlen(name, 512)` in fp_read_host_file → the DA2's
own DOWNLOAD-FILE request to the host carries a **512A filename** → the host has no
such MEM:// source → the exchange collapses before any heap shaping. The trigger's
parse never grew past 5132 in the trace because the command's XML text buffer is
capped by the parse chain's growth law, and the 60KB name itself never re-entered
any device-side buffer.

## 5) Fallback evaluation (task 3): the 0xC00 escape buffer as target node

The escape buffer (0xC00, cached at [0x4006e95c], persistent) IS a live heap
allocation — but it is allocated with `FUN_4000a390(0xc00)` from the same first-fit
free list, meaning:

- It is reachable only via a successful heap corruption — which task 3 of this audit
  shows cannot happen through fp_read_host_file on this build.
- No other reachable path writes attacker-controlled bytes past an allocation.

Verdict: the fallback is moot while the only overflow primitive is closed.

## 6) Where this leaves the campaign (honest)

| Mechanism | Status on 2710EX01 |
|---|---|
| XML-escape 0xBFA cap blocks payload | **FALSE** — input truncated at 512 first |
| stage-3 fails via over-delivery overflow | **FALSE** — callback returns 0xc0010006 |
| stage-3 fails via buffer-too-small (real meaning) | **TRUE** — request < packet length |
| 60KB trigger shapes the heap | **FALSE** — 512-char truncation upstream |
| fp_read_host_file overflow (heapbait core) | **CLOSED** — watertight on this build |
| mxml/parse-side overflow (NOT yet audited) | **OPEN** — only remaining candidate class |

The only un-audited allocation surface left is the mxml parse path itself (the
140→…→5132 realloc chain) and FUN_400020ac's attribute handling. heapbait-as-published
cannot work here; a different vector (or a build-specific bug in the parser) would be
required. That reframes the #409 question for ea29ia: on 200EX01, does his read
callback really over-deliver (returns packet_length > request without error)? His
build must differ at FUN_4002aa28's `if (requested < hdr.word3)` check.

## 7) Verifiable artifacts

- escape_caller_audit_out.md — all 6 escape callers decompiled + string xrefs + caller map
- escape_caller_audit2_out.md — FUN_4000b600 (strnlen), ALLINONE handler, registrars
- usb_read_audit2/3_out.md — read/write callbacks + the 0xc0010006 gate
- .data byte checks: DAT_400566d0 → 0x4004e006 ("USB error..."), DAT_40054a48/4c
  → thunk targets, envelope magic 0xFEEEEEEEF ↔ mtkclient MAGIC
- Geometry math: stage3_geometry.py (advertised 0x13FC → malloc 0x1400 → chunk 0x140C)

No device contact. No file modification. All findings static.
