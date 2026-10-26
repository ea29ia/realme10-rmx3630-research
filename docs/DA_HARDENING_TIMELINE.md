# MT6789 DA hardening timeline (public `DA_BR` corpus)

Status: **verified by disassembly**, not by byte-pattern heuristics. Every verdict below is
backed by the instructions that decide it. Intended as an appendix to `DA2_AUDIT.md` /
`DA1_AUDIT.md` and to `bkerler/mtkclient#409`.

## Why this exists

The #409 thread compared exactly two builds (2710EX01 vs 200EX01) plus a generic DA, and
therefore could not say *when* each mitigation landed, nor which part of the "transport fix"
was one change vs several. Eleven public MT6789 builds, ordered by their own `MTK_DA_v6`
timestamp, answer both questions.

Corpus: `saidanimelek26/DA_mtk_FirehoseLoaders` (`Oppo_Realme_Oneplus_DA`, `DAfiles_from_hxru`,
and per-brand DA directories). Files are as-published; hashes below let anyone reproduce.

## Corpus and identity

| build (`MTK_DA_v6_...`) | file | sha256 (short) | DA1 len | DA2 len |
|---|---|---|---|---|
| 2022-12-12 19:57:10 | vivo.bin | `4ed58c17…` | 0x5F544 | 0x530C8 |
| 2023-03-14 20:05:39 | mt6789_realme.bin | `024d01b8…` | 0x64D58 | 0x548C0 |
| 2023-08-15 16:03:42 | xiaomi.bin | `df37fb80…` | 0x618A8 | 0x50E40 |
| 2023-09-11 18:11:07 | samsung.bin == SAMSUNG_TAB_A9_DA_MT6789.bin | `617fa2c7…` | 0x61B84 | 0x510A4 |
| 2023-09-28 19:00:45 | infinix0.bin | `cdd1ea53…` | 0x61EB8 | 0x55CD4 |
| 2024-03-07 13:40:31 | TB351F_MT6789.bin == lenovo.bin | `69b08bfd…` | 0x61A90 | 0x511F8 |
| **2024-09-02 22:21:09** | **200EX01 `DA_BR.bin` (control)** | `abee43e8…` | 0x689FC | 0x56FC8 |
| 2024-09-29 22:14:26 | infinix2.bin | `514c8bb2…` | 0x62D70 | 0x569FC |
| 2025-01-03 17:53:54 | oukitel.bin | `9815c803…` | 0x60374 | 0x51B50 |
| 2025-01-08 15:47:37 | infinix3.bin | `e76cae22…` | 0x63088 | 0x5721C |
| 2025-06-24 22:10:17 | doogee.bin | `b52138d4…` | 0x60624 | 0x52650 |
| **2025-12-09 (build stamp)** | **2710EX01 (control, raw stages)** | DA1 `6c49eba0…` / DA2 `f95f2b82…` | 0x69424¹ | 0x57710 |

¹ the 2710EX01 container declares **DA1 len `0x69424` (431,140 B) for this build** — larger than
the 200EX01 `0x689FC`. So the 431,140-byte file is the *whole* declared region, not "region plus
DA2 head": the trailing `0xA28` lives inside the region and holds DA1's own hash table
(`sha256(DA2[0:0x57610])` at region offset `0x692F4`), DA1's signature block (container `soff`
`0x693E0`, `sig_len 0x100`), and an `"ANY_MODEL"` string. DA2 starts immediately after, at
container `0x694E0`.

## Provenance of the 2710EX01 blobs (independently re-derived, no third party involved)

The vendor OTA zip is still served with `Accept-Ranges: bytes`, so the two members can be pulled
without downloading 16.8 GB:

```
https://rms01.realme.net/sw/RMX3630export_11_14.0.0.2710EX01_2025122619580180.zip
  size 16,785,417,673   Accept-Ranges: bytes
  CD @ 0x3E87B6FB0 (size 112,055)  → ZIP64 EOCD @ 0x3E87D2567
  IMAGES/download_agent/DA_BR.bin             789,488 B  sha256 2e15a832…
  IMAGES/MTK_AllInOne_DA.bin                  789,488 B  sha256 63980fa5…
  IMAGES/preloader_k6789v1_64.bin             391,380 B  sha256 677d1feb…
  IMAGES/all-in-one-signature.bin             102,128 B  sha256 9d55f474…
```

Results of this re-derivation:

* `DA_BR.bin` = `2e15a832b58e500505b785c1bb2817c77614b1c7475b2c84511015fa9e65d245` — identical to
  the hash reported in #151/#409 for the unit's own build; container version string is
  `MTK_DA_v6_2025-12-09 15:56:46 DA_05 KEY_…` (the firmware zip is dated 2025-12-26).
* Region table: DA1 `{buf 0xBC, len 0x69424, addr 0x200000, soff 0x693E0, sig 0x100}`,
  DA2 `{buf 0x694E0, len 0x57710, addr 0x40000000, soff 0xC0AF0, sig 0x100}`; entries [0] and [1]
  identical.
* Extracted region hashes equal the files published in #409: DA1 = `6c49eba0…6e20`,
  DA2 = `f95f2b82…de47`. The DA1/DA2 claims in the thread are therefore self-consistent.
* `preloader_k6789v1_64.bin` = `677d1feb…` — identical to the hash in the `probe_*` logs, so those
  logs really were produced against this firmware.
* `MTK_AllInOne_DA.bin` from the *same* zip is byte-identical to `DA_BR.bin` except for the two
  signature trailers: payloads equal for both stages, trailers `0/256` nonzero (AllInOne) vs
  `256/256` and `254/256` (DA_BR). The "zero-trailer AllInOne, signed DA_BR" pattern is therefore
  a property of the packaging, not of the 200EX01 export.
* `all-in-one-signature.bin` is **not** a DA signature: it starts with the MTK cert-section magic
  `0x58881688` (section `"aee"`), carries `0x58891689` entries, and contains neither DA trailer.

Container layout facts worth recording (uniform across all 14 containers): version string at
offset `0x20`; magic `0x22668899` at `0x64`; entry count (u16) at `0x7E`; 20-byte entries
`{buf,len,addr,soff,sig_len}` from `0x80`; **entries [0] and [1] are always byte-identical**
(so a v6 container holds two distinct images, not three); `soff + sig_len == buf + len` for all
entries; no gaps and no overlap between DA1 end and DA2 start.

## Method (reproducible, no pattern matching)

1. Parse the entry table; take DA1 (`addr 0x200000`) and DA2 (`addr 0x40000000`).
2. `cmd_boot_to`: find the ASCII `"CMD:BOOT-TO"`, resolve the `movw/movt` pair that materialises
   its VA, simulate to the `bl <registrar>` and take `r2` = handler. All 14 handlers start with
   `e92d4bf0 push {r4-r9,fp,lr}` and parse `da/arg/at_address`, `da/arg/jmp_address`,
   `da/arg/source_file`; the load address is `strtoul(jmp_address)`/`strtoul(at_address)`.
3. `fp_read_host_file`: find `"Download host file:%s"`, resolve its `movw/movt`, take the
   enclosing prologue. The receive request is the value stored to `[sp,#0x7c]` (note: `0x40` is
   stored to the same slot first, for the per-chunk status read — the second store is the data
   request).
4. Escape helper: the guard is `movw rX,#0xBFA` + `sub` + `cmp` + `bge`, reached from the
   `"Dest XML file name buffer overflow"` tripwire path, with `malloc(0xC00)`.

## Results

| build | boot_to handler | gate | exit test | fp_read_host_file | clamp | escape bound |
|---|---|---|---|---|---|---|
| 2022-12-12 | 0x200F38 | — | bne | 0x400273D0 | — | — |
| 2023-03-14 | 0x200FEC | — | bne | 0x400294A8 | — | — |
| 2023-08-15 | 0x200F38 | — | bne | 0x40027720 | — | — |
| 2023-09-11 | 0x200F38 | — | bne | 0x400276F0 | — | — |
| 2023-09-28 | 0x200F38 | — | bne | 0x400280C0 | — | — |
| 2024-03-07 | 0x200F38 | — | bne | 0x400279DC | — | — |
| **2024-09-02** | **0x201080** | **r4** | bne | 0x4002AE8C | — | — |
| 2024-09-29 | 0x200FC4 | r4 | bne | 0x40028684 | — | — |
| 2025-01-03 | 0x200FCC | r4 | blo | 0x40027BFC | **yes** | — |
| 2025-01-08 | 0x200FFC | r4 | blo | 0x40028BDC | yes | — |
| 2025-06-24 | 0x20100C | **r6** | bhi | 0x4002847C | yes | — |
| **2025-12-09** | **0x20112C** | **r6** | bhi | 0x4002AFD8 | yes | **yes** (`malloc 0xC00`) |

Gate (fixed form, 2710EX01 — the r6 build):

```
0x2011fc  e3560101  cmp   r6, #0x40000000     ; jmp_address
0x201200  e3a01401  mov   r1, #0x1000000
0x201204  03500101  cmpeq r0, #0x40000000     ; at_address
0x201208  e50b001c  str   r0, [fp, #-0x1c]
0x201210  0a00001a  beq   0x201280            ; only route to the transfer
```

Failure prints `"2nd DA address is invalid. reset.\n"` and returns `0xC0010001`; the transfer
block has exactly one incoming edge (that `beq`), so it is unreachable otherwise. 200EX01 uses
the same five instructions with `r4` (`e3540101` at `0x20113c`).

Vulnerable form (e.g. 2024-03-07) has no compare at all: `str r0,[fp,#-28]` followed by ten
straight-line instructions into `bl <2nd-DA download>`, and `jmp_address` is stored separately as
the post-hash jump target — both the staging address and the jump target are host-chosen.

Clamp (2710EX01):

```
0x4002b2f4  e59d1024  ldr  r1, [sp, #0x24]    ; packet_max
0x4002b2f8  e0490007  sub  r0, r9, r7         ; remaining = total - done
0x4002b300  e1500001  cmp  r0, r1
0x4002b304  21a00001  movcs r0, r1            ; min()
0x4002b30c  e58d007c  str  r0, [sp, #0x7c]
```

## The three changes are separate, and they are ordered

* **Carbonara gate**: last build without = **2024-03-07**; first with = **2024-09-02**.
  Window `(2024-03-07, 2024-09-02]`. Register form changes r4 → **r6** by 2025-06-24.
* **Receive clamp** (heapbait): last without = **2024-09-29**; first with = **2025-01-03**.
  Window `(2024-09-29, 2025-01-03]`. Coincides with the exit predicate changing from `bne`
  (equality) to `blo`/`bhi` (>=) — a *second* edit in the same loop.
* **Escape-helper bound** (`movw #0xBFA` + `malloc(0xC00)` + tripwire string): present **only** in
  the 2025-12-09 build in this corpus; the 2025-06-24 build is clamped but still `malloc(0x200)`
  with no bound. Window `(2025-06-24, 2025-12-09]`. This is a third, independent mitigation, not
  part of the clamp patch.

Consequence for #409: "the transport fix is a single clamp" is wrong. There are two edits in the
recv loop (clamp + exit predicate) and a separate, later escape-helper hardening. On 2710EX01 all
three are present.

## Pitfalls if you re-scan (these produced wrong answers during verification)

1. `movw #0xBFA` alone is not a reliable marker: in `vivo` (`0x4000af78`) and `infinix2`
   (`0x40032d28`) the pattern occurs as the low half of *string pointers* `0x40040BFA`
   (`"write cert file fail."`) and `0x40050BFA` (`"[%s] Misc group otp ver:"`). 2 false positives.
2. The exit predicate is **not** a signature: `bne` (unclamped era) → `blo` (2025-01) → `bhi`
   (2025-06 and 2710). A `bhi`-only scan misses two of the three clamped samples.
3. Two stores target `[sp,#0x7c]` in every build; the first (`0x40`) is the status read.
4. These are **A32** images: all string references are `movw/movt`. A Thumb sweep or an
   `ldr`-literal scan returns zero hits for target VAs (and the only raw dword equal to one
   target VA straddles two ARM instructions at file `0x2e512`).
5. A bare `cmp #0x40000000` word (`E3540101`) exists in **all** images inside the DA1 entry-stub
   range check (between `1a00003a bne` and `3a000038 bcc`), so a compare-word-only scanner marks
   every vulnerable image "patched". Only the adjacent pair `cmp rX,#0x40000000 ; mov r1,#0x1000000`
   is meaningful.
6. Register coverage of the pair differs: mtkclient `Tools/da_parser.py` covers r4 and r0;
   penumbra `carbonara.rs` covers r4 only (the r0 literal was dropped) and covers x23 (A64) and
   T32 r0. Neither covers r6, i.e. neither recognises the 2025-06-24 or 2710EX01 form; both
   still reach the right verdict only because the `"2nd DA address is invalid"` string is also
   present. A gate-only scanner without that string would call both vulnerable.
7. `DA1_6789_in.bin` (fixed, r4 form) and `DA1_6789_op.bin` (vulnerable) are raw stage-1 dumps
   without a container header — useful as extra baselines, but they carry no version string.

## Additional data points reported by the owner (2026-10-26; not independently re-verified here)

Device experiments on the 2710EX01 unit with DA_BR containers pulled from intermediate exports:
`1900EX01` (May 2025) → `0x7024`, `400EX01` (Jan 2025) → `0x7024`. Together with 200EX01 and
420EX01 that is every exploit-open generation refused, so **the DAA key material was rolled once,
before Jan 2025** — not per-OTA as we suspected earlier, and older than the exploit fixes.

DA2 side of the same exports: `400EX01`/`1900EX01` DA2s are still the vulnerable family (356,296 B,
no `"Dest XML"` tripwire, ~99.91 % byte-identical to the 200EX01 DA2 — only date/build strings and
the trailer differ); `2302EX01` (Oct 2025) already carries the tripwire at 358,160 B, the same size
as the 2710EX01 DA2. So **OPLUS's own DA2 hardening landed between May and Oct 2025**.

Important reading of the table above: the boundaries derived from this corpus are MTK's DA
generations *as repackaged by other OEMs* (an Oukitel DA of 2025-01-03 is already clamped), not an
OPLUS release calendar. OPLUS kept the older DA family in its exports until after 1900EX01 (May
2025). Do not use the boundary dates here to date an OPLUS build; use the per-build DA2 markers.

## Limits

Only eleven public builds. The DA corpus still has no MT6789 preloader, but the 2710EX01
preloader is now available from the vendor zip (see Provenance) — the DAA-key question is being
answered separately and does not depend on this table. The three boundaries are "between these two
samples", not exact release dates. `DA2_6789_op.bin` is excluded: it is not a container but a
memory-region dump.
