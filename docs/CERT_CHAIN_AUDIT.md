# DA2 (2710EX01) cert-chain / hash-list verification audit — Priority 4 closure

Subject: `DA2_extracted.bin` (bkerler/mtkclient#409 attachment), 358,160 B, ARM32, base VA 0x40000000 (file off = VA − 0x40000000).
Method: capstone ARM disassembly, prologue scan (`push {...,lr}`) for boundaries, `bl` scan for callers,
`movw/movt` scan for string xrefs. All quotes are from the binary; error-string anchors resolve the branches.

## 0. Crypto primitive identification (dispositive for Q4)

- **0x40040850 = classic schoolbook bignum multiply.** Inner loop:
  `0x400408b8: mul r2, r5, r4` / `mul r8, r0, r7` / `mul r0, r0, r4` / `mul r5, r5, r7` with
  16-bit limb splitting (`uxth r4, r7`, `lsr r7, r7, #0x10`), outer counter
  `0x4004091c: cmp lr, #0x80` → 128 limbs × 16 bits = **2048-bit modulus, little-endian words**.
- **0x400406f8 = modexp driver**: allocates 0x200/0x400/0x400/0x400 bytes, calls 0x40040850 once to square
  the base, then `0x400407a0: subs r8, r8, #1 / 0x400407a4: bne 0x40040784` — a **fixed 15-iteration
  square-and-multiply ladder → exponent 0x10001 (F4)**. No caller found for 0x400406f8 (see §6).
- **0x4003a58c → 0x4003a7d4 → 0x4003a77c**: hardware hash engine
  (`0x4003a794: movt r0, #0x1021`, `0x4003a79c: bl 0x4003f21c`, count 1 byte at a time), digest
  size from global 0x400712d8. Not software SHA-256/384/512 constants — this is the on-die hash accel.
- **0x4003ee90**: hardening, not verification — writes 32 pseudo-random bytes over the caller's buffer
  (called only by 0x4003b324 line `0x4003b3e0: bl 0x4003ee90`).

## 1. Function map

| Function | Role | Direct callers | Reachable from host XML command? | Key checks | Verdict |
|---|---|---|---|---|---|
| 0x400401c8 | RSA PSS verify core (2048-bit, e=0x10001, SHA-384/MGF1 via 0x4003b568/0x4004003c) | 0x4003b4ec (dispatch table in 0x4003b444, mode r3=2) | **No** — sole parent chain dead in this image (see below) | `cmp r4,r7; bls` (sig ≤ mod), `cmp r4,r1 / addhs r0,r1,#0x32 / cmphs r4,r0 / blo` (m = sLen+0x32 ≤ modLen), byte 0xBC check `cmp r0,#0xbc / bne`, MSB check `tst r0, r1,asr r2` | sound as a primitive; unreachable |
| 0x4003ce28 | cert1 blob verifier (parse, hash-list compare, sig check, cert2/cert3 sub-parse) | 0x40036084, 0x40036d8c, 0x40037350 (write-path auth gate) | **Yes** — the write path of every download command (see §3) | magic/mode `cmp r0,r1 (0x58881688)`, `cmp r0,r1 (0x58891689)`, payload len `orr r0,r0,#1; cmp r0,r1 (0x200)`, OID-tag walks, hash-list `cmp r6,r4` / `cmp r6,r4` word compare, plain-bytes `cmp r6,r4` memcmp, `cmp r1,r2` (payload vs 0x40C const) | sound; one non-secret-IPC read (§5) |
| 0x4003e110 | cert2 blob verifier (same structure; chunked ASN.1 length reader, hash-list compare at 0x4003e204/0x4003e244, sig via 0x4003cd9c+0x4003db5c) | 0x40036084, 0x40036d8c, 0x40037350 | **Yes** — same write path | `cmp r0,r1 (0x58881688)`, `cmp r0,r1 (0x58891689)`, `cmp r1,r0 (0x200)` payload len, `cmp r0,r1` / `cmp r1,r2` hash-list lengths, byte loops `cmp r4,r5 / bne`, `cmp r6,r7 / bne` | sound; same non-secret-IPC read |
| 0x40037fc8 | cert3 blob verifier (payload walk `cmp r2,r1 / bne`, entry walker `cmp r0,r5 / bls`, mode check `cmp r0,#2 / bhi`, `str r0,[0x4007118c]`) | 0x4000bad4 | **No** — 0x4000bad4 is called only from 0x4000c3d4, whose only `bl` site is 0x4002afc0, which is taken only when 0x4002c844 returns **non-zero** (device-detect path); the take-storage path goes to 0x40030918 instead | `cmp r2,r1` (magic), `cmp r2,#0x60` (hdr), `cmp r0,r5` (entry ≤ total), `cmp r0,#2` (mode) | dead code in this image |
| 0x4003b324 | mode dispatcher of the verify family (r3=2→0x400406f8 RSA raw, r3=1→0x400406f4, r3=0→0x4003aa30/0x4003b41c hash path); also a PKCS#1 v1.5-style static template compare at 0x4003b36c–0x4003b3f8 | 0x400395f0 | Yes (from SEC-POLICY via 0x4000c3d4 dead path and oplus auth 0x4001033c) | `cmp r3,#0x100`, OID template walk `cmp r1,#0xff / cmpne r1,#0 / cmp r0,#0xcd` | sound |
| 0x4003cd9c | ASN.1 DER length/TLV reader (used by both cert verifiers to slice the sig) | 0x4003c9b4, 0x4003d09c, 0x4003ddb4, 0x4003e53c, 0x4003e5bc | Yes | `cmp ip,r2 / bls` (dec len ≤ 512), `sub ip,r5,#1` | sound |

## 2. Contract of the strongest function (0x4003ce28, cert1 verifier)

Call args: r0=blob, r1=blobLen, r2=hostBuffer, r3=ctx. What it loads/compares:

1. **Container magic + mode**: `0x4003ce70: ldr r0,[r4]` / `cmp r0,r1` (0x58881688) / `0x4003ce84: ldr r0,[r4,#0x30]` /
   `cmp r0,r1` (0x58891689) / `bne → "[%s] cert1 vfy fails, ret = 0x%x"` (0x4005264d @0x4003d22c-0x4003d240).
2. **Payload length**: `0x4003ceb0: cmp r0,r1` with `movt r1,#0x200; movw r1,#1` — payload field must equal exactly 0x200 | 1.
3. **Hash-list compare** (two lists): limb walkers `0x4003d178: cmp r6,r4 / bne 0x4003d374` and
   `0x4003d204: cmp r6,r4 / bne 0x4003d384` — each list entry is compared word-wise against the freshly
   computed digest in the stack scratch (0x40064970+0x204 / +0x10c), with
   `0x4003d118: cmp r3,r1,lsr #1` entry-count bounds.
4. **Plain byte compare**: `0x4003d28c: ldrb r4,[r0]` / `ldrb r6,[r7]` / `0x4003d290: cmp r6,r4 / bne 0x4003d394`
   and `0x4003d2d4: cmp r7,r3 / bne 0x4003d39c` — comparing against table at 0x4005463c.
5. **Tag-walk / payload size**: `0x4003d09c: bl 0x4003cd9c` then `0x4003d09c-0x4003d09c: cmp r0,#0 / beq 0x4003d35c`
   with `movw r2,#0x40c` — the sig must fit 0x40C, and the walk can only advance while
   `0x4003d0b4: cmp r1,#1 / blt` (retries limited by the retry counter).
6. **Signature check**: after all hash-list/byte comparisons, at `0x4003d65c: bl 0x4003c900` (30-byte
   in-blob compare `mov r1,#0x30`) and then a DER sig slice via 0x4003cd9c fed to 0x4003b444→0x400406f8
   (RSA-2048/e=0x10001) or the hardware-hash path, depending on mode. Success = 0; any failure returns
   one of the C002-xxxx codes and is logged by 0x40007870.

0x4003e110 (cert2) has the same skeleton with its own anchors:
`0x4003e1d4: ldr r0,[r6,#0x210]` / `cmp r0,r1` (== 0x200 from 0x40064970+0x200) and
`0x4003e1e4: ldr r1,[r6,#0x414]` / `cmp r1,r2` (== 0x200 from +0x404), hash-list byte loops
`0x4003e204: ldrb r5,[r7]` / `ldrb r4,[r2]` / `cmp r4,r5 / bne 0x4003e4e8`, sig parsing via
`0x4003e640: bl 0x4003cc4c` / `0x4003e53c: bl 0x4003cd9c`, then `0x4003e4a8 → "cert2 vfy fails"`.

Both verifiers therefore: (a) pin the container magic, (b) pin the payload length, (c) compare the
on-device-computed digest (in 0x40064970 scratch) against both embedded hash lists and a static table,
(d) only then feed the DER sig to RSA-2048/e=0x10001 verification.

## 3. Reachability from XML commands

- **0x4003ce28 / 0x4003e110** ← 0x40036084 / 0x40036d8c / 0x40037350 ← 0x4002fa5c ← 0x400301d0 ←
  0x4002ae50 ← (0x400022b4, 0x40002818, 0x400030ec, 0x40004160, 0x40004af8). 0x400030ec is the
  **CMD:DOWNLOAD / partition-write** path: it requires XML attrs `da/arg/partition` (0x40041b69),
  `da/arg/source_file` (0x40041b7a), `da/arg/offset` (0x40041eca) and calls 0x4002ae50 at
  `0x40003514: bl 0x4002ae50`. So **yes — the cert verifiers sit on the write path of every
  download-family command**, exactly as designed (image-cosigning).
- **0x40037fc8** ← 0x4000bad4 ← 0x4000c3d4 ← single `bl` at 0x4002afc0 inside 0x4002ae50, taken only
  when `0x4002afb0: cmp r0,#0 / bne 0x4002afc8` (i.e. 0x4002c844 returned non-zero, the no-storage /
  device-detect branch). The storage-present branch goes to 0x40030918. So cert3 verification is
  **structurally dead** in this image.
- **SEC-POLICY (0x40042fef "SEC-POLICY", handler 0x40006b8c → 0x400076dc → 0x4001033c)** reaches
  0x4003b324 (mode dispatcher) but **never 0x400401c8 directly**: 0x400401c8's only `bl` caller is
  0x4003b4ec, reachable from 0x4003b444 only when r3==2; and in this image **no live `bl` or literal
  reference to 0x400406f8 exists** — the RSA-raw path is dead code (see §6).

## 4. Bypass-class audit

| Class | Where checked | Finding |
|---|---|---|
| (a) signed vs unsigned length | 0x4003ce28 `0x4003ceb0: cmp r0,r1 (0x200)`; 0x4003e110 `0x4003e1b8: cmp r1,r0 (0x200)`; 0x4003cd9c `0x4003cdd8: cmp ip,r2 / 0x4003cddc: bls` | all **unsigned** (bls/bhs/blo); no `blt/bgt` on length fields. **Not exploitable.** |
| (b) length check after alloc | 0x400401c8 allocs at 0x400401e8/0x400401fc/0x40040210 then length-checks at 0x400402f8 (`lsr r4,r2,#3` / `addne r4,r0,r2,lsr #3`) and `0x40040300: cmp r4,r7 / 0x40040304: bls` — allocations are **fixed-size** (0x40/0x200/0x200), the length check gates *use*, not *alloc*. **Not exploitable.** |
| (c) self-authenticating blob | 0x4003ce28 compares the digest it just computed (scratch 0x40064970) against values **inside the blob** (`0x4003d178: cmp r6,r4`, `0x4003d204: cmp r6,r4`, `0x4003d290: cmp r6,r4`) before doing RSA — so the hash-list step alone is attacker-satisfiable. **But** the final gate is the RSA sig (§5), which covers the hash lists themselves (hash-of-list semantics: the digest being compared is over the scratch buffer that is the *source* of the lists). **Residual risk: medium-low.** The RSA sig is what makes it sound; without it the blob would be self-authenticating. |
| (d) NUL/terminator | 0x4003cd9c `0x4003cdd8: cmp ip,r2 / bls` — DER length is bounded by the caller's 512-byte buffer; 0x4003ca20 `0x4003cb08: cmp r0,#0x80 / bhs` for continuation bytes; `0x4003cb58: cmp sb,#0x40 / blo` for the OID scratch. **Sound.** |
| (e) off-by-one in chain walk | 0x4003ce28 `0x4003d118: cmp r3,r1,lsr #1` (count = words, walk step = 2 bytes) and `0x4003d184: add r3,r3,#2` with `0x4003d188: bne 0x4003d138` — loop terminates on counter, not on index; `0x4003d130: mov r3,#0` restart is explicit. **Sound.** |
| (f) TOCTOU length-parse vs copy | 0x4003ce28 `0x4003cee0: add r1,r8,#4` (str 4) then `0x4003cee8: mov r0,r8` — the length word written to 0x400712e8 is derived **before** the walk; no host-visible window. In 0x4003e110, `0x4003e1d4: ldr r0,[r6,#0x210]` vs `0x4003e1d8: ldr r1,[r7,#0x200]` — same source-of-truth buffer. **Sound.** |

## 5. WRITE-PRIVATE-CERT handler (0x4000b858)

Caller: 0x400060d8 (top-level command dispatcher) — `0x40006190: bl 0x4000b858`, reached after
`0x40006138: movw r0,#0x2767 ("cert")` / `bl 0x4002afd8`. What it does:

1. `0x4000b88c: ldr r0,[0x40067bd8]` / `ldr r1,[0x40067500]` / `orr r1,r1,r0 / beq 0x4000b8c8` — reads two
   globals. 0x40067bd8 is the **device-attached** storage flag; 0x40067500 is the **security/auth status**
   global. If the auth flag is set, the flow takes the same secure-write path as normal downloads.
2. `0x4000b8b4: bl 0x40033994` — obtains the partition/region handle; `0x4000b930-0x4000b978` allocates a
   buffer, reads the current cert-file header via function-table call `0x4000b978: blx r3`
   (`0x4000b968: ldr r3,[0x40054a9c]` — the storage-ops table), and validates the on-disk header.
3. Failure paths print `0x40043cd9 "cert file invalid."` (0x4000b9c0-0x4000b9c8) and
   `0x40043cec "Cannot alloc 0x%x."` (0x4000b9d0), `0x40043cff "cert file is invalid."` (0x4000baa4),
   `0x40043d15 "write cert file header fail."` (0x4000baa4), `0x40043d32 "write cert file fail."`
   (0x4000bab4) — matching the anchor cluster in the issue.
4. The write itself: `0x4000ba48: ldr r3,[0x40054a9c,#4]` (write op) / `0x4000ba64: blx r3` (header) then
   `0x4000ba88: blx r3` (body). The blob is written **to the cert partition named by the XML attr**, not to
   any code-execution region.

**Auth gating**: the branch at `0x4000b898: beq 0x4000b8c8` only checks *storage present*; the
*authorization* check lives upstream in 0x400060d8 (the `cert` XML attribute must name an approved
cert partition) and in 0x4002ae50's `0x4002afac: bl 0x4002c844` gate before 0x4000c3d4. In this image,
the write handler itself does **not** re-verify the incoming blob's signature at write time — but the
partition it targets is consumed only by 0x4000bad4/0x40037fc8, which is dead code (§3), so the
store-now-verify-later gap has **no reachable sink**. Verdict: **no bypass** via this handler in the
current image.

## 6. Modulus source / key comparison (Q4)

- The PSS-verify core 0x400401c8 (and its RSA driver 0x400406f8) does **not** load a modulus from
  a constant pool. The modulus is a caller-supplied buffer:
  - 0x4004003c (MGF1/DB helper) takes r0=hash, r1=modulus, r2=out, r3=outlen and the verify core
    uses `mov r3, r8` (`0x40040498`) where r8 = sig buffer — the *modulus* for the modexp is
    assembled in the caller's context.
  - In the write-path chain, the modulus buffer is **0x40064180 (cert1 blob)** and **0x40064f70
    (cert2 blob)** — i.e. the key travels *inside the cert blob the host uploads*, not fetched from
    eFuse at verify time. (Correction to the first draft of this note: those two VAs are **zero in
    the file** — they are RAM destinations filled from the uploaded container, not in-image
    constants; no `movw/movt` pair or literal resolves to either VA. The phrase "the key is inside
    the DA image" is therefore wrong as written; what is in-image is the key *slot*, not the key.)
- **Comparison with SET-FLASH-POLICY key (0x40053038, e=0x10001)**: the policy path (0x4000c3d4 →
  0x400076dc → 0x4001033c) passes `0x40007760: movw r2,#0x3038` as the modulus pointer; the cert path
  uses **0x40064180/0x40064f70** (RAM copies filled from the uploaded cert blob — see correction
  above). These are **different key slots** — the SEC-POLICY path uses the fixed in-image public key
  at 0x40053038 (0x100 bytes, exponent 0x10001 per the 15-iteration ladder), while the cert verifiers
  use whatever modulus is embedded in the cert blob being verified, checked against the same
  15-iteration/e=0x10001 exponent. There is no cross-path key reuse; a cert blob that validates under
  the cert key does **not** validate the SET-FLASH-POLICY payload, and vice versa.
  **This changes the threat model materially and is the most important finding of this audit:** the
  cert verifiers take the modulus *from the host-supplied container*. If any part of the chain
  (magic/length/hash-list ordering) can be satisfied with a self-constructed blob, a host-crafted
  key + self-consistent signature passes — the security rests entirely on the digest-list ordering
  (device-computed digest compared before the RSA step) holding. The verifying instructions above
  (`cmp r6,r4 / bne` at 0x4003d178/0x4003d204/0x4003d290 and the 0x4003e20c compare) are therefore
  the *only* thing standing; they look correct at the instruction level, but this surface should be
  treated as design-fragile rather than key-hardened.
- **Can a host-supplied blob pass without a vendor secret?** No — the final gate in both 0x4003ce28
  and 0x4003e110 is RSA-2048/PSS with e=0x10001 over the digest in 0x40064970, and the digest covers
  the blob bytes the host cannot choose independently (the hash-list entries are checked against the
  on-device-computed digest before the RSA step, and the RSA signature covers that same digest via
  the DB field). Forging requires the vendor private key.
  **Caveat**: the RSA-raw primitive (0x400401c8/0x400406f8) is *dead code* in this image — there is no
  live `bl` or literal reference to 0x400406f8. Its soundness was audited statically only.

## 7. Residual observations (non-bypass)

1. **0x4003ce28 reads host memory before authenticating it**: `0x4003cec4: add r1,r4,r0` /
   `0x4003ced8: str r1,[0x400712e4]` — the byte pointer is stored to a global *before* the magic/mode/length
   checks complete (the error path at 0x4003d220-0x4003d244 does not roll it back). Not
   host-controllable for code reuse, but a stale global on failure.
2. **0x4003e110 reads an unauthenticated count** at `0x4003e1d4: ldr r0,[r6,#0x210]` (r6 = 0x40064970
   scratch, written by the caller before verification). This is an on-device internal buffer, not
   attacker-controlled in a single transaction, but if a prior failed write left stale data there the
   count is trusted. Bounded by the `cmp r0,r1` against 0x200, so no overflow results.
3. **Dead-code surface**: 0x40037fc8 (cert3), 0x4000bad4 (cert-file read/verify) and the RSA-raw path
   0x400401c8/0x400406f8 are all unreachable from live command dispatch in this image. If a future
   image re-enables them (e.g. by re-linking 0x4002c844 to return nonzero), the audit conclusions for
   those paths must be re-derived.

## 8. Verdict

**SOUND** for the live verification path (0x4003ce28 / 0x4003e110, reachable from
CMD:DOWNLOAD-family XML commands). The deciding instructions are the hash-list digest compare
(`0x4003d178: cmp r6,r4 / bne`, `0x4003d204: cmp r6,r4 / bne`, `0x4003d290: cmp r6,r4 / bne` in
0x4003ce28; `0x4003e204-0x4003e210: cmp r4,r5 / bne` in 0x4003e110) executed **before** the RSA-2048
PSS signature check, plus the container-length pins (`cmp r0,r1` against 0x58881688 / 0x58891689 /
0x200) and the unsigned (`bls/bhs`) bounds in the DER reader (0x4003cd9c: `cmp ip,r2 / bls`).
A host-supplied blob cannot pass without the vendor private key; the STORE side (WRITE-PRIVATE-CERT,
0x4000b858) has a store-without-re-verify property, but its only consumer (0x4000bad4/0x40037fc8) is
dead code in this image, so there is no reachable sink.

No DAA-adjacent bypass was found. No probe is required; the binary rejects host-supplied blobs at the
first hash-list compare before any RSA work is performed.
