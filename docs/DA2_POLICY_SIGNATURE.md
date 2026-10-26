# OPLUS DA2 policy-path signature — port to 2710EX01 (and a model-wide key)

Origin: `ea29ia/mtkclient` `docs/notes/reverse/re-oplus-auth-paths.md` (200EX01 analysis,
2026-10-24) + a 2026-10-26 re-audit of the 2710EX01 DA2. This closes `HOW_TO_CONTINUE.md`
Priority 6 ("oplus_security state machine — internal transitions never byte-audited") for
**both** builds, and adds one fact the 200EX01 note could not see.

Nothing here is a new unlock path: the verdict of the 200EX01 note stands unchanged. What it
adds to this repo is (a) the same verdict proven on the 2710EX01 binary with its own addresses,
(b) a check the 200EX01 analysis did not run — whether the signing key is per-build, and
(c) a sharper statement of the replay caveat that survives into 2710EX01.

## TL;DR

The ladder, the gate and the crypto are the same design in 200EX01 and 2710EX01; the
**256-byte RSA modulus is byte-identical in both builds** (`c58002ae…`), so the policy
signature is model-wide, not per-OTA. Forging a policy requires the OPLUS private key, exactly
as concluded for 200EX01. For a *captured* vendor-signed blob, the replay model is unchanged:
the signature covers a 0xD0-byte device-info context, the policy body beyond the first 0x100
bytes is unsigned, so one captured blob is a master authorization for the device — but not a
route to unlock, because WRITE-* still face per-partition policy, AVB and LK.

## Address map (200EX01 → 2710EX01)

| element | 200EX01 (`da2_oplus.bin`, 356,296 B) | 2710EX01 (`DA2_extracted.bin`, 358,160 B) | same semantics |
|---|---|---|---|
| `CMD:SECURITY-SET-FLASH-POLICY` handler | `0x40006DDC` | `0x40006B8C` | Y |
| core (`oplus_security_verify_sec_policy`) | `0x400103DC` | `0x4001033C` | Y |
| `g_oplus_auth_status` | `0x4005455C` | `0x40054C88` | Y |
| status stores | `0x40010578`(3) / `0x400105C4`(1) / `0x400105EC`(4) / `0x40010668`(5) | `0x4001059C`(3) / `0x400105E0`(1) / `0x40010608`(4) / `0x40010684`(5) | Y |
| registrar gate (locked/read-back) | `0x40001AE4` | `0x40001A78` | Y |
| hashed DEVICE_INFO ("OSIG") block | `0x4006A088`, 0xD0 B | `0x4006A810`, 0xD0 B | Y |
| 19-byte SHA-256 DigestInfo | `0x40053C10` | `0x40054268` | Y |
| RSA modulus (256 B) | `0x400529E0` | `0x40053038` | **byte-identical** |
| payload download | `0x4002AE8C` | `0x4002AFD8` | Y (both log `"Download host file:%s"`) |

Both files start with the status word `03 00 00 00` — the DA2 boots **locked** (3), matching
the thread's observation that `ERR!UNSUPPORTED` is the steady state of a stock session.

## The ladder and the gate (instruction-level, 2710EX01)

Decision tree at `0x4001033C` (values stored to `[0x40054C88]`):

```
load key material from 0x40053038            0x4001040C  bl 0x40039590
in-blob sig_ver present -> verify -> 0    => status 1   0x400105E0  e5845000   (str r5)
   (value 1; a second attempt path yields 2)
marker 0x59 / 0x4E fallback paths           (0x4E -> status 2 on 2710's 3rd try)
all checks fail                             => status 3   0x4001059C  e5801000   (str r1)
then: policy tail byte [+0x701] == 0x1C     => status 4   0x40010608  e5840000
      policy tail byte [+0x700] == 0x19 && status==1 => 5 0x40010684
```

The registrar gate at `0x40001A78` compares **only** 4 and 3:

```
0x40001A78  e5900000      ldr r0,[r0]         ; g_oplus_auth_status
0x40001A7C  e3500004      cmp r0,#4
0x40001A80  0a000008      beq <read-back branch>   ; "[oplus] …read back mode, can not register cmd_write_partition"
0x40001A88  e3500003      cmp r0,#3
0x40001A8C  1a00000d      bne <full table>         ; 0/1/2/5 register WRITE-PARTITION/WRITE-FLASH/WRITE-PARTITIONS
... (==3)   "[oplus] do not get oplus permission" + return
```

`1 = FULL` is consistent with the #409 thread: the status word is forced to 1 during a
successful policy verify; 3 is the boot default; 4 is read-back. The executor itself contains
**no** reference to the status word (`0x40008884 ldr r2,[r4,#0x10]` / `blx r2` dispatches
whatever the registrar installed), so elevation is purely a registration-time decision.

Registration of `SET-FLASH-POLICY` is in the basic table and unpredicated (`0x40001DA8`
`movw r2,#0x6B8C` → `bl 0x400083DC`); its only precondition is the GET-DEV-FW-INFO flag
`[0x400683A8] == 1`, else `0xC0010001`.

## The crypto is a real RSA-2048 PKCS#1 v1.5 verify (both builds)

* exponent assembled at `0x4003F8D8`: `e3001001` / `e3401001` → **e = 0x00010001**;
* modexp driver `0x4003B41C` → `0x4003AA30` (2048-bit; 3072/4096 variants behind a size
  dispatch at `0x4003B444`);
* modulus: 256 bytes at `0x40053038` (2710) / `0x400529E0` (200EX01), 256/256 non-zero,
  entropy 7.157, first bytes `e8 fa 24 c7 …` — **sha256 `c58002ae…` in both files**;
* what is hashed: the locally built 0xD0-byte "OSIG" context at `0x4006A810`
  (`str 0x4749534F` "OSIG" at `0x4000FCF8`), via unkeyed HACC SHA-256 (`0x10210000`);
* the compare operates on the **RSA output**: `add r1,r6,#0xCD` (DigestInfo), `add r4,r6,#0xE0`,
  `memcmp 0x20`. EM layout: `00 01` @0, `FF`×202 @2..0xCB, `00` @0xCC, DigestInfo @0xCD–0xDF,
  digest @0xE0–0xFF;
* `0x4003EE90` (called at `0x4003B3D8`) is only a hex debug dump of `EM[0xE0]` — no transform.

Nothing after the `memcmp` exists (no counter, no whole-blob digest); caller-side extras are a
5-byte header at `blob+0x700` and a ≤0x400 length cap.

## Replay caveat (unchanged, and now scoped to 2710)

The signature covers the device-info context, not the policy body. `policy[0x100:]`
(partition permissions, tail flags) is plaintext, so one legitimately captured vendor-signed
blob is replayable with an arbitrary body while the 0xD0 context still matches — per the
200EX01 note, the context is version-derived, not a per-device UID, which is why the *same*
signed blob maps onto both builds' verification. Two consequences worth stating for anyone
who finds a blob:

* it grants `status=1` (FULL table) — flash-write commands become registrable;
* it does **not** unlock the device: per-partition write policy (`0x40006798`-family checks),
  AVB and the LK-side `img_auth_required` still apply, and RPMB remains out of reach without a
  key session. The unlock recipe (LK mirror `0x1DC–0x1DF`) still waits on an *authenticated
  RPMB write*, which this path does not provide.

## Forging — negative results, with what was searched

* no RSA/`modexp`/`PSS` strings in either binary — but the arithmetic is present (see above),
  so string absence is not evidence;
* no key material from efuse/OTP/mailbox/flash on the policy path: `movt #0x1000`/`#0x11xx`
  scans across the four SEC-POLICY functions give 0 off-chip register hits; only
  `0x10001088/8C` clock gates and the HACC hash;
* the RPMB KDF (`0x40039C14`) has no path into the policy verifier;
* modulus is a valid RSA-2048 modulus (odd, no factor < 113, `gcd(N, 65537) == 1`), not filler;
* e = 65537 excludes small-exponent forgery; the PKCS#1 check range-checks all filler bytes
  (with the known 200EX01 deviation that 0x00 is accepted alongside 0xFF).

## What would falsify this note

One emulator run of `0x4003AA30` with a random input (assert `out == in^e mod N`, `out != in`)
would close the "modexp is real" reading beyond structure-level argument; and a capture of a
real vendor session would test the replay model directly (expected: any body accepted while
the context matches). Neither requires a locked unit beyond the stock DA2 handshake.
