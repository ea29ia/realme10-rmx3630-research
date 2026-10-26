# Provenance & reproducibility — how every blob in this repo's claims is re-obtained

This repo deliberately ships no binaries. That only works if every artifact is re-derivable
from the official sources. This note collects the URLs, offsets and hashes verified on
2026-10-25/26, so any reader can reproduce the DA1/DA2/preloader/LK findings without trusting
anyone's file (including the author's).

## The OTA zips answer Range requests

`rms01.realme.net` serves the full export zips with `Accept-Ranges: bytes`, so individual
members can be fetched in tens of KB instead of 9–17 GB. Verified for the 2710EX01 zip:

```
URL   https://rms01.realme.net/sw/RMX3630export_11_14.0.0.2710EX01_2025122619580180.zip
size  16,785,417,673      Accept-Ranges: bytes
EOCD64 offset 0x3E87D2567 (locator at 0x3E87D259F), central directory @0x3E87B6FB0, 112,055 B, 1008 entries
```

Recipe (pure stdlib; ~400 KB transferred):

1. `GET` last 128 KB → find `PK\x06\x07` (ZIP64 locator) → EOCD64 at its stored offset →
   central-directory `offset`/`size` fields.
2. `GET` the CD range → parse `PK\x01\x02` entries; when `usize/csize/lho` are `0xFFFFFFFF`,
   read the ZIP64 extra (header id 1): `lho` comes first in that extra.
3. Per member: `GET lho..+30+nlen+elen`, verify `PK\x03\x04`, then `GET` the compressed bytes
   at `lho+30+nlen+elen` and `zlib.decompress(data, -15)` for method 8.

## Members verified from the 2710EX01 zip

| member | size | sha256 |
|---|---|---|
| `IMAGES/download_agent/DA_BR.bin` | 789,488 | `2e15a832b58e500505b785c1bb2817c77614b1c7475b2c84511015fa9e65d245` |
| `IMAGES/MTK_AllInOne_DA.bin` | 789,488 | `63980fa53b15bad4565bd9b0ebd322f08d1f87f624b0c3bf3a92f64345f7cfc3` |
| `IMAGES/preloader_k6789v1_64.bin` | 391,380 | `677d1febbbf10e4fcb77fd41e2615b23d705a87d344bfb06af9d93e4ccc7e22f` |
| `IMAGES/all-in-one-signature.bin` | 102,128 | `9d55f4746136554fed3092baeebafa8948c8dd28` |

Notes:

* `DA_BR.bin` version string: `MTK_DA_v6_2025-12-09 15:56:46 DA_05 KEY_02` (zip itself dated
  2025-12-26). Region table: DA1 `{buf 0xBC, len 0x69424, addr 0x200000, soff 0x693E0, sig 0x100}`,
  DA2 `{buf 0x694E0, len 0x57710, addr 0x40000000, soff 0xC0AF0, sig 0x100}`; entries [0] and [1]
  are byte-identical (v6 containers always carry a duplicate DA1 entry). Region law
  `soff + sig_len == buf + len` holds for all entries; the extracted region hashes are exactly
  `6c49eba0…` (DA1) and `f95f2b82…` (DA2) — the files this repo's audits describe.
* The preloader hash equals the value the unit reports in the probe logs, so the log provenance
  is confirmed, not assumed.
* `MTK_AllInOne_DA.bin` from the **same** zip is byte-identical to `DA_BR.bin` except the two
  signature trailers: payloads equal for both stages; trailers 0/256 non-zero (AllInOne) vs
  256/256 and 254/256 (DA_BR). The zero-trailer AllInOne is a packaging property, not a
  200EX01-specific quirk.
* `all-in-one-signature.bin` is **not** a DA signature: it starts with the MTK cert-section
  magic `0x58881688` (section name `aee`), carries `0x58891689` entries (22 X.509 records,
  `OU=Mediatek / CN=Oplus_cert0`), and contains neither DA trailer. Treat it as the cert-chain
  sidecar, unrelated to DAA.

## Other files referenced across the docs (for cross-checking)

| artifact | size | sha256 | source |
|---|---|---|---|
| 200EX01 `DA_BR.bin` | 785,024 | `abee43e8abc67de86c5f4e20eb58f8665cb560fa38ce1b135aa7c0f97ca8007c` | `RMX3630export_11_14.0.0.200EX01_2024090223460108.zip` |
| 200EX01 preloader | 390,868 | (build stamp `20240902-222100`; base 0x200F10) | same zip |
| 200EX01 `lk.img` | 2,884,672 | `80c8f8ab89d6bb5c82ee51e306a4403c0d39f6baedf8033f5242034162f88f47` (build stamp `c0edacf_202409021420`) | same zip |
| 2710EX01 `lk.img` | 2,884,928 | `b1be770e63b9aecf5771a117b22d35a66813982c315013cb93956d26283fa97a` (build stamp `c0edacf_202512090756`) | 2710EX01 zip, declared uncompressed size 2,884,928 |
| 2710EX01 DA1 (region) | 431,140 | `6c49eba0cea6d966539d2cb9bfe029eec4b3c772a11616c6ade2452aa8426e20` | `DA_BR.bin` region |
| 2710EX01 DA2 (region) | 358,160 | `f95f2b82c684115a0fd4bf50f3286ebcb357721a19134d56515d534e209dde47` | `DA_BR.bin` region |

The two `lk.img` files are confirmed distinct builds (build stamps differ; the 2710 one matches
the zip's declared size). The byte-difference analysis in the #409 thread ("lock/RPMB path
0-diff, whole image 0.94 %") therefore compares **two different builds**, not two copies of one.

## DAA-signed DA experiments (device-tested by this repo's author)

| build | DA source | DAA result |
|---|---|---|
| 200EX01 (2024-09-02) | own `DA_BR.bin` | accepted (pre-Dec builds) |
| 420EX01 (2025-03) | its DA_BR | `0x7024` |
| 400EX01 (2025-01) | its DA_BR | `0x7024` |
| 1900EX01 (2025-05) | its DA_BR | `0x7024` |

All four failures occurred at the preloader's `vfy_da` with intact 256-byte signatures, so the
key material was rolled once, before 2025-01 — a single event, distinct from the DA2 code
hardening (see `DA_HARDENING_TIMELINE.md` for the code-side dates).

## Caveat

`rms01.realme.net` availability is region/CDN-dependent; if the zips are gone, the hashes above
still allow anyone holding the archives to verify which blob they have. Nothing in the audits
depends on un-hashed files.
