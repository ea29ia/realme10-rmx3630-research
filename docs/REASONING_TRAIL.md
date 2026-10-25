# Reasoning Trail — Realme 10 4G (RMX3630) Bootloader Research

**Target:** Realme 10 4G (RMX3630), MT6789 (Helio G99), build 2710EX01
(Dec-2025 security patch), UFS, A/B, locked (ro.boot.flash.locked=1).

**Period:** 2026-10-20 to 2026-10-25 (6 days of continuous investigation).

**Outcome:** DA2 XML attack surface fully audited. No viable vector found within
that surface. Heapbait is patched at the transport layer. Untested surfaces
ranked for future work (see Section 8).

**Purpose of this document:** Capture the complete reasoning trail — every
hypothesis, every failure, every discovery — so that a future researcher can
pick up exactly where we left off without re-deriving what's already proven.
This is the published version of our working log; personal journal content
has been removed.

---

## Table of Contents
1. Executive Summary
2. Phase 0 — Initial hypotheses (and their disproof)
3. Phase 1 — Heapbait investigation
4. Phase 2 — The 420EX01 discovery
5. Phase 3 — The logprobe breakthrough
6. Phase 4 — Full DA2 XML audit (14 functions)
7. Key methodological lessons (reusable)
8. What was NOT pursued and why
9. How to continue from here
10. Appendix — addresses, hashes, references

---

## 1. Executive Summary

### What we set out to do
Find a public, reproducible path to unlock the bootloader on a Realme 10 4G
(RMX3630) running build 2710EX01 (December 2025 security patch).

### What we found
- **The known heapbait primitive is patched at the transport layer** on 2710EX01.
  The loop clamps request to `min(remaining, packet_max)`, and the read callback
  refuses any packet larger than the request with `0xc0010006`. This is a
  byte-level difference from the generic upstream DA (which has the old unclamped
  loop) and from the 420EX01 build (which we range-downloaded from the official
  OTA server and disassembled).
- **Older DAs are refused at the DAA gate** (`0x7024`). Verified with 420EX01 DA
  (Realme-signed, genuine signature) — still rejected. **[Corrected later: the
  mechanism is the preloader's own RSA-PSS verifier rejecting the unsigned
  AllInOne container, not cert rotation — see `PRELOADER_AUDIT.md` §3]**
- **The entire DA2 XML command surface was audited** (14 functions, assembly-level
  evidence for every size check and memory lifecycle). Result: 0 candidates ≥3/5.
- **The preloader descriptor issue** (wMaxPacketSize=0) from earlier reports was
  **tooling-side**, not firmware sabotage. mtkclient's `usblib.py` calls
  `set_configuration()` unconditionally, triggering pyusb's documented "lightweight
  device reset". Fix: call `get_active_configuration()` first. Handshake works
  cleanly after that (verified on both Linux and Windows).

### Verdict
**No public path via DA2 XML commands on 2710EX01.** The remaining untested
surfaces (DA1, Preloader, EFUSE handlers, cert chain, RPMB, oplus_security state
machine) are documented in Section 8 with estimated probabilities.

### What this means for future researchers
The DA2 XML surface is closed. Don't waste 6 days re-proving it. Start with DA1
(Section 8.1) — it's the strongest candidate and has never been audited in any
public research we could find.

---

## 2. Phase 0 — Initial hypotheses (and their disproof)

### H1: "The preloader USB descriptor is broken (wMaxPacketSize=0)"
**Hypothesis:** The Dec-2025 firmware sabotages the preloader USB descriptor to
prevent handshake, as an anti-exploitation measure.

**What we tried:**
- Multiple USB cables, ports, controllers (xHCI/EHCI)
- Driver binding (UsbDk, WinUSB via wdi-simple, stock MediaTek)
- Various entry methods (adb reboot, cold plug, cable-hold + power button)
- Both Windows and Linux (Ubuntu 22.04 on VMware and bare-metal)

**Result:** The `wMaxPacketSize=0` signature appeared consistently, but was
accompanied by `can't set config #1, error -32` in dmesg (Linux) or HIDClass
binding despite WinUSB INF (Windows). Zero echo from the chip in all cases.

**Disproof:** We traced the issue to mtkclient's `Library/Connection/usblib.py`:
```python
self.device.set_configuration()   # UNCONDITIONAL
```

Pyusb documentation confirms that calling set_configuration() on an already-
configured device performs a "lightweight device reset" that clears endpoint
state. The fix:

```python
if self.device.get_active_configuration() is None:
    self.device.set_configuration()
```

After this fix, handshake works cleanly on both Linux (libusb1) and Windows
(libusb0 with 22d9:0006 preloader).

Lesson: Verify the tooling before assuming hardware/firmware behavior. The
"firmware sabotage" theory cost us 3 days of false investigation.

Status: CLOSED. Fix is proposed upstream (see PR).

---

H2: "Battery level affects the preloader window"

Hypothesis: The preloader VCOM window duration depends on battery level —
low battery (3-13%) holds the window open for minutes; high battery (37-43%)
skips it entirely.

What we tried:

· Repeated handshake attempts at different battery levels
· Kernel-level timing analysis of the preloader window
· Windows-side USB watchers at 100ms polling

Result: The window-open behavior correlated with battery in early tests, but
the correlation vanished once the set_configuration() bug was fixed. The window
opens reliably at any battery level ≥30% after the fix.

Lesson: Apparent correlations in early testing can be artifacts of a
completely separate bug. Don't build theories on uncontrolled observations.

Status: CLOSED. Battery level is not a significant factor after the tooling fix.

---

H3: "The preloader binds as HID, blocking WinUSB"

Hypothesis: The preloader USB descriptor has bInterfaceClass=0x03 (HID),
causing Windows to bind HIDClass regardless of the INF. This prevents
Antumbra/nusb from seeing the device.

What we tried:

· Custom INF with WinUSB binding via wdi-simple
· Zadig for direct driver replacement
· UsbDk for raw USB access

Result: The device did bind as HIDClass despite the INF being installed
(correctly registered in the driver store, but not selected by the PnP manager).
This was real, but not the primary blocker — the set_configuration bug (H1) was
the actual issue.

Lesson: Multiple issues can coexist. Fixing one doesn't reveal the others
until you test end-to-end.

Status: CLOSED (subsumed by H1's fix — the handshake works even though the
descriptor still shows HID in some cases).

---

H4: "BROM mode is available"

Hypothesis: Holding Volume Up + Power during USB connection triggers BROM
mode (0E8D:0003), which would bypass the preloader entirely.

What we tried:

· Volume Up + Power held during USB plug
· Various button combinations (Vol Up + Down, Vol Up + Down + Power)
· Cable-hold method

Result: The device never enumerated as BROM (0E8D:0003). It either booted
normally to Android, entered Recovery (Vol Up + Down), or briefly showed the
broken preloader stub. The efuse is confirmed blown for BROM on this device.

Lesson: BROM efuse is a hard limit on this chip family. No software workaround.

Status: CLOSED. BROM path is permanently unavailable.

---

3. Phase 1 — Heapbait investigation

H5: "heapbait is exploitable on 2710EX01"

Hypothesis: The known heapbait primitive (fp_read_host_file's over-delivery)
works on our build, allowing us to take over the DA2 command loop and bypass
SLA / oplus auth.

What we tried:

· Full chain with mtkclient on the ea29ia branch (758d71e + fixes)
· All values verified against Ghidra (heap_base=0x40071580, heap_size=0x32000000,
  dpc_addr=0x4006a570, etc.)
· Logprobe (OPLUS_STREAM_READER, uartloglevel=0, logchannel=USB) to see live heap traces
· Multiple attempts with different payloads and geometry

Result: Host-side chain executes successfully (allinone upload OK, Stage 2 OK,
Stage 3 OK, overflow triggered), but the shellcode never takes the loop. The
stock XML envelope (NAK 0xc0010001) is always returned.

Disproof: Three independent layers of patch on 2710EX01:

1. Loop clamp: request = min(remaining, packet_max) — over-delivery never
   requested.
2. Callback refusal: if (request < packet_len) → 0xc0010006 — even if
   over-delivery requested, refused.
3. Callback identity: Raw byte evidence at file offset 0x54A48 =
   0x40007ea4 (thunk) → FUN_4002aa28 (the documented refusing callback).

Compared against the generic upstream DA (older shape: unclamped request +
done != size termination + callback accepts) — the difference is byte-level,
not geometry.

Lesson: The over-delivery primitive must EXIST on your specific build before
geometry tuning matters. "Same pattern" is not proof.

Status: CLOSED. heapbait is not exploitable on 2710EX01.

---

H6: "The heap geometry can be tuned to force the hijack"

Hypothesis: Even with the clamp, maybe a specific filename length or heap
shaping sequence can place the corrupted chunk on a live free-list node.

What we tried:

· Filename length sweep (L=4200, L=5000 baseline)
· 60KB trigger command between Stage 3 and GETBAITED to walk the whole realloc
  chain through the free list
· Realloc chain analysis (FUN_4000e790: double below 1KB, then +0x400)

Result: The corrupted bytes never landed on a free-list node. The chunk
after the 0x1400 data buffer is either an exact-fit carve or an allocated
chunk's body (inert). The 60KB trigger's parse swept ~45 ascending request
sizes through the free list and hit nothing.

Lesson: If the primitive is closed at the transport layer, geometry is
irrelevant. Don't chase geometry after proving the primitive is dead.

Status: CLOSED (subsumed by H5).

---

4. Phase 2 — The 420EX01 discovery

H7: "The 420EX01 DA has the vulnerable heapbait loop"

Hypothesis: The older 420EX01 firmware (March 2025) has a vulnerable DA
build. Loading it on our 2710EX01 device would restore heapbait.

What we found:

· Confirmed: We range-downloaded only DA_BR.bin from the official Realme OTA
  server (rms01.realme.net, 9.7 GB zip, ~370KB transferred, 785,024 bytes
  extracted, SHA-256 f80607f3...66e).
· The 420EX01 DA has the OLD loop shape: unclamped request + done != size
  termination + no anti-heapbait marker. The vulnerability IS present.
· Full exploit values were derived for the 420EX01 DA (heap_base=0x40070e00,
  dpc_addr=0x40069df0, etc.).

Why it doesn't help: On 2710EX01, uploading the 420EX01 DA fails at
DAA_SIG_VERIFY_FAILED (0x7024) — the device refuses the DA at the
authentication gate.

**Correction (added later, after the preloader audit):** the original
"anti-downgrade via certificate rotation" explanation was WRONG. The 0x7024
comes from the **preloader's own signature verifier** (FUN_00237938, see
`PRELOADER_AUDIT.md`): the AllInOne container ships DA1/DA2 with an all-zero
256-byte signature trailer, and DA_BR's copies are signed — same code bytes.
So "load an older DA" fails because it is **unsigned in its container**, not
because certs rotated. The verifier is a genuine RSA-2048/e=65537/PSS-SHA256
check (sig_len hard-gated at 0x100, digest over da_len−sig_len, modulus in
boot-populated SRAM) — unforgeable without the MTK/OPLUS private key.

Lesson: Even a vulnerable DA is useless if the device refuses to load it —
and the refusal here is cryptographic, not a cert-rotation policy.

Status: CLOSED. Older DA path is blocked at DAA (mechanism now fully
understood — see PRELOADER_AUDIT.md §3).

---

H8: "A DA build between 420EX01 and 2710EX01 might have the vulnerable loop AND pass DAA"

Hypothesis: If OPLUS rotated the DA signing certificate at some point between
March 2025 (420EX01) and December 2025 (2710EX01), but only fixed the heapbait
loop in the December OTA, an intermediate build (e.g., 1900EX01 or 2302EX01)
would be exploitable.

Status: NOT PURSUED. This is a real possible vector but requires downloading
and analyzing multiple intermediate DA builds. We documented it in Section 8 as
a possible future direction but did not pursue it (time budget).

---

5. Phase 3 — The logprobe breakthrough

H9: "We can see the heap via USB if we enable TRACE logging"

Hypothesis: The DA2's allocator debug prints ("allocation was %zd bytes long
at %p") can be enabled via the XML command CMD:SET-RUNTIME-PARAMETER with
<da_log_level>TRACE</da_log_level> and <log_channel>USB</log_channel>.

What we found:

· Confirmed: The SET-RUNTIME-PARAMETER handler is ALIVE on 2710EX01, despite
  the strings appearing "orphaned" in static analysis.
· With --uartloglevel 0 --logchannel USB on the mtkclient command line, the
  DA2 streams malloc/free traces in-band over USB.
· This is the single biggest breakthrough of the project — it eliminates the
  "we can't see the heap" problem that blocked all previous heap geometry work.

Why it didn't solve the final puzzle: Even with full heap visibility, the
transport-layer patch (H5) prevents the overflow from reaching the heap in the
first place. The logprobe is useful for future work (any heap-based exploit
on any MTK DA) but cannot resurrect heapbait on 2710EX01.

Lesson: Visibility tools are extremely valuable. Even when a specific
hypothesis fails, the tool remains for future use.

Status: DELIVERED as scripts/trace_decode_logprobe.py (the trace decoder is in
this repo's scripts/ directory).

---

6. Phase 4 — Full DA2 XML audit (14 functions)

Methodology

1. 3-way diff: Compare 2710EX01 (951 functions) vs 420EX01 (979) vs generic
   MTK (900). Byte-level fingerprints + mnemonics.
2. Reachability: Build call graph from all XML command handlers. 715/951
   reachable.
3. Priority: Focus on 20 functions OPLUS added/modified after March 2025.
4. Gate analysis: For each function — scoping (source of sizes, reachability),
   decompile, assembly evidence for every size check, memory lifecycle audit.

Results table

# Function Role Grade Key evidence
1 FUN_4002ae50 download request sender 1/5 not a copy loop; single XML send + OK parse
2 FUN_4002bff4 scatter XML parser 1/5 count guard 0xbf before every write; bounded copies
3 FUN_400084cc command loop 1/5 only diff = result-mux from DA1 handoff (magic-checked)
4 FUN_40030364 storage write pump 1/5 CSEL min() clamp + same callback refusal
5 FUN_400307a8 envelope reader 2/5 same callback; theoretical NUL-walk (shared pattern)
6 FUN_4000bad4 preloader download engine 2/5 fall-through defect neutralized by caller memset; malloc from config
7 FUN_4000c764 preloader HB builder 2/5 sizes from device cert; 3 mallocs, 3 null checks; single free per path
8 FUN_40001504 storage checksum examine 2/5 global cache (config-sized); CSEL min() clamp
9 FUN_40002818 download-partition 2/5 covered by closed callees
10 FUN_400030ec partition download 2/5 covered by closed callees
11 FUN_40003c38 partition erase 2/5 two-stage 64-bit bounds; overflow-proof
12 FUN_4002afd8 fp_read_host_file already-audited clamp + callback refusal
13 oplus_security_verify OPLUS auth already-audited mapped by ea29ia
14 mxml/escape/get_node parser/escape/allocator already-audited from previous sessions

Verdict: 0 candidates ≥3/5 in the entire OPLUS-added queue.

---

7. Key methodological lessons (reusable)

These are lessons learned across the investigation that apply to ANY future
MTK DA analysis:

7.1 — Ghidra .data section is unreliable

Values that appear as zero in Ghidra's decompiler often exist in the raw bytes.
For any global whose initial value matters, read from DA_BR.bin at
file_offset = DA2_base_offset + (VA - 0x40000000). Verified case:
DAT_40054a48 appears as 0 in Ghidra but is 0x40007ea4 (thunk to FUN_4002aa28)
in the raw binary. Writer-tracing is unaffected by this issue.

7.2 — Decompiler boolean casts are often artifacts

The decompiler sometimes renders if (a <= b) as (uint)(a <= b) — misleading
as a boolean cast. Always get the raw assembly for any size check. Verified case:
the "clamp" in FUN_40030364 and FUN_4000bad4 looked like a suspicious edge-case
bypass in decompiler output, but the assembly showed a clean 64-bit CSEL
min() operation.

7.3 — Cross-command state is a real attack surface

Always verify that globals used as state are fresh-zeroed per command, not
persistent across commands. Verified case: _DAT_4006a7c0 looked like it could
be stale (cross-command leak), but the only writer is FUN_4000c3d4 which
creates a new stack frame + memset before calling into FUN_4000bad4.

7.4 — Fall-through defects are code smells

An error path that prints an error but doesn't return is suspicious. But
check the caller before assuming exploitability — the caller's memset/init
may neutralize the defect. Verified case: FUN_4000bad4 error path falls
through to the main loop, but the caller's memset ensures the loop exits
immediately.

7.5 — Reachability first

Build the call graph from XML handlers before auditing anything. Roughly 75%
of the 951 functions are reachable from a command handler — focus on those.
The remaining 25% are utilities, init code, or error paths that never
process host input.

7.6 — "Same pattern" is not proof

If two functions look like they have "the same clamp" or "the same check,"
verify with assembly. Pattern matching at the decompiled-C level is unreliable
due to compiler optimization and decompiler rendering artifacts.

7.7 — External validation matters

Cross-check findings against:

· MTK CVE timelines (CVE-2024-20056, CVE-2025-20635, CVE-2025-20650,
  CVE-2025-20658/heapb8, CVE-2025-20696, CVE-2025-20730)
· Academic papers (SSTIC 2024 "When Samsung meets MediaTek" — validates the
  allocator mechanics and exact-fit splitting rules)
· Community research (ea29ia's PR #410, DekuzenOkahiro's #134, R0rt1z2's writeup)

7.8 — Raw byte verification is the highest standard

When Ghidra disagrees with reality (or when a global's initial value matters),
read the raw bytes from the binary at the exact file offset. This was the
decisive evidence for the callback identity (0x40007ea4 = thunk to FUN_4002aa28).

---

8. What was NOT pursued and why

8.1 — DA1 (strongest candidate, ~30-40% est.)

Size: 0x69424 bytes (428 KB), located before DA2 in the DA_BR.bin.
Why it's promising: DA1 runs first, parses its own host commands (COM ports,
boot parameters), and establishes the environment before DA2 loads. It has NEVER
been audited in any public research we could find.
How to audit: Same methodology as DA2 (3-way diff vs 420EX01/generic,
reachability from DA1 handlers, gate analysis with assembly).
DAA caveat: The DAA gate ensures that only signed DA1 is loaded, but the
DAA gate does not audit DA1's OWN command handling. If DA1 has a vulnerability
in its host-command parsing, it's reachable BEFORE the DAA gate matters.

8.2 — Intermediate DA builds (1900EX01, 2302EX01) (~10-15% est.)

Idea: If OPLUS rotated the DA signing cert at a point between March 2025
(420EX01) and December 2025 (2710EX01), but only fixed the heapbait loop in
December, an intermediate build could be exploitable.
How: Range-download the DA_BR.bin from each intermediate build's official OTA
URL, analyze the loop shape (clamped vs unclamped), test loading on our device.
Risk: Even if the loop is vulnerable, DAA might still refuse (if cert was
already rotated by the intermediate build).

8.3 — Preloader (~15-20% est.)

Why: The preloader runs before the DAA gate. Its command handlers, if
vulnerable, could provide a bypass without DA involvement.
Status: Handshake protocol audited (descriptor issue was tooling-side, not
firmware). But the preloader's own command handlers (0x4000bad4's callees in
the preloader code, if separate) have not been audited.

8.4 — EFUSE handlers (~10-15% est.)

Why: Reachable via CMD:WRITE-EFUSE and CMD:READ-EFUSE. The handlers
(0x4003184a through 0x40032dc4) do index math for efuse bit manipulation. If
there's a logic bypass, it could flip SLA/DAA enables.
Status: Structural review only. Never deep-dived.

8.5 — Cert chain verification (~10-15% est.)

Why: FUN_40037fc8, 0x4003ce28, 0x4003e110, 0x400401c8 verify cert
chains. If the chain validation has a logic bug (e.g., accepts certs signed by
a different key), DAA bypass becomes possible.
Status: Never audited.

8.6 — RPMB suite (~3-5% est.)

Why: The RPMB handlers (0x40025d4c through 0x40026eb0) handle HMAC framing.
Lower priority because RPMB requires an active key session.
Status: Structural review only.

8.7 — oplus_security state machine (~5-8% est.)

Why: FUN_4001033c (oplus_security_verify_sec_policy) has internal
transitions (status 1/2/3/4). If any transition has a logic bypass, it could
bypass the SLA dummy-signature check.
Status: Mapped by ea29ia in PR #410. Internal transitions not byte-audited.

8.8 — UART hardware tap (~15-25% est., HIGH RISK)

Why: Direct preloader shell access would bypass all software gates.
Status: NOT attempted. Requires physical disassembly, UART probe, risk of
hardware damage. Out of scope for a software-only investigation.

8.9 — Commercial tools (ChimeraTool, UnlockTool)

Status: These support the RMX3630 per their public listings. Reproduce at
your own risk, requires payment, and the technical mechanism is unknown (likely
a leaked DA signing key or an unpublished preloader exploit). Not pursued in
this research (not open, not reproducible).

---

9. How to continue from here

Recommended first step: Audit DA1 with the same methodology used for DA2.
It's the strongest untested surface (~30-40% estimated probability of a usable
vulnerability).

Recommended second step: Analyze intermediate DA builds (1900EX01, 2302EX01)
for the vulnerable loop + DAA-pass combination (~10-15%).

For tooling: The logprobe (Section 5, H9) is available for any future
heap-based exploit — scripts/trace_decode_logprobe.py decodes the traces.

For methodology: Section 7 has the reusable lessons. Read it before starting.

If you find something: The mtkclient issue #409 is the active thread for
this device. Post there. Include:

· Which function/phase revealed the finding
· The exact evidence (assembly fragment, address, hash)
· The reproduction steps (if any)
· Your judgment of severity/exploitability

---

10. Appendix — addresses, hashes, references

Key addresses (2710EX01 DA2)

· DA2 base: 0x40000000
· DA2 file offset in DA_BR.bin: 0x694E0
· Command loop: FUN_400084cc
· fp_read_host_file: FUN_4002afd8
· Read callback: FUN_4002aa28 (via thunk 0x40007ea4 at .data offset 0x54A48)
· malloc core: FUN_40008b10
· malloc wrapper: FUN_4000a390
· heap_init: FUN_40008e64
· DPC called-fn field: 0x4006a570
· DAL/DI: 0x4001033c (oplus_security_verify_sec_policy)
· g_oplus_auth_status: 0x40054C88
· g_dual_cache_base: 0x40069da8

Key addresses (420EX01 DA2, for reference)

· heap_base: 0x40070e00
· dpc called-fn: 0x40069df0
· get_node wrapper: 0x4000a59c
· cmd_loop: 0x4000875c
· reg_cmd: 0x400086d4

Hashes (SHA-256)

· DA_BR.bin (2710EX01): 2e15a832b58e500505b785c1bb2817c77614b1c7475b2c84511015fa9e65d245
· DA_420EX01.bin: f80607f31b9e9f4d2e5a4c11323644bd4c301bd4080fabfddfd2ce7848f6266e
· DA2_extracted.bin: f95f2b82...de47
· DA2_420EX01_extracted.bin: 6133db37...f529cb

Key external references

· bkerler/mtkclient issue #409 (this investigation)
· bkerler/mtkclient PR #410 (ea29ia — DA2 pre-patching)
· Penumbra issue #134 (DekuzenOkahiro — same device)
· Penumbra discussion #153 (original NAK wall thread, closed)
· SSTIC 2024 "When Samsung meets MediaTek: the story of a small bug chain" (Rossi, Bellom, Neveu)
· R0rt1z2's HeapBait writeup (Jan 2026)
· MTK Security Bulletins 2024-2025 (CVE-2024-20056, CVE-2025-20635, CVE-2025-20650, CVE-2025-20658, CVE-2025-20696, CVE-2025-20730)

Diagnostic commands used

· python mtk.py r gpt /tmp/gpt.bin --preloader <preloader> --loader <DA> --uartloglevel 0 --logchannel USB
· Ghidra 12.1 headless with PyGhidra (JDK 21)
· trace_decode_logprobe.py for heap traces

---

End of REASONING_TRAIL.md
