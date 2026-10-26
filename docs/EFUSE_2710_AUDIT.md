# EFUSE handlers — 2710EX01 DA2 (`DA2_extracted.bin` from bkerler/mtkclient#409 attachment, 358,160 B, sha256 f95f2b82c684115a…, base VA 0x40000000, file off = VA − 0x40000000)

## 0. Headline correction to the task anchors

The anchors "WRITE-EFUSE handler at 0x4000599C / READ-EFUSE at 0x40005A80" are **wrong for this build**.
Those VAs contain `cmp r1,r0 / blt −8 / ldr r1,[sp,#0x30]…` — the tail of a table-walk loop (`0x40005988: ldr r3,[r6,r2]; cmp r3,#2; beq …; add r1,#1; add r2,#0x48; cmp r1,r0; blt 0x40005988`) inside an unrelated dispatcher, not a handler entry. No reference to 0x4000599C/0x40005A80 exists anywhere in the image (no literal dword, no ARM movw/movt pair, no Thumb pair).

The real handlers were resolved from the registrar itself (Task 1).

## 1. Registrar resolution (2710EX01)

Registrar: `0x400083DC(name, group, handler)` — allocates 20-byte node `{next, group, name, 0, handler}`, pushes onto list head `0x40054ABC` (BSS-safe: head dword lives at file-off 0x54ABC? no — head pointer var is in the loaded region; list built at runtime).

Registration site `0x40001A78` (ARM, movw/movt materialized args):

```
0x40001A80  movw r4,#0x161b ; movt #0x4004   ; r4 = 0x4004161B = "1"   (group)
0x40001A84  movw r0,#0x161f ; movt #0x4004   ; r0 = "CMD:WRITE-EFUSE" (0x4004161F)
0x40001A88  movw r2,#0x5c20 ; movt #0x4000   ; handler 0x40005C20
0x40001A9C  bl  0x400083DC
0x40001AA0  movw r0,#0x162f ; movt #0x4004   ; r0 = "CMD:READ-EFUSE" (0x4004162F)
0x40001AA4  movw r2,#0x5d04 ; movt #0x4000   ; handler 0x40005D04
0x40001AB4  bl  0x400083DC
```

**Confirmed: CMD:WRITE-EFUSE → 0x40005C20, CMD:READ-EFUSE → 0x40005D04.**

Gated siblings registered in the same two setup functions (0x40001A78… and 0x40001D24…):

| name (VA) | handler |
|---|---|
| CMD:WRITE-EFUSE (0x4004161F) | 0x40005C20 |
| CMD:READ-EFUSE (0x4004162F) | 0x40005D04 |
| CMD:GET-HW-INFO (0x4004163E) | 0x40006200 |
| CMD:WRITE-PARTITION (0x400416B4) | 0x400022B4 (skipped when "read back mode") |
| CMD:WRITE-FLASH (0x400416C8) | 0x400030EC |
| CMD:WRITE-PARTITIONS (0x4004177A?) | 0x40002818 |
| CMD:READ-PARTITION-TABLE | 0x400038A4 |
| CMD:DEBUG:UFS | 0x40006D5C |
| CMD:EMMC-CONTROL | 0x40006798 |
| CMD:REBOOT | 0x40005E2C |
| CMD:READ-PARTITION | 0x40003554 |
| CMD:READ-FLASH | 0x40003674 |
| CMD:ERASE-PARTITION | 0x40003A64 |
| CMD:ERASE-FLASH | 0x40003C38 |
| CMD:SET-BOOT-MODE (0x40041795) | 0x40006008 |
| CMD:WRITE-PRIVATE-CERT (0x400417A7) | 0x400060D8 |
| CMD:GET-DA-INFO (0x400417BE) | 0x40006668 |
| CMD:SET-HOST-INFO (0x400417CE) | 0x400021E8 |
| CMD:GET-DOWNLOADED-IMAGE-FEEDBACK (0x400417E0) | 0x40007304 |
| CMD:NOTIFY-INIT-HW (0x40041802) | 0x40002194 |
| CMD:SECURITY-SET-ALLINONE-SIGNATURE (0x40041815) | 0x4000695C |
| CMD:GET-SYS-PROPERTY (0x40041839) | 0x400073E4 |
| CMD:SECURITY-GET-DEV-FW-INFO (0x4004185D) | 0x40006A44 |
| CMD:SECURITY-SET-FLASH-POLICY (0x4004187A) | 0x40006B8C |
| CMD:OPLUS-WRITE-HASH256-ID (0x40041898) | 0x40000A28 |
| CMD:OPLUS-GET-CPUID (0x400418B3) | 0x40000AB8 |
| CMD:OPLUS-STORAGE-INFO (0x400418C7) | 0x40000BA8 |

Feature registrar `0x4000845C(name, value)` (12-byte nodes, head 0x4006A608): `bl 0x4000845C("DA.SLA","ENABLED")` at 0x40001D8C. **No READ-REGISTER / WRITE-REGISTER commands exist on this build** — the register-access gate context is the generic CMD table, and there is no register R/W command at all.

### Dispatch gate (context)
The CMD table is not registered at boot. `CMD:SECURITY-SET-FLASH-POLICY` (0x40006B8C, block 0x40006CBC) pulls a file from the host (0x4002AFD8, tag `"SEC-POLICY"`), verifies it (`bl 0x400076DC(data,len)`); on failure it logs **"Server is not authenticated. Locked."** (0x40042FFA, ref 0x40006D2C) and returns 0xE0000010; only on success does it `bl 0x40001A78` — the registration function above. So the whole CMD:* surface, including both EFUSE commands, is gated behind that verified policy/auth file (plus the OPLUS download-authorization path, `g_oplus_auth_status`, 0x40010374). No *additional* per-command SLA check was found inside the EFUSE handlers themselves.

## 2. Handler disassembly

### CMD:WRITE-EFUSE — 0x40005C20 (ARM)
```
r6=conn, r4=packet
bl 0x40008134                       ; session/lock helper
mov r2,#0x4000ED18 ; mov r0,#0 ; mov r1,r4
bl 0x4000CFEC                       ; parse XML packet → node (r4)
cmp r0,#0 ; beq 0x40005CC4          ; fail: log [0x40054924] "Required XML node path not found…" ; ret 0xC0010001
mov r1,#0x40041B7A                  ; "da/arg/source_file"
bl 0x400020AC                       ; get string value
cmp r0,#0 ; beq 0x40005CE0          ; fail, ret 0xC0010001
r5 = 0xC0010001
mov r1,r0 ; r0=0 ; r2=sp+12 ; r3=sp+8 ; [sp]="efuse"(0x40042679)
mov r0,r6 ; bl 0x4002AFD8           ; fetch host file (tag "efuse") → [sp+8]=len, [sp+12]=buf
cmp r0,#0 ; bmi end
r1=[sp+8](len) ; r0=[sp+12](buf)
bl 0x40007EA8                       ; dev_efuse_write(buf,len)
r5=r0 ; free(buf) (0x4002B36C)
end: free(node) 0x4000E9C4 ; return r5
```
- **Parses:** XPath `da/arg/source_file` only.
- **Backend:** `dev_efuse_write` (0x40007EA8, ARM):
```
cmp r0,#0 ; beq 0x40007F14          ; null buf → r4=0xC0030007, log "Invalid parameters." (0x4004356D)
mov r5,r1(len) ; mov r4,r0(buf)
bl 0x4000791C                       ; log level
cmp r5,#0x200 ; bne 0x40007F34      ; *** ONLY bounds check: len must be EXACTLY 512 ***
                                    ; else 0xC0030007 + "efuse img size is incompatible." (0x40043582)
log "\n Enter dev_efuse_write.\n" (0x400435A3)
mov r1,#0x6F706C75 ; mov r2,#0x63657274   ; "oplu"/"cert" (BE ascii) magic args
mov r0,r4 ; blx 0x40031A18          ; efuse blow engine (Thumb)
log "Exit dev_efuse_write.\n" (0x400400435BD)
return r4 (engine result)
```
- **Return:** 0 on success, 0xC0030007 on bad size/ptr, engine error codes (0x10000 battery, 0x400000 verify, 0x2000000 reinit, 0x1000000 blow-busy-timeout) otherwise.

### Blow engine — 0x40031A18 (Thumb) — the real writer
```
r4=buf(512B), r5=r1(magic, UNUSED after 0x40031A58), r9=r2(magic, UNUSED)
log 0x40054053
r0=0,r1=buf,r2=0 → blx 0x4000CFEC           ; parse the 512-byte image AS XML
  (node==0 → 0x40031ADC: log, bl 0x4003189E reinit, … error paths)
walk sections via 0x4000ED20 (iterate child nodes) and 0x40032C26/0x40032C44 (name compare):
  "debug"   → lock_voltage / lock_vcore_time / write / fsource voltage knobs (logs 0x40050F6D, 0x40050F99)
  "write"   → build blow_list[]: per child node, 0x4000CD2C(node,"address") + 0x4000AE8C(atoi) →
              blow_list[i] = {efuse_addr, efuse_data} (8 bytes each; logs "[EFUSE] blow_list[%d].efuse_addr= 0x%x / .efuse_data= 0x%x", 0x4005104A/0x40051073)
              *** NO validation of efuse_addr against any table — raw value from XML ***
  "verify"  → verify_list[] (addr/data pairs), same unvalidated construction
  per-section validators invoked via callbacks: 0x400326F4/0x40032736/0x4003277A… (sbc-related content checks:
    "[EFUSE] Error: sbc related enable" 0x4005065C @0x40032758; require companion key-hash words non-zero)
battery/power gate: [0x11C104C0] bit31 → "[EFUSE] battery voltage (%x) is too low" → err 0x10000
bl 0x400318EA(1)                             ; BPKEY: [0x11C10008] = 0x6B32970A ("[EFUSE] EFUSE unlock")
for each blow_list entry:                    ; loop 0x40031DE6–0x40031E0E
    log "[EFUSE] blow_list[%d].efuse_addr= 0x%x"
    ldrd r0,r1,[r5]                          ; (addr, data) straight from XML
    bl 0x4003184A                            ; raw write — NO range check on r0
then verify stage ("[EFUSE] ========da_efuse_blow_handle: verify …" 0x40050EED):
    per verify entry: bl 0x4003189E (reinit), r4 = [verify_addr] (direct load), cmp expected r3,[fp] ;
    mismatch → "[EFUSE] …verify failed: 0x%x != 0x%x" (0x40050C96) and r6 |= 0x100000
bl 0x400318EA(0)                             ; BPKEY lock ("[EFUSE] EFUSE lock")
return r6 (0 = success)
```

Raw write primitive **0x4003184A(addr, data)** (Thumb):
```
ip = 0x11C10000 ; wait [ip] bit1 set, timeout 0x1000   (controller ready)
[r0] = r1                                   ; *** arbitrary 32-bit store to addr ***
wait [ip] bit1 again, timeout 0x1000
success → return 0 ; timeout → log 0x40054067, return 0x1000000
```
Init/reinit **0x4003189E**: `[0x11C10000] |= 4`, wait bit0 (timeout 0x100000) → 0 / 0x2000000 + "[EFUSE] Error: reinit fail" (0x4004FE4D).
BPKEY **0x400318EA**: writes 0x6B32970A (unlock) / other (lock) to **0x11C10008**.

### CMD:READ-EFUSE — 0x40005D04 (ARM)
```
parse packet 0x4000CFEC(0, packet, 0x4000ED18); get "da/arg/target_file" (0x40041AF7) via 0x400020AC
r0=0x5000 ; bl 0x4000A390 (malloc 20480)
memset(buf,0,0x5000) (0x4000B2C8)
bl 0x40007F58(buf, 0x5000)                   ; dev_efuse_read
   → Thumb 0x40031964: memset global 0x4006EFD4 (128B), header "==read the blown efuse list==" (0x40050022),
     then loop 37× over the fixed field table at 0x400571F8 (stride 24):
       r0 = entry[0] (hw register), read value, entry[1] = mask,
       format "idx[0x%x] = 0x%x\n" (0x40050041) into 128B chunks, append into dump buffer
     returns 0 ALWAYS (wrapper 0x40007F58 returns 0 unconditionally; only caller checks buf)
buf[0x4FFF]=0 ; bl 0x4000B600 (length) ; send response 0x4002B49C(conn, target_file, buf, len+1, [sp]="efuse")
return 0xC0010001 on any earlier failure
```
- **Parses:** XPath `da/arg/target_file`. **Backend:** fixed-table dump from efuse controller shadow registers 0x11C1xxxx (direct register reads — no mailbox/TEE call in this path). **Return:** always 0 from the wrapper; handler returns 0xC0010001 only on malloc/transfer failure.

Platform note: the controller register base **0x11C10000** and `[0x11C104C0]` battery flag identify this as a **UNISOC (Spreadtrum) AON efuse controller**, not MTK — the "secure-world mailbox 0x1021xxxx" hypothesis does not apply; the write path is direct controller register access from the DA.

## 3. Efuse ID whitelist (2710EX01)

There is **no switch and no (id→action) table for commands**; the only whitelist is the **fixed 37-entry field table at 0x400571F8** used exclusively by the READ dump. Entry = `{hw_reg, mask, code, shadow_reg, shadow_mask, x}`; id = code & 0xFF:

| id | hw_reg | mask | id | hw_reg | mask |
|----|--------|------|----|--------|------|
|0x03|0x11C10070|0xFFFFFFFF|0x14|0x11C1051C|0xFFFFFFFF|
|0x04|0x11C10074|0xFFFFFFFF|0x15|0x11C10520|0xFFFFFFFF|
|0x05|0x11C10078|0xFFFFFFFF|0x16|0x11C10524|0xFFFFFFFF|
|0x06|0x11C1007C|0xFFFFFFFF|0x17|0x11C10850|0xFFFFFFFF|
|0x07|0x11C10090|0xFFFFFFFF|0x18|0x11C10854|0xFFFFFFFF|
|0x08|0x11C10094|0xFFFFFFFF|0x19|0x11C10858|0xFFFFFFFF|
|0x09|0x11C10098|0xFFFFFFFF|0x1A|0x11C1085C|0xFFFFFFFF|
|0x0A|0x11C1009C|0xFFFFFFFF|0x1B|0x11C10020|0x1417|
|0x0B|0x11C100A0|0xFFFFFFFF|0x1C|0x11C10060|0x48037F|
|0x0C|0x11C100A4|0xFFFFFFFF|0x1D|0x11C104A0|0x2|
|0x0D|0x11C100A8|0xFFFFFFFF|0x1E|0x11C104C4|0xFFFFFFFF|
|0x0E|0x11C100AC|0xFFFFFFFF|0x1F|0x11C104C8|0xFFFFFFFF|
|0x0F|0x11C10030|0xFFFF|0x20|0x11C10808|0x8000|
|0x10|0x11C10038|0xFFFF|0x21|0x11C104A4|0x8|
|0x11|0x11C10510|0xFFFFFFFF|0x22|0x11C104C0|0x1|
|0x12|0x11C10514|0xFFFFFFFF|0x23|0x11C104CC|0x1FF|
|0x13|0x11C10518|0xFFFFFFFF|0x24|0x11C10068|0x1F|
|    |          |          |0x25|0x11C10028|0x6|
|    |          |          |0x2A|0x11C10830|0x7F|
|    |          |          |0x2B|0x11C1080C|0xFFFFFFFF|

The dump/dispatch code names the security fields (strings "Secure Setting"/"Lock Setting" dump, 0x40032C88): main ctrl word `[ctx+0]`: **bit1 = sbc_en, bit2 = daa_en, bit3 = sla_en, bit0 = jtag_dis, bit6 = Enable_SW_JTAG_CON, bit8 = Disable_Rom_Cmd**; `[ctx+0x440]`: bit1 = md1_sbc_en, bit0 = c2k_sbc_en; 11 words of sbc_pub_key_hash `[ctx+0x30..]`; lock word `[ctx+8]`: **bit2 = sec_ctrl_lock, bit0 = sbc_pubk_hash_lock**. The masked low-flag ids (0x1B mask 0x1417 = bits 0,1,2,4,8,12 over 0x11C10020; 0x1C mask 0x48037F; 0x1D mask 2; 0x22 mask 1; 0x25 mask 6 …) are exactly these single-bit security/lock words.

**Writable IDs: ALL of them — the write path has no ID concept at all.** The blow list carries raw controller addresses taken verbatim from the XML image; nothing maps or filters them against the 37-entry table. So every security-relevant word above (SBC/DAA/SLA enable, JTAG-disable, sec_ctrl_lock, sbc_pubk_hash_lock, pub-key hash words) is writable by the DA through CMD:WRITE-EFUSE on any device where the guard below does not trigger.

## 4. SLA/DAA-relevant bits and the "no efuse-driven auth-state writer" claim

- The security-word bits (sbc_en/daa_en/sla_en/sec_ctrl_lock/sbc_pubk_hash_lock) are read into the "Efuse Secure Setting"/"Efuse Lock Setting" dump (0x40032C88) and validated by per-section callbacks.
- The deciding guard is **0x40032DC4** (last address of the issue's own list):
```
0x40032DC8  ldrb r0,[r4,#8]        ; lock word
0x40032DCC  lsls r0,r0,#31 ; bne 0x40032DE0      ; lock bit0 set → ALLOW blow
0x40032DD0  ldr  r0,[r4,#0x70]    ; secure-ctrl shadow
0x40032DD2  lsls r1,r0,#30 ; bpl 0x40032DE0      ; sbc_en(bit1)==0 → ALLOW
0x40032DD6  lsls r1,r0,#29 ; bpl 0x40032DE4      ; daa_en(bit2)==0 → FORBIDDEN
0x40032DDA  ands r0,r0,#0x41 ; beq 0x40032DE4    ; (jtag bits 0&6)==0 → FORBIDDEN
0x40032DE0  movs r0,#0 ; return                  ; ALLOW
0x40032DE4  log "[EFUSE] Error: SBC & DAA & (EN_JTAG_CON or Dis_JTAG) should be 1, forbidden blow" (0x4005129D)
            log "secure-ctrl: %x" (0x400512EF... "[EFUSE] control: %x" 0x400512EF region)
            return 0x400000
```
- So: **an efuse-driven auth-state writer DOES exist** (CMD:WRITE-EFUSE → raw blow of the secure-control word) — the claim "no efuse-driven auth-state writer exists" is **refuted at the structural level**. Mitigating facts:
  1. OTP semantics: bits can only be driven 0→1; sbc_en/daa_en cannot be *cleared* by this path (no "unset" mechanism exists anywhere in the image).
  2. The 0x40032DC4 guard refuses further blows on devices whose SBC state is already engaged (sbc_en=1 without daa_en+JTAG-console), and "Unlock Blow Protect Error" (0x40050E14, ref 0x400320F2) plus "Unlock Blow Failed" (0x4005025D) show a protected unlock-key flow exists in the module.
  3. Reachability requires passing the SEC-POLICY/OPLUS authorization gate first (§1).
- Remaining risk: on a **factory-fresh / SBC-off** unit, an authorized (or auth-bypassing) host can blow sbc_en/daa_en/Dis_JTAG/sec_ctrl_lock in one shot — permanently enabling (or misconfiguring) security, bricking debug, or, on units where a *disable*-polarity bit is the security control (e.g. jtag_dis family), weakening it. That is a real, reachable write of the bits backing SLA/DAA state.

## 5. Classic-flaw audit of the WRITE path

| flaw | finding |
|---|---|
| index computed before bounds check | N/A — no index arithmetic; blow_list is (addr,data) pairs, count comes from XML child iteration (`bl 0x40032C44` count, `lsls #3` alloc 0x40031C86; alloc size = n*8, no overflow at realistic n) |
| 64-bit wrap on (id*32+offset) | N/A — no id*32 math on the write path (that pattern belongs to MTK builds; here addresses are literal) |
| signed/unsigned compare | `cmp r5,#0x200; bne` — equality, not range; no signedness issue. `bl 0x40007F58` ret is ignored (always 0) |
| missing whitelist on write path | **CONFIRMED** — read path enumerates exactly 37 table-mapped fields; write path accepts arbitrary `efuse_addr` values, and 0x4003184A performs `[r0]=r1` with **zero address validation**. Since the verify stage also does `ldr r4,[verify_addr]` and logs mismatches, the same XML doubles as an arbitrary-read oracle |
| exact-size gate | the only hard gate: `cmp r5,#0x200 / bne → 0xC0030007 "efuse img size is incompatible."` (0x40007EC4) |

## 6. Verdict

**BUGGY (write path), SOUND (read path).**

| path | parse | bounds check | backend | gate | verdict |
|---|---|---|---|---|---|
| CMD:READ-EFUSE 0x40005D04 | XML `da/arg/target_file` | malloc 0x5000; fixed 37-entry table only | direct reads of 0x11C1xxxx shadow regs (0x40031964) | SEC-POLICY auth gate (table registration) | SOUND — enumeration limited to whitelisted ids |
| CMD:WRITE-EFUSE 0x40005C20 | XML `da/arg/source_file` → 512-byte efuse image XML (write/verify/debug sections) | **only** `cmp len,#0x200 / bne fail` (0x40007EC4) | raw `[addr]=data` store + busy-wait (0x4003184A), BPKEY 0x6B32970A → 0x11C10008 (0x400318EA) | auth gate + content guard 0x40032DC4 (only blocks already-SBC-locked devices) | BUGGY — no per-id/address whitelist; arbitrary-address store + read-back |

Deciding quotes:
- `0x40007EC4: cmp r5, #0x200 ; 0x40007EC8: bne 0x40007F34` — sole write-path size check (exact 512).
- `0x40031DF8: bl 0x4003184A` preceded by `ldrd r0,r1,[r5]` with no mask/range check — raw (addr,data) blow.
- `0x4003186C: str r1, [r0, #0]` — the unvalidated store.
- `0x40032DDA: ands r0, r0, #0x41 ; beq 0x40032DE4` + string 0x4005129D — the only content guard, and it triggers only for already-secured (SBC-engaged) devices.

Read-only host probe to demonstrate (no flash/otp side effects beyond what efuse already reflects):
1. Post-auth, send `CMD:WRITE-EFUSE` with a 512-byte XML image whose `<write>` section holds a single entry `address=0x11C10534, data=<current value>` and `<verify>` section `address=0x11C10534, data=<current value>` — a no-op blow against the sbc_pub_key_hash shadow word. Acceptance of an address *outside* the 37-id table range (e.g. 0x11C10860 or any unmapped 0x11C1xxxx word) with a matching verify pass proves no whitelist; the same XML with `address=<DA RAM addr>` + verify would additionally demonstrate the arbitrary store primitive (destructive — do not run on hardware you keep).
2. Contrast: `CMD:READ-EFUSE` output is strictly the 37 "idx[id] = value" lines — request cannot widen it.

**UNRESOLVED (one piece):** the exact behavior of `0x400076DC` (SEC-POLICY/auth-file verifier, called at 0x40006D0C) — whether its signature check is oplus-key-pinned or forgeable determines whether the WRITE-EFUSE path is attacker-reachable on a stock unit. Everything after that verifier is fully characterized above.
