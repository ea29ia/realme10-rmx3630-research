# Phase 1 priority list (merged: 3-way diff + reachability + string tags)

## PRIORITY A — OPLUS-added/modified (3-way diff unique to 2710EX01)
[A] 0x40001504 | FUN_40001504 | size=736 | reachable=True | handler=False | libc=- | tags=storage
      strings: malloc checksum buffer failed.
 | info list is unavailable.
 | buffer to store read back data is invalid. buffer_len:0x%x
 | read length: 0x%llx
 | %s: read data failed[0x%x]
 | storage_checksum_examine | storage checksum failed: pre_checksum[0x%x]!=post_checksum[0x%x]

[A] 0x40001a78 | FUN_40001a78 | size=684 | reachable=True | handler=False | libc=- | tags=CERT,EFUSE,oplus
      strings: CMD:WRITE-EFUSE | CMD:READ-EFUSE | CMD:GET-HW-INFO | [oplus] do not get oplus permission
 | [oplus] in read back mode, can not register cmd_write_partition
 | CMD:WRITE-PARTITION | CMD:WRITE-FLASH | CMD:WRITE-PARTITIONS | CMD:READ-PARTITION-TABLE | CMD:DEBUG:UFS | CMD:EMMC-CONTROL | CMD:REBOOT | CMD:READ-PARTITION | CMD:READ-FLASH | CMD:FLASH-ALL |
[A] 0x40001e0c | FUN_40001e0c | size=540 | reachable=True | handler=False | libc=- | tags=-
      strings: Invalid parameters
 | record_history.bin length 0x%x, expected length 0x%x
 | record_history.bin content corrupt, cnt value %d
 | record_history.bin contain wrong protection %s

[A] 0x40002818 | FUN_40002818 | size=2260 | reachable=True | handler=True | libc=- | tags=auth,hash,ownload
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/source_file | Download partition [%s]
 | hash_binding:%d, img_auth_required:%d
 | Security deny for [%s].
 | Security deny for [%s].
 | Erase [%s] At[0x%llx] Len[0x%llx]
 | Erase [%s] At[0x%llx] Len[0x%llx]
 | EXISTS | EXISTS |
[A] 0x400030ec | FUN_400030ec | size=1128 | reachable=True | handler=True | libc=- | tags=ost file,ownload,storage
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/partition | da/arg/source_file | Download partition [%s]
 | Security deny for [%s].
 | Erase [%s] At[0x%llx] Len[0x%llx]
 | da/arg/offset | Cannot find [%s] on current device storage. | [%s]Base address[0x%llx] is larger than p
[A] 0x40003c38 | FUN_40003c38 | size=1320 | reachable=True | handler=True | libc=- | tags=storage
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/partition | Security deny for [%s].
 | Erase [%s] At[0x%llx] Len[0x%llx]
 | da/arg/offset | Cannot find [%s] on current device storage. | partition_list: %s
 | da/arg/length | ERASE | NAND-BMT | offset is larger than partition 
[A] 0x40006200 | FUN_40006200 | size=1128 | reachable=True | handler=True | libc=- | tags=storage
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/target_file | cmd_get_hw_info malloc fail. | 3DMLC | <?xml version="1.0" encoding="utf-8"?><da_hw_info><version>1.0</version><ram_size>0x%llx</ram_size><battery_voltage>%d</battery_voltage><random_id>%s</random_id><storage>%s</
[A] 0x400084cc | FUN_400084cc | size=1604 | reachable=True | handler=False | libc=- | tags=-
      strings: da/version | reboot | <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version><command>CMD:START</command></host> | <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version><command>CMD:START</command></host> | <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version><command>CMD:START</command></host> | <?xml version="1
[A] 0x4000b858 | FUN_4000b858 | size=636 | reachable=True | handler=False | libc=- | tags=cert,storage
      strings: No storage is found. | cert file invalid. | cert file invalid. | Cannot alloc 0x%x. | cert file is invalid. | write cert file header fail. | write cert file fail.
[A] 0x4000bad4 | FUN_4000bad4 | size=2092 | reachable=True | handler=False | libc=- | tags=hash,oplus,ownload
      strings: %s: !!! memalign fail 

 | start_download | USB error(buf_total_length). maybe coding defect. | Data size bigger than partition max size.
 | Host Notify error. | download error. code 0x%x | USB checksum error, chksum in PC is 0x%x, chksum in RAM is 0x%x
 | write preloader fail 
 | size too large, space small. | erase preloader before download faile
[A] 0x4000c470 | FUN_4000c470 | size=680 | reachable=True | handler=False | libc=- | tags=storage
      strings: * Preloader data len 0x%x
 | create preloader header block error[0x%x]
 | * Preloader write sn[0x%x] at[0x%llx] data[0x%x] len[0x%x]
 | storage_interface.read Failed.
 | storage checksum error, chksm in dram is 0x%x, chksm in storage after read is 0x%x

[A] 0x4000c764 | FUN_4000c764 | size=780 | reachable=True | handler=False | libc=- | tags=security
      strings: * Preloader do not contain HB
 | security get HB size failed, status: 0x%x.
 | * Preloader HB size 0x%x
 | malloc preloader HB buffer failed.
 | malloc preloader HB buffer failed.
 | malloc preloader data buffer failed.

[A] 0x4000fb54 | FUN_4000fb54 | size=2024 | reachable=True | handler=False | libc=- | tags=OPLUS,cert,efuse,hash,oplus,security
      strings: Set serial # from efuse. errcode: %d
 | sn_buf1 %s | 0123456789ABCDEF | [OPLUS] efues_version_read_status :%d
 | [OPLUS] efuse_otp_version :%d
 | [OPLUS] atf cert1 version %d
 | [OPLUS] atf cert2 version %d
 | [OPLUS] get random_num: %d
 | [OPLUS] get fw info failed
 | [OPLUS] hash256 64 from ofp: %s
 | [OPLUS] old hash256 sec_read_wrapper() oplus_
[A] 0x4001033c | oplus_security_verify_sec_policy | size=892 | reachable=True | handler=False | libc=- | tags=OPLUS,auth,oplus,ownload,sec_policy,security,signature
      strings: [OPLUS]%s start, g_oplus_auth_status=%d buf_sz=%x | oplus_security_verify_sec_policy | [OPLUS] this is read back mode , %d
 | [OPLUS] this is read back mode , %d
 | [OPLUS] this is read back mode , %d
 | [OPLUS] verify signature of device info. 
 | [OPLUS] verify signature of device info. 
 | [OPLUS] Dev Mode
 | [OPLUS] not Dev 
 | [OPLUS]buf_sz < 
[A] 0x40013020 | FUN_40013020 | size=848 | reachable=True | handler=False | libc=- | tags=-
      strings: preloader | partition is in this range: %s
 | partition count in partition list  is %d.
 | allocate partition buffer failed.
 | preloader is in this range.
 | preloader backup is in this range.
 | Invalid section for EMMC & UFS.

[A] 0x4002afd8 | FUN_4002afd8 | size=916 | reachable=True | handler=False | libc=- | tags=eadHost,ead_host,ost file,ownload
      strings: Host notice error or user canceled.
 | USB error or buffer is too small to contain all data. | USB error or buffer is too small to contain all data. | <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version><command>CMD:DOWNLOAD-FILE</command><arg><checksum>%s</checksum><info>%s</info><source_file>%s</source_file><packet_length>0x%x</pack
[A] 0x4002bff4 | FUN_4002bff4 | size=1524 | reachable=True | handler=False | libc=- | tags=ownload,storage
      strings: Max partition count in scatter file overflow. | EMMC_BOOT1 | EMMC_BOOT1 | EMMC_BOOT1 | EMMC_BOOT2 | EMMC_BOOT2 | EMMC_BOOT2 | allocate ss->tbl.info buffer failed.
 | allocate ss->aux_tbl.info buffer failed.
 | Scatter file XML parser exception. | storage_type | Scatter File Content:
 | partition_index | partition_index | partition_name | file_name 
[A] 0x4002db64 | FUN_4002db64 | size=668 | reachable=True | handler=False | libc=- | tags=-
      strings: Dynamic flash space mapping:VA[0x%llx,0x%llx] OFFSET:0x%llx
 | The set space overlapped. | The set space[start: 0x%llx, length: 0x%llx] is larger than partition size[0x%llx].
[A] 0x4002f82c | FUN_4002f82c | size=388 | reachable=True | handler=False | libc=- | tags=-
      strings: allocate g_dual_cache_base failed.

[A] 0x40032f9c | FUN_40032f9c | size=916 | reachable=True | handler=False | libc=- | tags=-
      strings: key_derive fails(0x%x)
 | [%s] Invalid address
 | [%s] Invalid address
 | rpmb_hmac | rpmb_hmac | [%s] size over maximum allowed size
 | [%s] size is zero
 | hmac status 0x%x
 | fail to execute sha256 (0x%x)
 | fail to execute sha256 (0x%x)


## PRIORITY B — reachable, calls libc-like or security-tagged, not audited
[B] 0x40001d24 | cmd_handler_allinone_signature | handler=False | libc=- | tags=CPU,HASH,OPLUS,PROPERTY,SECURITY,SIGNATURE,SLA,STORAGE
      strings: CMD:NOTIFY-INIT-HW | CMD:SECURITY-SET-ALLINONE-SIGNATURE | CMD:GET-SYS-PROPERTY | DA.SLA | ENABLED | CMD:SECURITY-GET-DEV-FW-INFO | CMD:SECURITY-SET-FLASH-POLICY | CMD:OPLUS-WRITE-HASH256-ID | CMD:OPLUS-GET-CPUID | CMD:OPLUS-STORAGE-INFO
[B] 0x400022b4 | FUN_400022b4 | handler=True | libc=- | tags=auth,hash,ownload
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/partition | da/arg/source_file | da/arg/pre_erase | Download partition [%s]
 | Cannot find [%s] info from partition table.
 | h
[B] 0x40003674 | FUN_40003674 | handler=True | libc=- | tags=storage
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/target_file | da/arg/partition | da/arg/offset | Cannot find [%s] on current device storage. | Upload partition [%s]
 | da/arg/
[B] 0x40004160 | FUN_40004160 | handler=True | libc=- | tags=auth,hash
      strings: da/version | da/arg/source_file | hash_binding:%d, img_auth_required:%d
 | hash_binding:%d, img_auth_required:%d
 | Security deny for [%s].
 | Erase [%s] At[0x%llx] Len[0x%llx]
 | Erase [%s] At[0x%llx] Len[0x%llx]
 | EXISTS | EXISTS | get verified im
[B] 0x40004af8 | FUN_40004af8 | handler=True | libc=- | tags=oplus,ost file,ownload
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/version | da/arg/source_file | Security deny for [%s].
 | Erase [%s] At[0x%llx] Len[0x%llx]
 | Erase [%s] At[0x%llx] Len[0x%llx]
 |
[B] 0x40005c20 | FUN_40005c20 | handler=True | libc=- | tags=efuse
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/source_file | efuse
[B] 0x40005d04 | FUN_40005d04 | handler=True | libc=- | tags=efuse
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/target_file | efuse
[B] 0x40005e2c | FUN_40005e2c | handler=True | libc=- | tags=OPLUS,oplus
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/action | reboot | OPLUS_DELAY_REBOOT | [OPLUS]oplus_dev_wdt_reset
 | OPLUS_REBOOT_TO_EDL | [OPLUS] oplus_set_reboot_edl
 | IMME
[B] 0x40006798 | FUN_40006798 | handler=True | libc=- | tags=ost file
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/target_file | da/arg/function | LIFE-CYCLE-STATUS | LIFE-CYCLE-STATUS | EXHAUSTED | WARNING | WARNING | WARNING | WARNING | Wri
[B] 0x40006b8c | cmd_security_set_remote_sec_policy | handler=True | libc=- | tags=auth,emote,sec_policy,security
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/arg/source_file | Not get DevFWInfo.
 | is_get_DevFWInfo=%d
 | da/arg/preloader_sig_ver | %s: do not find da/arg/preloader_sig_ver,
[B] 0x40006d5c | FUN_40006d5c | handler=True | libc=- | tags=oplus
      strings: Required XML node path not found. Check command string. | Required XML node path not found. Check command string. | da/version | da/arg/source_file | ERASE | preloader | da/arg/function | UPDATE-FIRMWARE | [oplus] oplus fw file len=%d 
 | [oplus] ufs
[B] 0x40007644 | FUN_40007644 | handler=False | libc=- | tags=cust_,oplus,security
      strings: [oplus]%s:%d
 | cust_security_get_dev_fw_info | MT6789
[B] 0x40007ea8 | FUN_40007ea8 | handler=False | libc=- | tags=efuse
      strings: Invalid parameters.
 | efuse img size is incompatible.
 | 
 Enter dev_efuse_write.
 | Exit dev_efuse_write.

[B] 0x40007f58 | FUN_40007f58 | handler=False | libc=- | tags=efuse
      strings: 
 Enter dev_efuse_read.==%d
 | Exit dev_efuse_read.

[B] 0x4000c3d4 | FUN_4000c3d4 | handler=False | libc=- | tags=ownload
      strings: Download.Started | Download.Finished
[B] 0x400106b8 | FUN_400106b8 | handler=False | libc=- | tags=OPLUS,hash
      strings: [OPLUS] %s() start 
 | write_old_hash256 | write_old_hash256 | [OPLUS]write_old_hash256() : digest_id_offset = 0x%llx , digest_id_size = 0x%llx
 | [OPLUS]sec_write_wrapper two time fail, ret=%d
 | [OPLUS]sec_read_wrapper two time fail, ret=%d
 | [OPL
[B] 0x400108e0 | FUN_400108e0 | handler=False | libc=- | tags=OPLUS,oplus
      strings: [OPLUS] %s,  factory = %d
 | seccfg | [OPLUS] need format %s
 | [OPLUS] do not format %s
 | oplusreserve2 | [OPLUS] need format  %s in smt
 | [OPLUS] do not format %s in upgrade
 | userdata | metadata
[B] 0x40010a28 | FUN_40010a28 | handler=True | libc=- | tags=hash,oplus
      strings: %s:%d
 | cmd_write_hash256_id | [oplus] write_old_hash256 ok | [oplus] write_old_hash256 error | [oplus] write_old_hash256 error

[B] 0x40010ab8 | FUN_40010ab8 | handler=True | libc=- | tags=CPU,OPLUS,cpu,oplus
      strings: da/arg/target_file | [OPLUS] get cpuid_buf: %s
 | GET-CPUID | oplus command string. | oplus command string.
[B] 0x40010ba8 | FUN_40010ba8 | handler=True | libc=- | tags=oplus,storage
      strings: da/arg/target_file | %s is emmc
 | cmd_get_storage_info | cmd_get_storage_info | %s is ufs, sysob_ufs.vendor_id=0x%x
 | %s nand
 | %s is not exist
 | oplus command string. | oplus command string.
[B] 0x40010cdc | FUN_40010cdc | handler=False | libc=- | tags=oplus,storage
      strings: [oplus] %s:%d invalid param.
 | oplus_storage_verfiy_firmware | oplus_storage_verfiy_firmware | [oplus] %s: buffer is too short, length=%d
 | [oplus] ERROR: ufs fw crc error
 | [oplus] INFO: ufs fw crc ok
 | [oplus] storage firmware header: 
 | [oplu
[B] 0x40011000 | FUN_40011000 | handler=False | libc=- | tags=signature
      strings: check gpt header signature failed.
 | check gpt header crc failed.

[B] 0x40012384 | FUN_40012384 | handler=False | libc=- | tags=signature
      strings: ASSERT FAILED at (%s:%d): %s
 | ASSERT FAILED at (%s:%d): %s
 | ASSERT FAILED at (%s:%d): %s
 | Flash new PGPT.
 | Flash new SGPT.
 | check gpt header signature failed.
 | read pgpt failed.
 | read pgpt entry failed.
 | /work/000e/workspace/Build_S_V
[B] 0x4001e830 | FUN_4001e830 | handler=False | libc=- | tags=ownload
      strings: [PLFM] | %s emergency download mode(timeout: %ds).

[B] 0x4001fccc | FUN_4001fccc | handler=False | libc=- | tags=efuse
      strings: efuse_pll_set don't need in DA

[B] 0x4001fd8c | FUN_4001fd8c | handler=False | libc=- | tags=efuse
      strings: vefuse | Err: fsource get
 | Err: fsource set
 | fsource %d, %d

[B] 0x4002007c | FUN_4002007c | handler=False | libc=- | tags=storage
      strings: [%s] can't find boot device(%d)
 | storage
[B] 0x40020118 | FUN_40020118 | handler=False | libc=- | tags=storage
      strings: [%s] can't find boot device(%d)
 | [%s] raw_read fail
 | storage_wrap_read | storage_wrap_read
[B] 0x400201e0 | FUN_400201e0 | handler=False | libc=- | tags=storage
      strings: [%s] can't find boot device(%d)
 | [%s] raw_read fail
 | storage_wrap_write | storage_wrap_write
[B] 0x400202a8 | FUN_400202a8 | handler=False | libc=- | tags=storage
      strings: [%s] can't find boot device(%d)
 | storage_erase | storage_erase | [%s] raw_erase fail

[B] 0x40025d4c | FUN_40025d4c | handler=False | libc=- | tags=auth
      strings: [%s]: RPMB Fail in Sending request get result register response, ret = %d 
 | [%s]: RPMB nonce_buf pointer NULL
 | rpmb_authen_read_counter | rpmb_authen_read_counter | [%s]: RPMB wr_cnt pointer NULL
 | [%s]: RPMB Fail in Sending Write counter read r
[B] 0x40026138 | FUN_40026138 | handler=False | libc=- | tags=auth
      strings: [%s]: RPMB Fail in Sending request get result register response, ret = %d 
 | [%s]: RPMB rpmb_authen_read_counter fail! ret = %d
 | rpmb_ufs_set_wp | rpmb_ufs_set_wp | [%s]: RPMB rpmb_authen_secure_write_protect_conf_block_read fail! ret = %d
 | [%s]
[B] 0x400267c8 | FUN_400267c8 | handler=False | libc=- | tags=auth
      strings: [%s]: RPMB Fail in Sending result register read request, ret = %d 
 | [%s]: RPMB Fail in Sending request get result register response, ret = %d 
 | [%s]: RPMB WriteCounter Read Resp Check Fail, ret = %d 
 | [%s]: RPMB pfrm pointer NULL
 | [%s]: RPMB 
[B] 0x40026eb0 | FUN_40026eb0 | handler=False | libc=- | tags=auth
      strings: [%s]: RPMB rpmb_authen_read_counter fail! ret = %d
 | [%s]: RPMB rpmb_authen_secure_write_protect_conf_block_write Fail! ret = %d
 | rpmb_ufs_clr_wp | rpmb_ufs_clr_wp
[B] 0x4002ae50 | FUN_4002ae50 | handler=False | libc=- | tags=ownload
      strings: USB error or buffer is too small to contain all data. | Download [%s] with file:%s
 | <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version><command>CMD:DOWNLOAD-FILE</command><arg><checksum>%s</checksum><info>%s</info><source_file>%s</so
[B] 0x4002b49c | FUN_4002b49c | handler=False | libc=- | tags=ost file
      strings: Host notice error or user canceled.
 | USB error or buffer is too small to contain all data. | Host notice error.
 | <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version><command>CMD:UPLOAD-FILE</command><arg><checksum>CHK_NO</checksum><
[B] 0x4002b9e0 | FUN_4002b9e0 | handler=False | libc=- | tags=ost file
      strings: Host notice error.
 | REVEIVING CMD Result ERROR.
 | <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version><command>CMD:FILE-SYS-OPERATION</command><arg><key>%s</key><file_path>%s</file_path></arg></host> | Host file system OP: %s

[B] 0x4002cda8 | FUN_4002cda8 | handler=False | libc=- | tags=oplus
      strings: preloader | preloader | default | oplus_single_mode | oplus_single_mode | [SEC_POLICY] in oplus_single_mode
 | [SEC_POLICY] reached the end, use default policy

[B] 0x4002d15c | FUN_4002d15c | handler=False | libc=- | tags=auth,hash,security
      strings: hash =  | ==========security policy==========
 | policy of partition: %s
 | hash_binding = %d
 | img_auth_required = %d
 | dl_forbidden = %d
 | ===================================

[B] 0x4002d860 | FUN_4002d860 | handler=False | libc=- | tags=STORAGE
      strings: Storage checksum failed!
 | [UNSPARSE] Not mapped: VA:0x%llx Len:0x%llx | [BULK] S_STORAGE_WRITE_FAILED:status=0x%x, size=0x%llx

[B] 0x4002e700 | FUN_4002e700 | handler=False | libc=- | tags=STORAGE
      strings: Not mapped: VA:0x%llx Len:0x%llx | S_STORAGE_WRITE_FAILED:%d, status=%d, size=%d
 | S_STORAGE_READ_FAILED:%d, status=%d, size=%d
 | S_STORAGE_CHECKSUM_ERR:%d, post_chksum=0x%x, pre_chksum=0x%x

[B] 0x4002e968 | FUN_4002e968 | handler=False | libc=- | tags=storage
      strings: %s: partial_protect is enabled, start...
 | write_storage | write_storage | %s: ****storage[%d]vs[%d], region[%d]vs[%d]
 | remain: addr[%llx]vs[%llx], len[%llx]vs[%llx]
 p_cur[%p]vs[%p]
****
 | whole region is in protection.
 | not included in the ta
[B] 0x4002eda4 | FUN_4002eda4 | handler=False | libc=- | tags=storage
      strings: [%s]unknow or unsupport storage[%d]!
 | write_labor
[B] 0x4002eec8 | FUN_4002eec8 | handler=False | libc=- | tags=storage
      strings: %s: partial_protect is enabled, start...
 | whole region is in protection.
 | partial included and in the tail
 | partial included and in the front
 | whole included in operation area
 | erase_storage | erase_storage | %s: storage[%d]vs[%d], region[%
[B] 0x4002f340 | FUN_4002f340 | handler=False | libc=- | tags=storage
      strings: [%s]unknow or unsupport storage[%d]!
 | erase_labor
[B] 0x4002f44c | FUN_4002f44c | handler=False | libc=- | tags=storage
      strings: [%s]unknow or unsupport storage[%d]!
 | storage_ctrl
[B] 0x4002f514 | FUN_4002f514 | handler=False | libc=- | tags=storage
      strings: [%s]unknow or unsupport storage[%d]!
 | read_storage
[B] 0x4002f5fc | FUN_4002f5fc | handler=False | libc=- | tags=storage
      strings: [%s]unknow or unsupport storage[%d]!
 | storage_flush
[B] 0x4002f71c | FUN_4002f71c | handler=False | libc=- | tags=signature
      strings: external_signature malloc fail.
[B] 0x4002fa5c | FUN_4002fa5c | handler=False | libc=- | tags=hash,oplus,security,signature
      strings: hash =  | 0x%x  | @[external signature]. at [%s]
 | Security deny [%s] Signature(*.sig) invalid.
 | size too large, space small. image length[0x%llx], partition max size[0x%llx]
 | security_check.
 | image hash binding check fail
 | image hash bindin
[B] 0x40030918 | FUN_40030918 | handler=False | libc=- | tags=ownload,storage
      strings: Download.Started | Download.Finished | write_storage_proc | Download_data end.
 | ERR: start_record_device_action failed[0x%x].
 | ERR: end_record_device_action failed[0x%x].

[B] 0x40030aa4 | FUN_40030aa4 | handler=False | libc=- | tags=storage
      strings: size too large, space small. | read_storage() Failed. status 0x%x

[B] 0x4003184a | FUN_4003184a | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Error: TIMEOUT, mask[%x], data[%x]
[B] 0x4003189e | FUN_4003189e | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Error: reinit fail
 | [EFUSE] Error: TIMEOUT, mask[%x], data[%x]
[B] 0x400318ea | FUN_400318ea | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] EFUSE lock
 | [EFUSE] EFUSE unlock
 | [EFUSE] EFUSE unlock
 | [EFUSE] EFUSE BPKEY set success
 | [EFUSE] Error: EFUSE BPKEY set fail
 | [EFUSE] Error: TIMEOUT, mask[%x], data[%x]
[B] 0x40031964 | FUN_40031964 | handler=False | libc=- | tags=efuse
      strings: ==read the blown efuse list==
 | idx[0x%x] = 0x%x

[B] 0x40031a18 | FUN_40031a18 | handler=False | libc=- | tags=EFUSE,efuse
      strings: vcore | vcore | vcore | vcore | vcore | [EFUSE] Error: reinit fail
 | [EFUSE] Writer disable
 | [EFUSE] battery voltage (%x) is too low
 | [EFUSE] Start Blow Flow ...
 | [EFUSE] Enter da_efuse_blow
 | [EFUSE] Get efuse image, Start Check ...
 | [EFUS
[B] 0x400321a8 | FUN_400321a8 | handler=False | libc=- | tags=EFUSE,hash
      strings: [EFUSE] Error: Img hash is incorrect
 | [EFUSE] Image footer hash[%d]: 0x%x
 | [EFUSE] Img hash is correct

[B] 0x40032202 | FUN_40032202 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] chip init status: reblow(%x), broken(%x), hwecc(%x), hw_auto_ecc_dis(%x), sw_auto_ecc_dis(%x)

[B] 0x40032272 | FUN_40032272 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Set env
 | [EFUSE] Error: Set vcore blow fail

[B] 0x400322a6 | FUN_400322a6 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] idx(%x): S_EFUSE_MARK_RUNTIME_BYPASS
 | [EFUSE] idx(%x): S_EFUSE_MARK_SKIP
 | [EFUSE] idx(%x): hasn't been blown ever
 | [EFUSE] idx(%x): was blown before [0x%x=>0x%x]
 | [EFUSE] idx(%x): has been blown partly(0x%x)
 | [EFUSE] idx(%x): Stat(%
[B] 0x40032498 | FUN_40032498 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] data=%x, %x, %x
 | [EFUSE] data=%x, %x, %x
 | [EFUSE] idx[0x%x] success to write
 | [EFUSE] idx[0x%x] failed to write.
 | [EFUSE] idx[0x%x]: status[%x]
 | [EFUSE] Error: idx(%x): don't need to blow
 | [EFUSE] ECC NA: idx[0x%x], data[0x%x]
 | 
[B] 0x4003266c | FUN_4003266c | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Error: Set vcore high fail
 | [EFUSE] Error: 1st vcore high verify fail
 | [EFUSE] Error: Set vcore low fail
 | [EFUSE] Error: 2nd vcore low verify fail
 | [EFUSE] Error: set vcore high fail

[B] 0x400326f4 | FUN_400326f4 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Error: ackey related enable
 | [EFUSE] ackey %x, buf[%d]=0

[B] 0x40032736 | FUN_40032736 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Error: sbc related enable
 | [EFUSE] sbc: %x, buf[%d]=0

[B] 0x4003277a | FUN_4003277a | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Error: custk related enable
 | [EFUSE] custk: %x, buf[%d]=0

[B] 0x40032898 | FUN_40032898 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Error: multi-bit ecc region
 | [EFUSE] Error: idx(%x): %x, idx(%x): %x

[B] 0x40032914 | FUN_40032914 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] idx(%x): cannot revert [0x%x=>0x%x]

[B] 0x400329d8 | FUN_400329d8 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] index=%x, group_index=%x
 | [EFUSE] Disable I(%x):(%x)

[B] 0x40032bc6 | FUN_40032bc6 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Error: idx[0x%x] verify failed: 0x%x != 0x%x
 | [EFUSE] idx[0x%x] verify --> partially blown: [0x%x != 0x%x]
 | [EFUSE] idx[0x%x] verify pass, readback[0x%x]

[B] 0x40032c88 | FUN_40032c88 | handler=False | libc=- | tags=EFUSE,hash,sla
      strings: [EFUSE] 
========== Efuse Secure Setting ==========
 | [EFUSE] sbc_en               = %s  
 | [EFUSE] daa_en               = %s  
 | [EFUSE] sla_en               = %s  
 | [EFUSE] jtag_dis             = %s  
 | [EFUSE] Enable_SW_JTAG_CON   = %s  
 | 
[B] 0x40032dc4 | FUN_40032dc4 | handler=False | libc=- | tags=EFUSE
      strings: [EFUSE] Error: SBC & DAA & (EN_JTAG_CON or Dis_JTAG) should be 1, forbidden blow
 | [EFUSE] control: %x
 | [EFUSE] secure-ctrl: %x

[B] 0x40033fac | FUN_40033fac | handler=False | libc=- | tags=cust_
      strings: search_offset = 0x%llx
 | read_len = 0x%x
 | rom_info_ver = 0x%x
 | [%s][ROM] customer name = %s
 | ROM_INFO | ROM_INFO | ROM_INFO | [%s] rom_info_found = %d
 | [%s] cust_name_found = %d
 | sdl(ROM_INFO) = 0x%x
 | sboot(ROM_INFO) = 0x%x
 | sdl = 0x%x
[B] 0x40034f14 | FUN_40034f14 | handler=False | libc=- | tags=storage
      strings: seccfg | SEC_CFG | [%s] storage read fail, ret=%x

[B] 0x400351e4 | FUN_400351e4 | handler=False | libc=- | tags=ownload
      strings: [%s] downloaded img ver (%d) < otp ver (%d).
 | [%s] img sub group ver check fail, ret: 0x%x
 | [%s] Misc group otp ver:
 | [%s] sub_group: %d, sub_ver: %d
 | [%s] sub_info_init fail, ret: 0x%x

[B] 0x40035594 | FUN_40035594 | handler=False | libc=- | tags=cert
      strings: [Storage] preloader version is not sync. key(%d) cnt(%d)
 | [PL][ram] gfh_addr = %x
 | [PL] key cert not found. magic:0x%x
 | [PL] cnt cert not found. magic:0x%x

[B] 0x400357a4 | FUN_400357a4 | handler=False | libc=- | tags=ownload,storage
      strings: ram ver info: %d, 0x%x, 0x%x
 | get preloader version fail (ram)(0x%x)
 | [%s] get preloader version.
 | rom info version(stor) = %d
 | rom info version(ram) = %d
 | downloaded img ver (%d) < storage img ver (%d).
 | sig types are different in rom(0x
[B] 0x40035c04 | FUN_40035c04 | handler=False | libc=- | tags=ownload,storage
      strings: [%s] hw ver check pass.
 | [%s] ver_check = 0x%x
 | [%s] image ver(storage) = %d
 | [%s] image ver(to be flashed) = %d
 | downloaded img ver (%d) < storage img ver (%d)
 | downloaded img ver (%d) < otp ver (%d)

[B] 0x40036084 | FUN_40036084 | handler=False | libc=- | tags=signature,storage
      strings: [%s][storage] verified boot signature: 1
 | [%s][storage] verified boot signature: 0
 | [%s] image exists: ver = %d
 | [%s][storage] no image: ver = 0

[B] 0x40036430 | FUN_40036430 | handler=False | libc=- | tags=cert
      strings: preloader | recovery | [%s] searching for %s
 | get_ext_sig_from_allinone_ext_sig | get_ext_sig_from_allinone_ext_sig | get_ext_sig_from_allinone_ext_sig | get_ext_sig_from_allinone_ext_sig | get_ext_sig_from_allinone_ext_sig | get_ext_sig_from_allin
[B] 0x40037350 | FUN_40037350 | handler=False | libc=- | tags=signature
      strings: No more image!
 | [%s] verified boot signature: 1
 | [%s] verified boot signature: 0
 | [%s] ext_sig vfy pass.
 | [%s] Verification ok
 | [%s] Verification fail(0x%x)
 | [%s] buf_chk: cur_offset_low   = 0x%x
 | [%s] buf_chk: cur_offset_low   = 0x%x
 
[B] 0x40037fc8 | FUN_40037fc8 | handler=False | libc=- | tags=auth,cert,hash
      strings: preloader | preloader | 0x%x  | 0x%x  | [%s] image verify error = 0x%x
 | [%s]GFH_MULTI_SEC not found - Use default setting
 | [%s]GFH_MULTI_SEC found
 | [%s]multi_sec_info:
 | [%s]sec_level = 0x%x
 | [%s]root_key_ver = %u
 | [py] sig =
 | [py] ext_s
[B] 0x400391a8 | FUN_400391a8 | handler=False | libc=- | tags=auth,hash
      strings: 0x%x  | 0x%x  | sbc_en = 1
 | pl img pubk hash =  | fuse pubk hash =  | sbc_en = 0
 | pl pubk auth fail
 | pl pubk auth ok

[B] 0x4003af54 | FUN_4003af54 | handler=False | libc=- | tags=hash
      strings: Error: fail to allocate memory for DB for pkcs_1_pss_decode_sha256 operation
 | Error: fail to allocate memory for hash for pkcs_1_pss_decode_sha256 operation
 | Error: fail to allocate memory for mask for pkcs_1_pss_decode_sha256 operation
 | Error:
[B] 0x4003ce28 | FUN_4003ce28 | handler=False | libc=- | tags=cert
      strings: [%s] cert1 vfy fails, ret = 0x%x

[B] 0x4003e110 | FUN_4003e110 | handler=False | libc=- | tags=cert,hash
      strings: [%s] hash list does not exist, ret = 0x%x
 | [%s] cert2 vfy fails, ret = 0x%x

[B] 0x400401c8 | FUN_400401c8 | handler=False | libc=- | tags=hash
      strings: Error: fail to allocate memory for DB for pkcs_1_pss_decode_sha384 operation
 | Error: fail to allocate memory for hash for pkcs_1_pss_decode_sha384 operation
 | Error: fail to allocate memory for mask for pkcs_1_pss_decode_sha384 operation
 | Error:
