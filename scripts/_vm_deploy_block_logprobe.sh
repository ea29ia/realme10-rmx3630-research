cd ~/ea29ia_mtkclient
python3 - << 'LOGPROBEEOF'
# heapbait-logprobe config deploy (new config 0/2):
# setup_env already sends CMD:SET-RUNTIME-PARAMETER with da_log_level + log_channel
# before the exploit chain (xml_lib.py setup_env, reads daconfig.uartloglevel /
# daconfig.logchannel, which are copied from config.* in daconfig.py:91-92).
# Change ONLY the two defaults in mtk_config.py: 2 (INFO) -> 0 (TRACE), "UART" -> "USB".
# If the 2710EX01 DA2's SET-RUNTIME-PARAMETER handler is alive, TRACE level enables
# the allocator's own debug prints ("allocation was %zd bytes long at %p", strings at
# 0x40043ae7/0x40043aef) and the USB channel delivers them in-band -> full heap
# visibility without soldering -> geometry computable -> deterministic hijack.
# No exploit code touched. All prior fixes (relink payload, 60KB trigger, raw capture,
# sweep-4200, wrapper fallback, DA1_RETRY, FORCE_HEAPBAIT, conditional set_configuration)
# remain untouched.

p = "mtkclient/config/mtk_config.py"
src = open(p).read()

old1 = "        self.uartloglevel = 2"
new1 = "        self.uartloglevel = 0  # OPLUS logprobe (heapbait-logprobe config): TRACE -> free()/malloc() debug prints enabled in the DA2 if its SET-RUNTIME-PARAMETER handler is alive"
old2 = '        self.logchannel = "UART"'
new2 = '        self.logchannel = "USB"  # OPLUS logprobe (heapbait-logprobe config): deliver DA logs over the same USB connection instead of UART'
n1 = src.count(old1)
n2 = src.count(old2)
assert n1 == 1, f"uartloglevel anchor: expected 1 match, found {n1}"
assert n2 == 1, f"logchannel anchor: expected 1 match, found {n2}"
src = src.replace(old1, new1)
src = src.replace(old2, new2)
open(p, "w").write(src)
print("PATCH APPLIED: heapbait-logprobe (uartloglevel 2->0, logchannel UART->USB)")
LOGPROBEEOF
python3 -m py_compile mtkclient/config/mtk_config.py && echo "COMPILE OK"
python3 -m py_compile mtkclient/Library/DA/xmlflash/xml_lib.py && echo "XML_LIB COMPILE OK"
python3 -m py_compile mtkclient/Library/Exploit/heapbait.py && echo "HEAPBAIT COMPILE OK"
echo "--- markers ---"
grep -n "uartloglevel" mtkclient/config/mtk_config.py | head -2
grep -n "logchannel" mtkclient/config/mtk_config.py | head -2
grep -c "heapbait-logprobe" mtkclient/config/mtk_config.py
echo "--- prior fixes untouched (expect 1 1 1) ---"
grep -c "60000 \* \"A\"" mtkclient/Library/Exploit/heapbait.py
grep -c "dpc_addr + 4" mtkclient/Library/Exploit/heapbait.py
grep -c "RAW_GETBAITED_RESPONSE" mtkclient/Library/Exploit/heapbait.py
