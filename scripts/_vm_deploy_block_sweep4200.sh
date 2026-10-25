cd ~/ea29ia_mtkclient
python3 - << 'SWEEPEOF'
p = "mtkclient/Library/Exploit/heapbait.py"
src = open(p).read()
old = '        ncmd = self.xflash.cmd.cmd_security_set_allinone_signature(filename=5000 * "A")'
new = '        ncmd = self.xflash.cmd.cmd_security_set_allinone_signature(filename=4200 * "A")  # OPLUS sweep: 5000 baseline misses deterministically on 2710EX01 (next chunk = never-freed remainder); L shifts the mxml transient/free interleaving and the stage-3 hole map'
n = src.count(old)
assert n == 1, f"expected exactly 1 match, found {n} - aborting"
open(p, "w").write(src.replace(old, new))
print("PATCH APPLIED: stage-2 filename length 5000 -> 4200 (OPLUS hole-map sweep, raw-response capture untouched)")
SWEEPEOF
python3 -m py_compile mtkclient/Library/Exploit/heapbait.py && echo "COMPILE OK"
grep -n 'filename=4200 \* "A"\|filename=5000 \* "A"\|RAW_GETBAITED_RESPONSE' mtkclient/Library/Exploit/heapbait.py
