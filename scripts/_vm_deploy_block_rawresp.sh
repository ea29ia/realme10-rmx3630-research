cd ~/ea29ia_mtkclient
python3 - << 'RAWEOF'
p = "mtkclient/Library/Exploit/heapbait.py"
src = open(p).read()
old = """        self.xflash.xsend(b"GETBAITED\\0")
        result = self.xflash.get_response()
        if result != "ERR":"""
new = """        self.xflash.xsend(b"GETBAITED\\0")
        result = self.xflash.get_response(raw=True)  # raw bytes: our DA2 never answers bare "ERR" (probe is build-fragile)
        print(f"[RAW_GETBAITED_RESPONSE] {result!r}")
        result = result.rstrip(b"\\x00").decode('utf-8', errors='replace')
        if result != "ERR":"""
n = src.count(old)
assert n == 1, f"expected exactly 1 match, found {n} - aborting"
open(p, "w").write(src.replace(old, new))
print("PATCH APPLIED: GETBAITED response now captured raw ([RAW_GETBAITED_RESPONSE] prints bytes; probe comparison untouched)")
RAWEOF
python3 -m py_compile mtkclient/Library/Exploit/heapbait.py && echo "COMPILE OK"
grep -c "\[RAW_GETBAITED_RESPONSE\]" mtkclient/Library/Exploit/heapbait.py
grep -n "get_response(raw=True)\|RAW_GETBAITED_RESPONSE" mtkclient/Library/Exploit/heapbait.py
