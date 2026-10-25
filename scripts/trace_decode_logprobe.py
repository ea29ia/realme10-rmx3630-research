"""Decode the logprobe USB heap trace (2710EX01 DA2) and reconstruct the free-list timeline.

Trace semantics (verified against the DA2's own malloc core disasm @0x40008b10 and
free @0x40008cdc, and against 6 independent trace pairs):

  'ptr 0xX'                                    = free(X) argument — the USER pointer being freed
  'allocation was N bytes long at ptr 0xY'     = N = [X-4] = chunk_total; Y = [X-8] = the node addr

  Allocator layout (ARM32, LK-derived vendor variant):
    free-list node: [node+0]=next, [node+4]=prev, [node+8]=chunk_total
    malloc carve:   user = node+12
                    [user-12] = 'heap' magic (0x68656170)
                    [user-8]  = node addr
                    [user-4]  = chunk_total = round_up(request + 12, 4)
    usable bytes   = chunk_total - 12

The 4200-A stage-2 parse's final text buffer: chunk_total 5132 = 0x140C → usable 0x1400.

Usage: python trace_decode_logprobe.py "<path to log file>"
"""
import re
import sys

PAT = re.compile(r"allocation was (\d+) bytes long at ptr (0x[0-9a-fA-F]+)")
PTRPAT = re.compile(r"^\D*ptr (0x[0-9a-fA-F]+)")

def parse(path):
    events = []
    last_ptr = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            m = PAT.search(line)
            if m:
                size = int(m.group(1))
                node = int(m.group(2), 16)
                # The 'ptr 0xX' line precedes the alloc line; user = X from the most recent
                # standalone ptr line. If none seen (pair already consumed), infer user = node+12.
                if last_ptr is not None and last_ptr[1] - 12 <= node + 0x10000:
                    ln, user = last_ptr
                else:
                    ln, user = i, node + 12
                events.append({"line": ln, "user": user, "total": size, "node": node,
                               "usable": size - 12})
                last_ptr = None
                continue
            m = PTRPAT.search(line)
            if m:
                last_ptr = (i, int(m.group(1), 16))
    return events

def timeline(events):
    # 'allocation was' = the free() print. Two free prints for the same (user,total) in one
    # command = the buffer was freed and re-allocated identically (deterministic rebuild).
    # A buffer that never gets a free-print in the window = still live at window end.
    print(f"{'line':>6} {'user':>12} {'total':>7} {'usable':>8}  node")
    for e in events:
        print(f"{e['line']:>6} {e['user']:#12x} {e['total']:>7} {e['usable']:>#8x}  {e['node']:#x}")

def adjacency(events):
    print("\n=== adjacency among big chunks (usable >= 0x1000) ===")
    bigs = [e for e in events if e["usable"] >= 0x1000]
    for a, b in zip(bigs, bigs[1:]):
        end_a = a["node"] + a["total"]
        gap = b["node"] - end_a
        rel = "EXACT-ADJACENT" if gap == 0 else f"gap {gap} bytes"
        print(f"  [{a['node']:#x} .. {end_a:#x}) ({a['total']}B)  ->  next node {b['node']:#x}: {rel}")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else r"<DOWNLOAD_PATH>\\LOG LENIX.txt"
    ev = parse(path)
    print(f"decoded {len(ev)} free-events from {path}\n")
    timeline(ev)
    adjacency(ev)
