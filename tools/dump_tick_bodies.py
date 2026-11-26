"""Dump decoded tick bodies around a range, with printable runs, for manual reading."""
import sys
import pathlib

sys.path.insert(0, r"C:\Users\child\PROJECTS\FIxLag\tools")
import decode_lzw_chat as D

pcap = pathlib.Path(sys.argv[1])
port = int(sys.argv[2])
lo = int(sys.argv[3])
hi = int(sys.argv[4])

ticks, _other, _non = D.extract_ticks(pcap, port)
decoded, next_code, missing = D.decode_lzw16_ticks(ticks)
print(f"ticks={len(ticks)} decoded={len(decoded)} next=0x{next_code:x} missing={missing}")


def runs(data, n=4):
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= n:
                out.append(bytes(cur).decode())
            cur = bytearray()
    if len(cur) >= n:
        out.append(bytes(cur).decode())
    return out


for idx in range(lo, hi + 1):
    if idx not in decoded:
        continue
    ts, data = decoded[idx]
    if b"\x41" not in data:
        continue
    print(f"--- tick {idx} len={len(data)}")
    print("   hex:", data[:120].hex())
    for r in runs(data, 4):
        print("   run:", r)
