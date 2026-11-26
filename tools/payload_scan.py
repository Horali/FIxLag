"""Scan capture payloads for readable text and measure payload entropy.

Built for one question: is MLBB's in-match chat sent in the clear, or is the
UDP payload encrypted? A textbook answer needs bytes, so this reads the
payloads a full-snaplen capture holds (draft_capture.sh with snaplen 1500).

Two checks:

  * needle search - the exact bytes of a string you typed. An ASCII or UTF-8
    hit means that channel is not encrypted.
  * entropy - ~8 bits/byte means encrypted or compressed; ~3-5 bits/byte means
    structured or text-like data.

Header-only captures (-s 96) carry no payload and cannot answer this.

Usage:
    python tools/payload_scan.py captures/chat.pcap --needle "hora-chat-test-42"
    python tools/payload_scan.py captures/chat.pcap --entropy
    python tools/payload_scan.py --selftest
"""

import argparse
import collections
import math
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import parse_pcap as pp  # noqa: E402


def iter_packets(path):
    """Yield (ts, proto, src, sport, dst, dport, payload, truncated)."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return
    endian, _snaplen, linktype = pp.read_global_header(data)
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl > len(data):
            return
        pkt = data[off:off + incl]
        off += incl
        ts = ts_sec + ts_usec / 1e6

        ethertype, payload, _ifidx = pp.network_offset(pkt, linktype)
        if ethertype == 0x0800:
            if len(payload) < 20 or payload[9] not in (6, 17):
                continue
            proto_num = payload[9]
            ihl = (payload[0] & 0x0F) * 4
            src = ".".join(str(b) for b in payload[12:16])
            dst = ".".join(str(b) for b in payload[16:20])
            l4 = payload[ihl:]
        elif ethertype == 0x86DD:
            if len(payload) < 40 or payload[6] not in (6, 17):
                continue
            proto_num = payload[6]
            src = ":".join("%x" % w for w in struct.unpack("!8H", payload[8:24]))
            dst = ":".join("%x" % w for w in struct.unpack("!8H", payload[24:40]))
            l4 = payload[40:]
        else:
            continue

        proto = "udp" if proto_num == 17 else "tcp"
        if len(l4) < 8:
            continue
        sport, dport = struct.unpack("!HH", l4[:4])
        if proto == "udp":
            ulen = struct.unpack("!H", l4[4:6])[0]
            body = l4[8:]
            if ulen >= 8 and len(body) > ulen - 8:
                body = body[:ulen - 8]
        else:
            doff = (l4[12] >> 4) * 4
            body = l4[doff:] if len(l4) > doff else b""
        yield ts, proto, src, sport, dst, dport, body, orig > incl


def entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable_runs(data, minlen):
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(bytes(cur))
    return out


def strings_mode(path, minlen, limit):
    """Dump readable ASCII runs from UDP payloads, with flow and time."""
    seen = 0
    for ts, proto, src, sport, dst, dport, body, cut in iter_packets(path):
        for run in printable_runs(body, minlen):
            print("%s  %s %s:%d -> %s:%d  len=%-4d %r"
                  % (time_str(ts), proto, src, sport, dst, dport, len(run), run))
            seen += 1
            if seen >= limit:
                print("... stopped at %d runs" % limit)
                return 0
    print("no printable runs of %d+ chars in %d packets" % (minlen, 0))
    return 0


def scan(path, needles, show_entropy):
    flows = collections.defaultdict(
        lambda: {"pkts": 0, "bytes": 0, "hits": [], "sample": bytearray()})
    truncated = 0
    for ts, proto, src, sport, dst, dport, body, cut in iter_packets(path):
        if cut:
            truncated += 1
        key = (proto, src, sport, dst, dport)
        f = flows[key]
        f["pkts"] += 1
        f["bytes"] += len(body)
        if len(f["sample"]) < 20000:
            f["sample"].extend(body[:20000 - len(f["sample"])])
        for needle, raw in needles:
            idx = body.find(raw)
            if idx >= 0:
                f["hits"].append((ts, needle, idx, len(body)))

    if not flows:
        print("no UDP payload in this capture (header-only snaplen?)")
        return 1

    total_bytes = sum(f["bytes"] for f in flows.values())
    if total_bytes == 0:
        print("flows: %d, but every payload is empty -- this is a "
              "header-only capture." % len(flows))
        print("rerun with --snaplen 1500; -s 96 truncates at the UDP header.")
        return 1

    hits = [(k, v) for k, v in flows.items() if v["hits"]]
    print("flows: %d, with needle hits: %d" % (len(flows), len(hits)))
    if truncated:
        total_pkts = sum(f["pkts"] for f in flows.values())
        print("WARNING %d/%d packets are truncated: the capture was taken at a "
              "small snaplen." % (truncated, total_pkts))
        print("        A missing needle may mean 'not captured', not "
              "'not present'. Rerun with --snaplen 1500.")
    for (proto, src, sport, dst, dport), f in sorted(hits, key=lambda kv: -len(kv[1]["hits"])):
        print("HIT  %s %s:%d -> %s:%d  %d hit(s)"
              % (proto, src, sport, dst, dport, len(f["hits"])))
        for ts, needle, idx, blen in f["hits"][:5]:
            print("     %s  needle=%r at payload offset %d (payload %d bytes)"
                  % (time_str(ts), needle, idx, blen))
    if not hits:
        print("no needle found in any payload")

    if show_entropy:
        print("\npayload entropy per flow (8.0 = random, <5.5 = structured/text)")
        rows = sorted(flows.items(), key=lambda kv: -kv[1]["bytes"])[:12]
        for (proto, src, sport, dst, dport), f in rows:
            print("  %-3s %-15s:%-5d -> %-15s:%-5d  pkts=%-6d bytes=%-8d entropy=%.2f"
                  % (proto, src, sport, dst, dport, f["pkts"], f["bytes"],
                     entropy(bytes(f["sample"]))))
    return 0


def time_str(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _ipv4(src, dst, proto, l4):
    total = 20 + len(l4)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, src, dst) + l4


def build_sample(path, text, tcp_text=None):
    """Write a tiny raw-IP pcap holding a UDP packet, and a TCP one if asked."""
    payload = b"\x01\x02" + text.encode() + b"\x00\x99"
    udp = struct.pack("!HHHH", 40000, 5008, 8 + len(payload), 0) + payload
    udp_pkt = _ipv4(bytes([10, 0, 0, 5]), bytes([164, 52, 73, 243]), 17, udp)

    pkts = [udp_pkt]
    if tcp_text is not None:
        body = tcp_text.encode() + b"\r\n"
        tcp = struct.pack("!HHIIBBHHH", 41000, 30101, 1, 1, 5 << 4, 0x18,
                          65535, 0, 0) + body
        pkts.append(_ipv4(bytes([10, 0, 0, 5]), bytes([161, 202, 213, 215]), 6, tcp))

    gh = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
    out = bytearray(gh)
    for i, pkt in enumerate(pkts):
        out += struct.pack("<IIII", 1795000000 + i, 0, len(pkt), len(pkt)) + pkt
    Path(path).write_bytes(bytes(out))


def selftest():
    needle = "hora-chat-test-42"
    tcp_needle = "tcp-marker-9"
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "s.pcap"
        build_sample(p, needle, tcp_needle)
        code = scan(str(p), [(needle, needle.encode()),
                             (tcp_needle, tcp_needle.encode())], True)
    ok = code == 0
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "s.pcap"
            build_sample(p, "something else entirely", "nothing here")
            scan(str(p), [(needle, needle.encode()),
                          (tcp_needle, tcp_needle.encode())], False)
    out = buf.getvalue()
    if "HIT" in out:
        raise SystemExit("selftest failed: false positive")
    if "no needle found" not in out:
        raise SystemExit("selftest failed: miss not reported")
    if not ok:
        raise SystemExit("selftest failed: build path returned non-zero")
    print("selftest OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--needle", action="append", default=[],
                    help="string to search for, repeatable")
    ap.add_argument("--entropy", action="store_true", help="report payload entropy")
    ap.add_argument("--strings", type=int, metavar="N",
                    help="dump printable runs of at least N characters")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return
    if not args.pcap:
        raise SystemExit("usage: payload_scan.py <capture.pcap> --needle STR [--entropy]")
    if args.strings:
        raise SystemExit(strings_mode(args.pcap, args.strings, args.limit))
    needles = [(n, n.encode("utf-8")) for n in args.needle]
    raise SystemExit(scan(args.pcap, needles, args.entropy))


if __name__ == "__main__":
    main()
