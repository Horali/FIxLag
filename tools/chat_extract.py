"""Extract in-match chat records from a capture, split by game phase.

Built for the draft-pick experiment: does chat during hero selection reach the
client, and does a message from the enemy team arrive at all?

What it knows, from the measured protocol (plan.md §5.16):

    team chat   field 0x7002   followed by 0x41 <len> <text>
    all chat    field 0x7003   followed by 0x41 <len> <text>

Anything outside that shape is not silently dropped: --strings dumps printable
runs from the draft phase, so an unfamiliar framing is visible rather than
invisible.

Phases are split on the first packet to a port in 5000-5999, which is when the
match server connection opens. Everything before it is DRAFT, after it MATCH.

Usage:
    python tools/chat_extract.py captures/draft_DRAFT.pcap
    python tools/chat_extract.py captures/draft_DRAFT.pcap --self "team,all"
    python tools/chat_extract.py captures/draft_DRAFT.pcap --strings 6 --limit 80
    python tools/chat_extract.py captures/draft_DRAFT.pcap --phase DRAFT
"""

import argparse
import datetime
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import parse_pcap as pp  # noqa: E402

CHANNELS = {b"\x70\x00\x02": "TEAM", b"\x70\x00\x03": "ALL "}
MATCH_PORT_LO, MATCH_PORT_HI = 5000, 5999


def iter_payloads(path):
    """Yield (ts, proto, src, sport, dst, dport, payload, truncated)."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return
    endian, _sn, linktype = pp.read_global_header(data)
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
            if len(payload) < 20:
                continue
            proto_num = payload[9]
            if proto_num not in (6, 17):
                continue
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
        if len(l4) < 8:
            continue
        sport, dport = struct.unpack("!HH", l4[:4])
        proto = "udp" if proto_num == 17 else "tcp"
        if proto == "udp":
            ulen = struct.unpack("!H", l4[4:6])[0]
            body = l4[8:]
            if ulen >= 8 and len(body) > ulen - 8:
                body = body[:ulen - 8]
        else:
            doff = (l4[12] >> 4) * 4
            body = l4[doff:] if len(l4) > doff else b""
        yield ts, proto, src, sport, dst, dport, body, orig > incl


def phase_boundary(path):
    """Timestamp of the first packet to/from a match port."""
    for ts, _p, _s, sp, _d, dp, _b, _c in iter_payloads(path):
        if MATCH_PORT_LO <= dp <= MATCH_PORT_HI or MATCH_PORT_LO <= sp <= MATCH_PORT_HI:
            return ts
    return None


def chat_records(body):
    """Yield (label, text).

    Strict on purpose. In the measured protocol the text tag sits immediately
    after the channel tag -- 70 00 02 41 04 "team" -- and the text is valid
    UTF-8 with at least one letter. Loosening either condition produced
    thousands of false positives from game state that happens to contain the
    same bytes.
    """
    for tag, label in CHANNELS.items():
        start = 0
        while True:
            i = body.find(tag, start)
            if i < 0:
                break
            j = i + 3
            if j + 2 <= len(body) and body[j] == 0x41:
                n = body[j + 1]
                raw = body[j + 2:j + 2 + n]
                if 1 <= n <= 200 and len(raw) == n and looks_like_text(raw):
                    yield label, raw
                    break
            start = i + 3


def looks_like_text(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        return False
    return any(c.isalpha() for c in text)


def printable_runs(data, minlen):
    out, cur = [], bytearray()
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


def decode(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--self", dest="self_texts", default="",
                    help="comma-separated texts you sent, marked SELF in the output")
    ap.add_argument("--phase", choices=["DRAFT", "MATCH", "ALL"], default="ALL")
    ap.add_argument("--strings", type=int, metavar="N",
                    help="dump printable runs of N+ chars (draft debugging)")
    ap.add_argument("--limit", type=int, default=120)
    ap.add_argument("--all-flows", action="store_true",
                    help="include tls/dns flows in --strings output")
    args = ap.parse_args()

    boundary = phase_boundary(args.pcap)
    self_set = set(t.strip() for t in args.self_texts.split(",") if t.strip())

    def phase_of(ts):
        if boundary is None:
            return "?"
        return "DRAFT" if ts < boundary else "MATCH"

    if args.strings:
        shown = 0
        for ts, proto, src, sp, dst, dp, body, _cut in iter_payloads(args.pcap):
            ph = phase_of(ts)
            if args.phase != "ALL" and ph != args.phase:
                continue
            if not args.all_flows and ({sp, dp} & {53, 123, 443, 853, 5353}):
                continue
            for run in printable_runs(body, args.strings):
                print("%s %s %s %s:%d -> %s:%d  %r"
                      % (ph, ts_str(ts), proto, src, sp, dst, dp, run.decode("latin-1")))
                shown += 1
                if shown >= args.limit:
                    print("... stopped at %d runs" % args.limit)
                    return
        print("no printable runs of %d+ chars" % args.strings)
        return

    rows = []
    seen = set()
    for ts, proto, src, sp, dst, dp, body, cut in iter_payloads(args.pcap):
        for label, raw in chat_records(body):
            key = (label, raw, round(ts, 0))
            if key in seen:
                continue
            seen.add(key)
            ph = phase_of(ts)
            if args.phase != "ALL" and ph != args.phase:
                continue
            text = decode(raw)
            who = "SELF" if text in self_set else "OTHER"
            rows.append((ts, ph, proto, src, sp, dst, dp, label, who, text, len(body)))

    if boundary is None:
        print("note: no match-port flow found; every record is DRAFT phase")
    else:
        print("match connection opens at %s" % ts_str(boundary))

    print("%-5s %-8s %-3s %-21s %-22s %-4s %-5s %s"
          % ("phase", "time", "p", "src:port", "dst:port", "chan", "who", "text"))
    for ts, ph, proto, src, sp, dst, dp, label, who, text, blen in sorted(rows):
        print("%-5s %-8s %-3s %-21s %-22s %-4s %-5s %r"
              % (ph, ts_str(ts), proto[:3], "%s:%d" % (src, sp),
                 "%s:%d" % (dst, dp), label, who, text))
    print("%d chat record(s)" % len(rows))


def ts_str(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


if __name__ == "__main__":
    main()
