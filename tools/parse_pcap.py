"""Parse a PCAPdroid capture and summarise MLBB UDP flows.

Diagnostic script for the research phase, not part of the tool.
Reads a PCAP file (raw IP, Ethernet, SLL or SLL2) and prints the
dominant UDP flows plus any packets to/from the latency-probe port.

Usage:
    python tools/parse_pcap.py captures/mlbb_custom1.pcap
"""

import collections
import datetime
import struct
import sys

PROBE_PORT = 30190
MATCH_PORT = 5522

MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\xa1\xb2\x3c\x4d": ">",
}


def read_global_header(data):
    endian = MAGICS.get(data[:4])
    if endian is None:
        raise SystemExit("not a pcap file: unknown magic %r" % data[:4])
    _, _, _, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", data[:24])
    return endian, snaplen, linktype


def network_offset(pkt, linktype):
    """Return (ethertype, payload) for the supported link types."""
    if linktype == 101:  # raw IP
        if not pkt:
            return None, None
        return (0x0800 if (pkt[0] >> 4) == 4 else 0x86DD), pkt
    if linktype == 1:  # Ethernet
        if len(pkt) < 14:
            return None, None
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        payload = pkt[14:]
        while ethertype == 0x8100 and len(payload) >= 4:
            ethertype = struct.unpack("!H", payload[2:4])[0]
            payload = payload[4:]
        return ethertype, payload
    if linktype == 113:  # Linux cooked
        if len(pkt) < 16:
            return None, None
        return struct.unpack("!H", pkt[14:16])[0], pkt[16:]
    if linktype == 276:  # Linux cooked v2
        if len(pkt) < 20:
            return None, None
        return struct.unpack("!H", pkt[0:2])[0], pkt[20:]
    return None, None


def parse_udp(ethertype, payload):
    """Return (src, dst, sport, dport, l4_len) for a UDP packet, else None."""
    if ethertype == 0x0800:
        if len(payload) < 20:
            return None
        ihl = (payload[0] & 0x0F) * 4
        if payload[9] != 17:
            return None
        src = ".".join(str(b) for b in payload[12:16])
        dst = ".".join(str(b) for b in payload[16:20])
        l4 = payload[ihl:]
    elif ethertype == 0x86DD:
        if len(payload) < 40 or payload[6] != 17:
            return None
        src = ":".join("%x" % struct.unpack("!H", payload[8 + 2 * i:10 + 2 * i])[0] for i in range(8))
        dst = ":".join("%x" % struct.unpack("!H", payload[24 + 2 * i:26 + 2 * i])[0] for i in range(8))
        l4 = payload[40:]
    else:
        return None

    if len(l4) < 8:
        return None
    sport, dport, _ = struct.unpack("!HHH", l4[:6])
    return src, dst, sport, dport, len(l4)


def main(path):
    data = open(path, "rb").read()
    endian, snaplen, linktype = read_global_header(data)
    print("pcap linktype=%d snaplen=%d" % (linktype, snaplen))

    off = 24
    total = 0
    start = None
    flows = collections.defaultdict(lambda: {"pkts": 0, "bytes": 0, "first": 1e18, "last": 0})
    probes = []

    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        total += 1
        ts = ts_sec + ts_usec / 1e6
        if start is None:
            start = ts

        ethertype, payload = network_offset(pkt, linktype)
        parsed = parse_udp(ethertype, payload)
        if parsed is None:
            continue
        src, dst, sport, dport, l4len = parsed

        flow = flows[(src, sport, dst, dport)]
        flow["pkts"] += 1
        flow["bytes"] += l4len
        flow["first"] = min(flow["first"], ts)
        flow["last"] = max(flow["last"], ts)

        if PROBE_PORT in (sport, dport):
            remote = dst if dport == PROBE_PORT else src
            probes.append((ts - start, remote, dport, l4len))

    print("capture start: %s" % datetime.datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M:%S"))
    print("packets=%d udp_flows=%d" % (total, len(flows)))

    print("\n=== top UDP flows ===")
    header = "%-22s %-6s %-22s %-6s %8s %9s %7s"
    print(header % ("src", "sport", "dst", "dport", "pkts", "bytes", "dur_s"))
    for (src, sport, dst, dport), f in sorted(flows.items(), key=lambda kv: -kv[1]["pkts"])[:20]:
        print(header % (src, sport, dst, dport, f["pkts"], f["bytes"], f["last"] - f["first"]))

    if probes:
        print("\n=== port %d probes (relative seconds) ===" % PROBE_PORT)
        seen = set()
        for rel, remote, dport, l4len in sorted(probes):
            key = (remote, dport)
            if key in seen:
                continue
            seen.add(key)
            print("  +%6.2fs  -> %-16s dport=%d len=%d" % (rel, remote, dport, l4len))

    match = [(k, v) for k, v in flows.items() if MATCH_PORT in (k[1], k[3])]
    if match:
        print("\n=== port %d (match server) ===" % MATCH_PORT)
        for (src, sport, dst, dport), f in sorted(match, key=lambda kv: -kv[1]["pkts"]):
            remote = dst if dport == MATCH_PORT else src
            print("  %-16s pkts=%-5d first=+%.2fs last=+%.2fs"
                  % (remote, f["pkts"], f["first"] - start, f["last"] - start))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tools/parse_pcap.py <capture.pcap>")
    main(sys.argv[1])
