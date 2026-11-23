"""Parse a PCAPdroid or tcpdump capture and summarise MLBB UDP flows.

Diagnostic script for the research phase, not part of the tool.
Reads a PCAP file (raw IP, Ethernet, SLL or SLL2) and prints the
dominant UDP flows plus any packets to/from the latency-probe port.

When the capture uses Linux cooked v2 (SLL2, link type 276), the
per-packet interface index is extracted and mapped to a name, so we can
tell which link (Wi-Fi vs cellular) carried each flow.

Usage:
    python tools/parse_pcap.py captures/mlbb_custom1.pcap
    python tools/parse_pcap.py captures/all.pcap --probe
"""

import collections
import datetime
import struct
import sys

PROBE_PORT = 30190
MATCH_PORTS = (5506, 5507, 5515, 5522)

# ifindex -> name on the SM-S936B used for these captures. Override with
# --iface if the device enumerates differently.
IFACE_NAMES = {
    14: "rmnet_ipa0",
    44: "wlan0",
    62: "rmnet_data0",
}

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
    """Return (ethertype, payload, if_index) for the supported link types."""
    if linktype == 101:  # raw IP
        if not pkt:
            return None, None, None
        return (0x0800 if (pkt[0] >> 4) == 4 else 0x86DD), pkt, None
    if linktype == 1:  # Ethernet
        if len(pkt) < 14:
            return None, None, None
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        payload = pkt[14:]
        while ethertype == 0x8100 and len(payload) >= 4:
            ethertype = struct.unpack("!H", payload[2:4])[0]
            payload = payload[4:]
        return ethertype, payload, None
    if linktype == 113:  # Linux cooked v1
        if len(pkt) < 16:
            return None, None, None
        return struct.unpack("!H", pkt[14:16])[0], pkt[16:], None
    if linktype == 276:  # Linux cooked v2
        if len(pkt) < 20:
            return None, None, None
        ethertype = struct.unpack("!H", pkt[0:2])[0]
        if_index = struct.unpack("!I", pkt[4:8])[0]
        return ethertype, pkt[20:], if_index
    return None, None, None


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


def iface_name(idx):
    if idx is None:
        return "-"
    return IFACE_NAMES.get(idx, "if%d" % idx)


def main(path, show_probes_only=False):
    data = open(path, "rb").read()
    endian, snaplen, linktype = read_global_header(data)
    print("pcap linktype=%d snaplen=%d" % (linktype, snaplen))

    off = 24
    total = 0
    start = None
    flows = collections.defaultdict(
        lambda: {"pkts": 0, "bytes": 0, "first": 1e18, "last": 0, "ifaces": collections.Counter()}
    )
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

        ethertype, payload, if_idx = network_offset(pkt, linktype)
        parsed = parse_udp(ethertype, payload)
        if parsed is None:
            continue
        src, dst, sport, dport, l4len = parsed

        flow = flows[(src, sport, dst, dport)]
        flow["pkts"] += 1
        flow["bytes"] += l4len
        flow["first"] = min(flow["first"], ts)
        flow["last"] = max(flow["last"], ts)
        flow["ifaces"][iface_name(if_idx)] += 1

        if PROBE_PORT in (sport, dport):
            remote = dst if dport == PROBE_PORT else src
            probes.append((ts - start, remote, dport, l4len, iface_name(if_idx)))

    when = datetime.datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M:%S")
    print("capture start: %s" % when)
    print("packets=%d udp_flows=%d" % (total, len(flows)))

    if not show_probes_only:
        print("\n=== top UDP flows ===")
        header = "%-18s %-6s %-18s %-6s %7s %8s %8s %-12s"
        print(header % ("src", "sport", "dst", "dport", "pkts", "bytes", "dur_s", "iface"))
        for (src, sport, dst, dport), f in sorted(flows.items(), key=lambda kv: -kv[1]["pkts"])[:20]:
            top_if = f["ifaces"].most_common(1)[0][0]
            print(header % (src, sport, dst, dport, f["pkts"], f["bytes"],
                            f["last"] - f["first"], top_if))

    if probes:
        print("\n=== port %d probes (relative seconds) ===" % PROBE_PORT)
        seen = set()
        for rel, remote, dport, l4len, ifn in sorted(probes):
            key = (remote, dport)
            if key in seen:
                continue
            seen.add(key)
            print("  +%7.2fs  -> %-16s dport=%-5d len=%-4d if=%s" % (rel, remote, dport, l4len, ifn))
    else:
        print("\n(no port %d probe packets in this capture)" % PROBE_PORT)

    match = [(k, v) for k, v in flows.items()
             if k[1] in MATCH_PORTS or k[3] in MATCH_PORTS]
    if match:
        print("\n=== match-server ports %s ===" % (MATCH_PORTS,))
        for (src, sport, dst, dport), f in sorted(match, key=lambda kv: -kv[1]["pkts"]):
            remote = dst if dport in MATCH_PORTS else src
            top_if = f["ifaces"].most_common(1)[0][0]
            print("  %-16s pkts=%-6d first=+%.2fs last=+%.2fs iface=%s"
                  % (remote, f["pkts"], f["first"] - start, f["last"] - start, top_if))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: python tools/parse_pcap.py <capture.pcap> [--probe]")
    main(sys.argv[1], "--probe" in sys.argv[2:])
