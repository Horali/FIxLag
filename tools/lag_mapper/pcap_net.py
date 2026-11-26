"""Incremental PCAP reader emitting IPv4 UDP and TCP packets across RAW/Eth/SLL/SLL2."""

from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass

from tools.chat_viewer.pcap_reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    LINKTYPE_SLL,
    LINKTYPE_SLL2,
    PCAP_MAGICS,
    SUPPORTED_LINKTYPES,
    InvalidPcapMagicError,
    UdpPacket,
)

_WIFI_NETS = (
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
)
_CELL_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
)


@dataclass(slots=True)
class NetPacket:
    """Single decoded IPv4 UDP or TCP packet from a non-truncated PCAP record."""

    ts: float
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    proto: str  # "udp" | "tcp"
    payload: bytes
    ifindex: int | None
    tcp_seq: int = 0
    tcp_flags: int = 0
    orig_len: int = 0
    incl_len: int = 0

    def to_udp_packet(self) -> UdpPacket:
        """Convert to `tools.chat_viewer.pcap_reader.UdpPacket` for read-only session reuse."""
        return UdpPacket(
            ts=self.ts,
            src_ip=self.src_ip,
            sport=self.sport,
            dst_ip=self.dst_ip,
            dport=self.dport,
            payload=self.payload,
            if_index=self.ifindex,
            orig_len=self.orig_len,
            incl_len=self.incl_len,
        )


def classify_link(local_ip: str, ifindex: int | None) -> tuple[str, str]:
    """Return `(iface_label, link_group)` from SLL2 ifindex or local IP fallback."""
    if ifindex == 44:
        return "wlan0", "Wi-Fi"
    if ifindex in (62, 63, 123):
        return "rmnet_data0", "Cellular"
    if ifindex == 14:
        return "rmnet_ipa0", "Cellular"

    iface_hint = f"if{ifindex}" if ifindex is not None else None
    try:
        ip_obj = ipaddress.IPv4Address(local_ip)
    except ValueError:
        return iface_hint or "unknown", "Other"

    if any(ip_obj in net for net in _WIFI_NETS):
        return iface_hint or "wlan0", "Wi-Fi"
    if any(ip_obj in net for net in _CELL_NETS):
        return iface_hint or "rmnet_data0", "Cellular"
    return iface_hint or "unknown", "Other"


def _decode_link_layer(pkt: bytes, linktype: int) -> tuple[int | None, bytes | None, int | None]:
    if linktype == LINKTYPE_RAW:
        if not pkt:
            return None, None, None
        ver = pkt[0] >> 4
        if ver == 4:
            return 0x0800, pkt, None
        if ver == 6:
            return 0x86DD, pkt, None
        return None, None, None

    if linktype == LINKTYPE_ETHERNET:
        if len(pkt) < 14:
            return None, None, None
        ethertype = struct.unpack_from("!H", pkt, 12)[0]
        off = 14
        while ethertype in (0x8100, 0x88A8) and off + 4 <= len(pkt):
            ethertype = struct.unpack_from("!H", pkt, off + 2)[0]
            off += 4
        return ethertype, pkt[off:], None

    if linktype == LINKTYPE_SLL:
        if len(pkt) < 16:
            return None, None, None
        ethertype = struct.unpack_from("!H", pkt, 14)[0]
        return ethertype, pkt[16:], None

    if linktype == LINKTYPE_SLL2:
        if len(pkt) < 20:
            return None, None, None
        ethertype = struct.unpack_from("!H", pkt, 0)[0]
        ifindex = struct.unpack_from("!I", pkt, 4)[0]
        return ethertype, pkt[20:], ifindex

    return None, None, None


def _decode_ipv4_l4(
    ethertype: int | None, l3: bytes | None
) -> tuple[str, str, int, int, str, bytes, int, int] | None:
    if ethertype != 0x0800 or l3 is None or len(l3) < 20:
        return None
    ihl = (l3[0] & 0x0F) * 4
    if ihl < 20 or len(l3) < ihl:
        return None
    frag = struct.unpack_from("!H", l3, 6)[0]
    if (frag & 0x1FFF) != 0:
        return None

    tot_len = struct.unpack_from("!H", l3, 2)[0]
    ip_end = min(len(l3), tot_len) if tot_len >= ihl else len(l3)
    proto_num = l3[9]
    src_ip = socket.inet_ntoa(l3[12:16])
    dst_ip = socket.inet_ntoa(l3[16:20])
    l4 = l3[ihl:ip_end]

    if proto_num == 17:
        if len(l4) < 8:
            return None
        sport, dport, ulen = struct.unpack_from("!HHH", l4, 0)
        body = l4[8:ulen] if 8 <= ulen <= len(l4) else l4[8:]
        return src_ip, dst_ip, sport, dport, "udp", body, 0, 0

    if proto_num == 6:
        if len(l4) < 20:
            return None
        sport, dport, seq = struct.unpack_from("!HHI", l4, 0)
        doff = (l4[12] >> 4) * 4
        flags = l4[13]
        if doff < 20 or len(l4) < doff:
            return None
        return src_ip, dst_ip, sport, dport, "tcp", l4[doff:], seq, flags

    return None


class IncrementalNetPcapReader:
    """Chunk-safe incremental PCAP reader for IPv4 UDP and TCP packets."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.offset = 0
        self.header_parsed = False
        self.endian = "<"
        self.ts_div = 1_000_000.0
        self.snaplen = 0
        self.linktype = 0
        self.total_records = 0
        self.skipped_truncated = 0

    def feed(self, chunk: bytes) -> list[NetPacket]:
        """Consume an arbitrary byte chunk and return complete decoded IPv4 UDP/TCP packets."""
        if not chunk:
            return []
        self._buf.extend(chunk)

        if not self.header_parsed:
            if len(self._buf) >= 4:
                magic = bytes(self._buf[:4])
                spec = PCAP_MAGICS.get(magic)
                if spec is None:
                    raise InvalidPcapMagicError(f"invalid pcap magic {magic!r}")
            if len(self._buf) < 24:
                return []
            magic = bytes(self._buf[:4])
            self.endian, self.ts_div = PCAP_MAGICS[magic]
            _, _, _, _, _, self.snaplen, self.linktype = struct.unpack_from(self.endian + "IHHIIII", self._buf, 0)
            if self.linktype not in SUPPORTED_LINKTYPES:
                raise InvalidPcapMagicError(f"unsupported pcap linktype {self.linktype}")
            del self._buf[:24]
            self.offset += 24
            self.header_parsed = True

        packets: list[NetPacket] = []
        pos = 0
        buf_len = len(self._buf)
        hdr_fmt = self.endian + "IIII"

        while buf_len - pos >= 16:
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack_from(hdr_fmt, self._buf, pos)
            rec_total = 16 + incl_len
            if buf_len - pos < rec_total:
                break
            raw_rec = bytes(self._buf[pos + 16 : pos + rec_total])
            pos += rec_total
            self.total_records += 1

            if orig_len > incl_len:
                self.skipped_truncated += 1
                continue

            ethertype, l3, ifindex = _decode_link_layer(raw_rec, self.linktype)
            parsed = _decode_ipv4_l4(ethertype, l3)
            if parsed is None:
                continue

            src_ip, dst_ip, sport, dport, proto, body, tcp_seq, tcp_flags = parsed
            ts = ts_sec + (ts_sub / self.ts_div)
            packets.append(
                NetPacket(
                    ts=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    sport=sport,
                    dport=dport,
                    proto=proto,
                    payload=body,
                    ifindex=ifindex,
                    tcp_seq=tcp_seq,
                    tcp_flags=tcp_flags,
                    orig_len=orig_len,
                    incl_len=incl_len,
                )
            )

        if pos > 0:
            del self._buf[:pos]
            self.offset += pos

        return packets
