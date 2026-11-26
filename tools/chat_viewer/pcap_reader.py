"""Incremental partial-record-safe PCAP reader supporting SLL2, SLL, Ethernet, and Raw IP."""

from __future__ import annotations

import struct
from dataclasses import dataclass

# Magic -> (endianness, timestamp_divisor)
PCAP_MAGICS: dict[bytes, tuple[str, float]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
}

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_SLL = 113
LINKTYPE_SLL2 = 276
SUPPORTED_LINKTYPES = frozenset({LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_SLL, LINKTYPE_SLL2})


class InvalidPcapMagicError(ValueError):
    """Raised immediately if the stream does not begin with a valid PCAP magic."""


@dataclass(slots=True)
class UdpPacket:
    """Single decoded UDP datagram from a non-truncated PCAP record."""

    ts: float
    src_ip: str
    sport: int
    dst_ip: str
    dport: int
    payload: bytes
    if_index: int | None
    orig_len: int
    incl_len: int


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
        if_index = struct.unpack_from("!I", pkt, 4)[0]
        return ethertype, pkt[20:], if_index

    return None, None, None


def _decode_udp_payload(ethertype: int | None, payload: bytes | None) -> tuple[str, int, str, int, bytes] | None:
    if ethertype is None or payload is None:
        return None

    if ethertype == 0x0800:
        if len(payload) < 20:
            return None
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl or payload[9] != 17:
            return None
        frag = struct.unpack_from("!H", payload, 6)[0]
        if (frag & 0x1FFF) != 0:
            return None
        src_ip = ".".join(str(b) for b in payload[12:16])
        dst_ip = ".".join(str(b) for b in payload[16:20])
        l4 = payload[ihl:]
    elif ethertype == 0x86DD:
        if len(payload) < 40 or payload[6] != 17:
            return None
        src_ip = ":".join(f"{w:x}" for w in struct.unpack_from("!8H", payload, 8))
        dst_ip = ":".join(f"{w:x}" for w in struct.unpack_from("!8H", payload, 24))
        l4 = payload[40:]
    else:
        return None

    if len(l4) < 8:
        return None
    sport, dport, ulen = struct.unpack_from("!HHH", l4, 0)
    body = l4[8:]
    if ulen >= 8 and len(body) > ulen - 8:
        body = body[: ulen - 8]
    return src_ip, sport, dst_ip, dport, body


class IncrementalPcapReader:
    """Chunk-safe incremental PCAP stream reader.

    Buffer retains unconsumed bytes until a full global header (24 B) or
    full record header + body (16 + incl_len B) is available. Records with
    `orig_len > incl_len` are skipped before reaching downstream decoders.
    """

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

    def feed(self, chunk: bytes) -> list[UdpPacket]:
        """Consume an arbitrary byte chunk and return complete decoded UDP packets."""
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
            spec = PCAP_MAGICS[magic]
            self.endian, self.ts_div = spec
            _, _, _, _, _, self.snaplen, self.linktype = struct.unpack_from(self.endian + "IHHIIII", self._buf, 0)
            if self.linktype not in SUPPORTED_LINKTYPES:
                raise InvalidPcapMagicError(f"unsupported pcap linktype {self.linktype}")
            del self._buf[:24]
            self.offset += 24
            self.header_parsed = True

        packets: list[UdpPacket] = []
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

            ethertype, l3, if_idx = _decode_link_layer(raw_rec, self.linktype)
            udp = _decode_udp_payload(ethertype, l3)
            if udp is None:
                continue
            src_ip, sport, dst_ip, dport, body = udp
            ts = ts_sec + (ts_sub / self.ts_div)
            packets.append(
                UdpPacket(
                    ts=ts,
                    src_ip=src_ip,
                    sport=sport,
                    dst_ip=dst_ip,
                    dport=dport,
                    payload=body,
                    if_index=if_idx,
                    orig_len=orig_len,
                    incl_len=incl_len,
                )
            )

        if pos > 0:
            del self._buf[:pos]
            self.offset += pos

        return packets
