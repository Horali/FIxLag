"""KCP reliable subchannel parser (01 51 / 41 51) and per-conv reassembler."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .protocol import lz4_decompress_raw, read_varint


@dataclass(slots=True)
class KcpSegment:
    """Single parsed KCP segment from an MLBB UDP datagram."""

    cmd: int
    conv: bytes
    una: int
    ts: int
    sn: int
    wnd: int
    frg: int
    comp: int
    body: bytes
    from_compressed_pkt: bool = False


def parse_kcp_datagram(payload: bytes) -> tuple[list[KcpSegment], int]:
    """Parse concatenated `01 51/52` and packet-LZ4 `41 51/52` segments in *payload*.

    `41 51` / `41 52` carries `[0x41][cmd][conv:4][ulen_varint][raw_lz4_block]`.
    Decompressing `payload[off:]` yields `una..len + body` followed optionally by
    more concatenated `01 51`/`01 52` segments.
    """
    segments: list[KcpSegment] = []
    lz4_errors = 0
    buf = payload
    i = 0
    from_41 = False

    while i + 2 <= len(buf):
        b0 = buf[i]
        cmd = buf[i + 1]
        if cmd not in (0x51, 0x52):
            break

        if b0 == 0x41:
            if i + 7 > len(buf):
                break
            conv = buf[i + 2 : i + 6]
            try:
                ulen, off = read_varint(buf, i + 6)
                dec = lz4_decompress_raw(buf[off:], ulen)
            except ValueError:
                lz4_errors += 1
                break
            buf = bytes([0x01, cmd]) + conv + dec
            i = 0
            from_41 = True
            continue

        if b0 == 0x01:
            if i + 24 > len(buf):
                break
            conv = buf[i + 2 : i + 6]
            una, kts, sn = struct.unpack_from("<III", buf, i + 6)
            wnd, frg, comp, ln = struct.unpack_from("<HBBH", buf, i + 18)
            if i + 24 + ln > len(buf):
                break
            body = buf[i + 24 : i + 24 + ln]
            segments.append(
                KcpSegment(
                    cmd=cmd,
                    conv=conv,
                    una=una,
                    ts=kts,
                    sn=sn,
                    wnd=wnd,
                    frg=frg,
                    comp=comp,
                    body=body,
                    from_compressed_pkt=from_41,
                )
            )
            i += 24 + ln
            continue

        break

    return segments, lz4_errors


class _ConvBuffer:
    """Per-(ep, direction, conv) segment store for safe `frg == 0` reassembly."""

    __slots__ = ("segs", "pending_ends", "completed_ends", "emitted_sns")

    def __init__(self) -> None:
        self.segs: dict[int, tuple[int, int, bytes, float]] = {}
        self.pending_ends: set[int] = set()
        self.completed_ends: set[int] = set()
        self.emitted_sns: set[int] = set()


@dataclass(slots=True)
class ReassembledKcpMessage:
    """Completed KCP message after fragment reassembly and optional LZ4 decode."""

    ts: float
    ep: tuple[str, int]
    direction: str
    conv: bytes
    sn_start: int
    sn_end: int
    comp: int
    payload: bytes
    complete: bool = True


class KcpStreamReassembler:
    """Reassembles KCP `01 51` / `41 51` streams keyed strictly by `(ep, direction, conv)`."""

    def __init__(self) -> None:
        self._streams: dict[tuple[tuple[str, int], str, bytes], _ConvBuffer] = {}
        self.raw_ok = 0
        self.lz4_ok = 0
        self.lz4_errors = 0
        self.pkt_lz4_errors = 0

    def on_datagram(
        self,
        ts: float,
        ep: tuple[str, int],
        direction: str,
        payload: bytes,
    ) -> list[ReassembledKcpMessage]:
        """Feed one UDP datagram and return any newly completed, decompressed KCP messages."""
        segments, pkt_errs = parse_kcp_datagram(payload)
        self.pkt_lz4_errors += pkt_errs
        out: list[ReassembledKcpMessage] = []

        for seg in segments:
            if seg.cmd != 0x51:
                continue
            key = (ep, direction, seg.conv)
            buf = self._streams.get(key)
            if buf is None:
                buf = _ConvBuffer()
                self._streams[key] = buf

            if seg.sn in buf.emitted_sns or seg.sn in buf.segs:
                continue

            buf.segs[seg.sn] = (seg.frg, seg.comp, seg.body, ts)
            if seg.frg == 0:
                buf.pending_ends.add(seg.sn)

            out.extend(self._drain_ready(buf, ep, direction, seg.conv))

        return out

    def _drain_ready(
        self,
        buf: _ConvBuffer,
        ep: tuple[str, int],
        direction: str,
        conv: bytes,
    ) -> list[ReassembledKcpMessage]:
        ready: list[ReassembledKcpMessage] = []
        for sn_end in sorted(buf.pending_ends):
            run_sns = [sn_end]
            cur = sn_end
            expected_frg = 1
            while (cur - 1) in buf.segs and buf.segs[cur - 1][0] == expected_frg:
                cur -= 1
                run_sns.append(cur)
                expected_frg += 1

            sn_start = run_sns[-1]
            # Guarantee no leading fragment (carrying <ulen_varint>) is missing.
            has_boundary = (
                sn_start == 0
                or (sn_start - 1 in buf.completed_ends)
                or (sn_start - 1 in buf.segs and buf.segs[sn_start - 1][0] == 0)
            )
            if not has_boundary:
                continue

            run_sns.reverse()
            raw = b"".join(buf.segs[s][2] for s in run_sns)
            comp = buf.segs[sn_start][1]
            msg_ts = buf.segs[sn_end][3]

            buf.pending_ends.discard(sn_end)
            buf.completed_ends.add(sn_end)
            for s in run_sns:
                buf.emitted_sns.add(s)
                if s != sn_end:
                    buf.segs.pop(s, None)
            # Keep an empty marker on sn_end only until sn_end+1 proves boundary, or keep tiny stub.
            buf.segs[sn_end] = (0, 0, b"", msg_ts)

            decoded = self._decode_body(raw, comp)
            if decoded is not None:
                ready.append(
                    ReassembledKcpMessage(
                        ts=msg_ts,
                        ep=ep,
                        direction=direction,
                        conv=conv,
                        sn_start=sn_start,
                        sn_end=sn_end,
                        comp=comp,
                        payload=decoded,
                        complete=True,
                    )
                )
        return ready

    def _decode_body(self, raw: bytes, comp: int) -> bytes | None:
        if comp == 0:
            self.raw_ok += 1
            return raw
        if comp == 1:
            try:
                ulen, off = read_varint(raw, 0)
                dec = lz4_decompress_raw(raw[off:], ulen)
            except ValueError:
                self.lz4_errors += 1
                return None
            self.lz4_ok += 1
            return dec
        self.raw_ok += 1
        return raw
