"""Per-interface UDP RTT extraction from MLBB `0x3f5` (`mid=1013`) echo packets."""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from tools.chat_viewer.kcp import KcpStreamReassembler
from tools.chat_viewer.protocol import parse_mlbb_struct, read_varint

from .pcap_net import NetPacket, classify_link

_PING_MARKER = b"\x70\x00\xf5\x07"
_MAX_PENDING_PER_EP = 4096
_MAX_SPARKLINE_POINTS = 180


@dataclass(slots=True)
class RttSample:
    """Single matched `0x3f5` outbound-request to inbound-echo RTT sample."""

    ts: float
    ep: tuple[str, int]
    local_ip: str
    iface_label: str
    link_group: str
    rtt_ms: float
    client_ts: int


def extract_outbound_ping_ts(payload: bytes) -> list[int]:
    """Extract `<client_ts_varint>` values from outbound `0x3f5` (`mid=1013`) TLV envelopes."""
    if _PING_MARKER not in payload:
        return []
    out: list[int] = []
    idx = payload.find(_PING_MARKER)
    while idx >= 0:
        try:
            st, _ = parse_mlbb_struct(payload, idx + 1)
            b5 = st.get(("b", 5))
            if isinstance(b5, bytes) and len(b5) >= 3 and b5[:2] == b"\x70\x00":
                val, _ = read_varint(b5, 2)
                out.append(val)
        except ValueError:
            pass
        idx = payload.find(_PING_MARKER, idx + 4)
    return out


def extract_inbound_echo_ts(payload: bytes) -> list[int]:
    """Extract echoed `<client_ts_varint>` from inbound KCP `mid=0` (`70 00 00`) reply body."""
    if len(payload) < 4 or payload[:3] != b"\x70\x00\x00":
        return []
    try:
        st, _ = parse_mlbb_struct(payload, 1)
    except ValueError:
        return []
    b6 = st.get(("b", 6))
    if isinstance(b6, bytes) and len(b6) >= 3 and b6[:2] == b"\x70\x00":
        try:
            val, _ = read_varint(b6, 2)
            return [val]
        except ValueError:
            return []
    return []


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(pct * (len(sorted_vals) - 1))
    return sorted_vals[idx]


def _bucket_stats(samples: list[RttSample]) -> dict[str, Any]:
    if not samples:
        return {
            "sample_count": 0,
            "min_ms": None,
            "median_ms": None,
            "p95_ms": None,
            "max_ms": None,
            "jitter_ms": None,
        }
    vals = [s.rtt_ms for s in samples]
    svals = sorted(vals)
    diffs = [abs(vals[i] - vals[i - 1]) for i in range(1, len(vals))]
    jitter = statistics.median(diffs) if diffs else 0.0
    return {
        "sample_count": len(vals),
        "min_ms": round(svals[0], 1),
        "median_ms": round(statistics.median(svals), 1),
        "p95_ms": round(_percentile(svals, 0.95), 1),
        "max_ms": round(svals[-1], 1),
        "jitter_ms": round(jitter, 1),
    }


def _downsample_series(
    samples: list[RttSample], t0: float, max_points: int
) -> list[dict[str, Any]]:
    n = len(samples)
    if n == 0:
        return []
    if n <= max_points:
        chosen = samples
    else:
        chosen = [samples[int(i * (n - 1) / (max_points - 1))] for i in range(max_points)]
    return [
        {
            "rel_s": round(max(0.0, s.ts - t0), 2),
            "ts": s.ts,
            "rtt_ms": round(s.rtt_ms, 1),
            "link": s.link_group,
            "local_ip": s.local_ip,
        }
        for s in chosen
    ]


def summarize_samples(
    samples: list[RttSample],
    *,
    base_ts: float | None = None,
    max_points_per_link: int = _MAX_SPARKLINE_POINTS,
) -> dict[str, Any]:
    """Summarize RTT metrics overall, by link group, by `(iface, local_ip)`, plus sparkline points."""
    by_link: dict[str, list[RttSample]] = defaultdict(list)
    by_iface_ip: dict[str, list[RttSample]] = defaultdict(list)
    for s in samples:
        by_link[s.link_group].append(s)
        by_iface_ip[f"{s.iface_label} ({s.local_ip})"].append(s)

    t0 = base_ts if base_ts is not None else (samples[0].ts if samples else 0.0)
    links_out: dict[str, Any] = {
        "Wi-Fi": _bucket_stats(by_link.get("Wi-Fi", [])),
        "Cellular": _bucket_stats(by_link.get("Cellular", [])),
        "Combined": _bucket_stats(samples),
    }
    if by_link.get("Other"):
        links_out["Other"] = _bucket_stats(by_link["Other"])

    series: list[dict[str, Any]] = []
    for grp in ("Wi-Fi", "Cellular", "Other"):
        grp_samples = by_link.get(grp)
        if grp_samples:
            series.extend(_downsample_series(grp_samples, t0, max_points_per_link))
    series.sort(key=lambda pt: pt["ts"])

    return {
        "links": links_out,
        "by_iface_ip": {k: _bucket_stats(v) for k, v in sorted(by_iface_ip.items())},
        "series": series,
    }


class RttTracker:
    """Tracks outbound `0x3f5` requests and matches inbound `mid=0` echoes per interface/link."""

    def __init__(self) -> None:
        self._kcp_in = KcpStreamReassembler()
        self._kcp_out = KcpStreamReassembler()
        self._pending_exact: dict[tuple[tuple[str, int], str], dict[int, tuple[float, str, str]]] = defaultdict(dict)
        self._pending_fallback: dict[tuple[str, int], dict[int, tuple[float, str, str, str]]] = defaultdict(dict)
        self._seen_outbound_ips: dict[tuple[str, int], set[str]] = defaultdict(set)
        self._samples_by_ep: dict[tuple[str, int], list[RttSample]] = defaultdict(list)

    def reset(self) -> None:
        """Clear all pending requests and collected RTT samples."""
        self._kcp_in = KcpStreamReassembler()
        self._kcp_out = KcpStreamReassembler()
        self._pending_exact.clear()
        self._pending_fallback.clear()
        self._seen_outbound_ips.clear()
        self._samples_by_ep.clear()

    def _record_outbound(self, ep: tuple[str, int], local_ip: str, ifindex: int | None, ts: float, c_ts: int) -> None:
        iface_label, link_group = classify_link(local_ip, ifindex)
        self._seen_outbound_ips[ep].add(local_ip)

        bucket = self._pending_exact[(ep, local_ip)]
        bucket[c_ts] = (ts, iface_label, link_group)
        if len(bucket) > _MAX_PENDING_PER_EP:
            oldest = next(iter(bucket))
            bucket.pop(oldest, None)

        fb = self._pending_fallback[ep]
        fb[c_ts] = (ts, local_ip, iface_label, link_group)
        if len(fb) > _MAX_PENDING_PER_EP:
            oldest_fb = next(iter(fb))
            fb.pop(oldest_fb, None)

    def on_udp_packet(
        self, pkt: NetPacket, *, ep: tuple[str, int], direction: str
    ) -> list[RttSample]:
        """Process one MLBB match-port UDP packet and return any new `RttSample`s."""
        if pkt.proto != "udp":
            return []
        payload = pkt.payload
        if direction == "out":
            local_ip = pkt.src_ip
            ts_vals = extract_outbound_ping_ts(payload)
            if not ts_vals and payload[:2] in (b"\x01\x51", b"\x41\x51"):
                for msg in self._kcp_out.on_datagram(pkt.ts, ep, "out", payload):
                    ts_vals.extend(extract_outbound_ping_ts(msg.payload))
            for val in ts_vals:
                self._record_outbound(ep, local_ip, pkt.ifindex, pkt.ts, val)
            return []

        if payload[:2] not in (b"\x01\x51", b"\x41\x51", b"\x01\x52", b"\x41\x52"):
            return []

        local_ip = pkt.dst_ip
        new_samples: list[RttSample] = []
        exact_bucket = self._pending_exact.get((ep, local_ip))
        fb_bucket = self._pending_fallback.get(ep)
        local_seen_out = local_ip in self._seen_outbound_ips.get(ep, set())

        for msg in self._kcp_in.on_datagram(pkt.ts, ep, "in", payload):
            for c_ts in extract_inbound_echo_ts(msg.payload):
                rec = exact_bucket.pop(c_ts, None) if exact_bucket is not None else None
                matched_ip = local_ip
                if rec is None and not local_seen_out and fb_bucket is not None:
                    fb_rec = fb_bucket.pop(c_ts, None)
                    if fb_rec is not None:
                        out_ts, matched_ip, iface_label, link_group = fb_rec
                        rec = (out_ts, iface_label, link_group)
                elif rec is not None and fb_bucket is not None:
                    fb_bucket.pop(c_ts, None)

                if rec is None:
                    continue
                out_ts, iface_label, link_group = rec
                if pkt.ifindex is not None and matched_ip == local_ip:
                    iface_label, link_group = classify_link(local_ip, pkt.ifindex)
                rtt_ms = (pkt.ts - out_ts) * 1000.0
                if 0.5 <= rtt_ms <= 5000.0:
                    sample = RttSample(
                        ts=pkt.ts,
                        ep=ep,
                        local_ip=matched_ip,
                        iface_label=iface_label,
                        link_group=link_group,
                        rtt_ms=rtt_ms,
                        client_ts=c_ts,
                    )
                    self._samples_by_ep[ep].append(sample)
                    new_samples.append(sample)
        return new_samples

    def get_samples(
        self,
        ep: tuple[str, int],
        *,
        start_ts: float | None = None,
        end_ts: float | None = None,
    ) -> list[RttSample]:
        """Return samples for *ep*, optionally bounded to `[start_ts, end_ts]`."""
        all_samples = self._samples_by_ep.get(ep, [])
        if start_ts is None and end_ts is None:
            return list(all_samples)
        lo = start_ts if start_ts is not None else -1e18
        hi = end_ts if end_ts is not None else 1e18
        return [s for s in all_samples if lo <= s.ts <= hi]

    def summarize_endpoint(
        self,
        ep: tuple[str, int],
        *,
        start_ts: float | None = None,
        end_ts: float | None = None,
    ) -> dict[str, Any]:
        """Compute full RTT stats and sparkline series for one endpoint and optional time window."""
        samples = self.get_samples(ep, start_ts=start_ts, end_ts=end_ts)
        return summarize_samples(samples, base_ts=start_ts)
