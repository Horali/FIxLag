"""Sequence-ordered TCP :30101 lobby gateway decoder with batch/cached Zstd and strict PII skip."""

from __future__ import annotations

import importlib.util
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.chat_viewer.protocol import parse_mlbb_struct, read_varint

from .pcap_net import NetPacket, classify_link

DEFAULT_ZSTD_EXE = Path(r"C:\msys64\ucrt64\bin\zstd.EXE")
LOBBY_PORT = 30101
DROP_MIDS = frozenset({10208})
ALLOWLISTED_MIDS = frozenset({20008, 10144, 11169, 11499, 10017})
MAX_STREAM_BYTES = 4 * 1024 * 1024
MAX_OUT_OF_ORDER_BYTES = 512 * 1024
MAX_BATCH_FRAMES = 256
MAX_BATCH_OUTPUT_BYTES = 8 * 1024 * 1024

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_EP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{4,5}\b")
_GEO_RE = re.compile(r"\b[a-z]{2}\|[A-Za-z0-9 _-]+\|[A-Za-z0-9 _-]+\b")
_TRACE_RE = re.compile(r"\b(?:client_[A-Za-z0-9_]+|Main_UI_[A-Za-z0-9_]+|gamereconnectInfo|Cmd_[A-Za-z0-9_]+)\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_TOKEN_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?\b")
_UNSET = object()


def redact_pii(text: str) -> str:
    """Redact email addresses and JWT/auth token strings."""
    cleaned = _EMAIL_RE.sub("[redacted-email]", text)
    return _TOKEN_RE.sub("[redacted-token]", cleaned)


def find_zstd(override: Path | str | None | object = _UNSET) -> tuple[str | None, Path | None]:
    """Return `(backend, exe_path)` where backend is `'zstandard'`, `'cli'`, or `None`."""
    if override is None:
        return None, None
    if override is not _UNSET:
        p = Path(str(override))
        return ("cli", p) if p.is_file() else (None, None)

    if importlib.util.find_spec("zstandard") is not None:
        return "zstandard", None
    if DEFAULT_ZSTD_EXE.is_file():
        return "cli", DEFAULT_ZSTD_EXE
    which = shutil.which("zstd")
    if which:
        return "cli", Path(which)
    return None, None


def parse_zstd_frame_content_size(frame: bytes) -> int | None:
    """Read uncompressed Frame_Content_Size from a Zstd frame header if present."""
    if len(frame) < 6 or frame[:4] != _ZSTD_MAGIC:
        return None
    fhd = frame[4]
    fcs_flag = (fhd >> 6) & 3
    single_seg = (fhd >> 5) & 1
    did_size = (0, 1, 2, 4)[fhd & 3]
    off = 5 + (0 if single_seg else 1) + did_size
    if fcs_flag == 0:
        if single_seg and off + 1 <= len(frame):
            return frame[off]
        return None
    if fcs_flag == 1:
        return (struct.unpack_from("<H", frame, off)[0] + 256) if off + 2 <= len(frame) else None
    if fcs_flag == 2:
        return struct.unpack_from("<I", frame, off)[0] if off + 4 <= len(frame) else None
    if fcs_flag == 3:
        return struct.unpack_from("<Q", frame, off)[0] if off + 8 <= len(frame) else None
    return None


def _is_valid_ipv4_port(ep: str) -> bool:
    host, _, port_s = ep.rpartition(":")
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        if any(not (0 <= int(p) <= 255) for p in parts):
            return False
        port = int(port_s)
        return 1 <= port <= 65535
    except ValueError:
        return False


def _geo_specificity(geo: str) -> tuple[int, int]:
    parts = [p.strip() for p in geo.split("|") if p.strip()]
    if len(parts) >= 3 and parts[1].lower() != parts[2].lower():
        return (2, len(geo))
    if len(parts) >= 2:
        return (1, len(geo))
    return (0, len(geo))


def _extract_geo_cards(st: dict[Any, Any]) -> list[tuple[str, str]]:
    cards: list[tuple[str, str]] = []

    def visit(obj: Any) -> None:
        if isinstance(obj, dict):
            raw_name = obj.get(("b", 2))
            if isinstance(raw_name, bytes):
                name = redact_pii(raw_name.decode("utf-8", "replace")).strip()
                if name and "@" not in name and len(name) <= 48:
                    geo = _extract_card_geo(obj)
                    if geo:
                        cards.append((name, geo))
            for val in obj.values():
                visit(val)
        elif isinstance(obj, list):
            for item in obj:
                visit(item)
        elif isinstance(obj, bytes) and len(obj) >= 3 and obj[0] == 0x70:
            try:
                sub, _ = parse_mlbb_struct(obj, 1)
                visit(sub)
            except ValueError:
                pass

    visit(st)
    return cards


def _extract_card_geo(card: dict[Any, Any]) -> str:
    cc_raw = card.get(("b", 87)) or card.get(("b", 97))
    cc = ""
    if isinstance(cc_raw, bytes):
        cc_txt = cc_raw.decode("utf-8", "ignore").strip().lower()
        if 2 <= len(cc_txt) <= 3 and cc_txt.isalpha():
            cc = cc_txt

    l71 = card.get(("l", 71))
    if isinstance(l71, list):
        parts: list[str] = []
        for x in l71:
            if isinstance(x, bytes):
                s = redact_pii(x.decode("utf-8", "ignore")).strip()
                if s and s not in parts:
                    parts.append(s)
        if len(parts) >= 3:
            prefix = cc or parts[0][:2].lower()
            return f"{prefix}|{parts[1]}|{parts[2]}"
        if len(parts) == 2:
            prefix = cc or parts[0][:2].lower()
            return f"{prefix}|{parts[0]}|{parts[1]}"

    s92 = card.get(("s", 92))
    if isinstance(s92, dict):
        l3 = s92.get(("l", 3))
        if isinstance(l3, list):
            for x in l3:
                if isinstance(x, bytes):
                    txt = redact_pii(x.decode("utf-8", "ignore"))
                    m = _GEO_RE.search(txt)
                    if m:
                        return m.group(0)
    return ""


@dataclass(slots=True)
class _PendingZstdFrame:
    ts: float
    gateway_ip: str
    link_group: str
    payload: bytes
    fcs: int | None


class _TcpStreamReassembler:
    """Per-direction sequence-ordered TCP stream buffer capped at `MAX_STREAM_BYTES`."""

    __slots__ = ("buf", "next_seq", "pending", "pending_bytes", "last_ts", "gateway_ip", "link_group")

    def __init__(self, gateway_ip: str, link_group: str) -> None:
        self.buf = bytearray()
        self.next_seq: int | None = None
        self.pending: dict[int, bytes] = {}
        self.pending_bytes = 0
        self.last_ts = 0.0
        self.gateway_ip = gateway_ip
        self.link_group = link_group

    def add_segment(self, seq: int, ts: float, payload: bytes, gateway_ip: str, link_group: str) -> None:
        self.last_ts = max(self.last_ts, ts)
        self.gateway_ip = gateway_ip
        self.link_group = link_group
        if not payload:
            return

        if self.next_seq is None:
            self.buf.extend(payload)
            self.next_seq = (seq + len(payload)) & 0xFFFFFFFF
        else:
            diff = (seq - self.next_seq) & 0xFFFFFFFF
            if diff == 0:
                self.buf.extend(payload)
                self.next_seq = (self.next_seq + len(payload)) & 0xFFFFFFFF
                self._drain_pending()
            elif diff < 0x80000000:
                if diff <= MAX_OUT_OF_ORDER_BYTES and self.pending_bytes + len(payload) <= MAX_OUT_OF_ORDER_BYTES:
                    if seq not in self.pending or len(payload) > len(self.pending[seq]):
                        self.pending_bytes += len(payload) - len(self.pending.get(seq, b""))
                        self.pending[seq] = payload
            else:
                back = (self.next_seq - seq) & 0xFFFFFFFF
                if back < len(payload):
                    self.buf.extend(payload[back:])
                    self.next_seq = (seq + len(payload)) & 0xFFFFFFFF
                    self._drain_pending()

        if len(self.buf) > MAX_STREAM_BYTES:
            drop = len(self.buf) - MAX_STREAM_BYTES
            del self.buf[:drop]

    def _drain_pending(self) -> None:
        assert self.next_seq is not None
        while self.pending:
            progressed = False
            for seq in list(self.pending):
                diff = (seq - self.next_seq) & 0xFFFFFFFF
                if diff == 0:
                    data = self.pending.pop(seq)
                    self.pending_bytes -= len(data)
                    self.buf.extend(data)
                    self.next_seq = (self.next_seq + len(data)) & 0xFFFFFFFF
                    progressed = True
                elif diff >= 0x80000000:
                    data = self.pending.pop(seq)
                    self.pending_bytes -= len(data)
                    back = (self.next_seq - seq) & 0xFFFFFFFF
                    if back < len(data):
                        self.buf.extend(data[back:])
                        self.next_seq = (self.next_seq + len(data) - back) & 0xFFFFFFFF
                    progressed = True
            if not progressed:
                break

    def pop_frames(self) -> list[tuple[int, bytes]]:
        frames: list[tuple[int, bytes]] = []
        pos = 0
        n = len(self.buf)
        while pos + 4 <= n:
            flag = self.buf[pos]
            total_len = int.from_bytes(self.buf[pos + 1 : pos + 4], "big")
            if flag not in (0x00, 0x10) or total_len < 4 or total_len > 2 * 1024 * 1024:
                pos += 1
                continue
            if pos + total_len > n:
                break
            frames.append((flag, bytes(self.buf[pos + 4 : pos + total_len])))
            pos += total_len
        if pos > 0:
            del self.buf[:pos]
        return frames


class TcpLobbyDecoder:
    """Reassembles TCP :30101 lobby streams and extracts non-PII handovers, geo cards, and traces."""

    def __init__(
        self,
        *,
        zstd_path: Path | str | None | object = _UNSET,
        enable_zstd: bool = True,
        live_mode: bool = False,
    ) -> None:
        if not enable_zstd:
            self._zstd_backend, self._zstd_exe = None, None
        else:
            self._zstd_backend, self._zstd_exe = find_zstd(zstd_path)
        self.zstd_available = self._zstd_backend is not None
        self.live_mode = live_mode

        self._streams: dict[tuple[str, int, str, int], _TcpStreamReassembler] = {}
        self._pending_zstd: list[_PendingZstdFrame] = []
        self._zstd_mod: Any = None
        if self._zstd_backend == "zstandard":
            import zstandard as zstd_mod  # type: ignore[import-not-found]

            self._zstd_mod = zstd_mod

        self.raw_frames = 0
        self.zstd_frames = 0
        self.skipped_zstd_frames = 0
        self.dropped_pii_frames = 0
        self.zstd_errors = 0

        self.handovers: list[dict[str, Any]] = []
        self.lobby_geo_by_name: dict[str, str] = {}
        self.traces: list[dict[str, Any]] = []
        self._seen_geo_pairs: set[tuple[str, str]] = set()
        self._seen_handover_keys: set[tuple[float, str]] = set()

    def reset(self) -> None:
        """Reset streams and extracted lobby metadata."""
        self._streams.clear()
        self._pending_zstd.clear()
        self.raw_frames = 0
        self.zstd_frames = 0
        self.skipped_zstd_frames = 0
        self.dropped_pii_frames = 0
        self.zstd_errors = 0
        self.handovers.clear()
        self.lobby_geo_by_name.clear()
        self.traces.clear()
        self._seen_geo_pairs.clear()
        self._seen_handover_keys.clear()

    def on_tcp_packet(self, pkt: NetPacket) -> list[dict[str, Any]]:
        """Ingest one TCP :30101 packet and return any immediately decoded lobby events."""
        if pkt.proto != "tcp" or (pkt.sport != LOBBY_PORT and pkt.dport != LOBBY_PORT):
            return []

        if pkt.sport == LOBBY_PORT:
            gateway_ip = pkt.src_ip
            local_ip = pkt.dst_ip
        else:
            gateway_ip = pkt.dst_ip
            local_ip = pkt.src_ip
        _, link_group = classify_link(local_ip, pkt.ifindex)

        key = (pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport)
        stream = self._streams.get(key)
        if stream is None:
            stream = _TcpStreamReassembler(gateway_ip, link_group)
            self._streams[key] = stream
        stream.add_segment(pkt.tcp_seq, pkt.ts, pkt.payload, gateway_ip, link_group)

        events: list[dict[str, Any]] = []
        for flag, body in stream.pop_frames():
            if flag == 0x00:
                self.raw_frames += 1
                events.extend(self._decode_inner_payload(body, pkt.ts, gateway_ip, link_group))
            elif flag == 0x10 and body.startswith(_ZSTD_MAGIC):
                self.zstd_frames += 1
                if not self.zstd_available:
                    self.skipped_zstd_frames += 1
                    continue
                fcs = parse_zstd_frame_content_size(body)
                self._pending_zstd.append(_PendingZstdFrame(pkt.ts, gateway_ip, link_group, body, fcs))
                if self.live_mode or len(self._pending_zstd) >= MAX_BATCH_FRAMES:
                    events.extend(self.flush())
        return events

    def flush(self) -> list[dict[str, Any]]:
        """Decompress all queued Zstd frames (batched for CLI speed) and return new events."""
        if not self._pending_zstd:
            return []
        batch = list(self._pending_zstd)
        self._pending_zstd.clear()

        if not self.zstd_available:
            self.skipped_zstd_frames += len(batch)
            return []

        events: list[dict[str, Any]] = []
        if self._zstd_backend == "zstandard" and self._zstd_mod is not None:
            dctx = self._zstd_mod.ZstdDecompressor()
            for item in batch:
                try:
                    dec = dctx.decompress(item.payload, max_output_size=MAX_BATCH_OUTPUT_BYTES)
                except Exception:
                    self.zstd_errors += 1
                    continue
                events.extend(self._decode_inner_payload(dec, item.ts, item.gateway_ip, item.link_group))
            return events

        # CLI batch mode: split into groups with known FCS <= MAX_BATCH_OUTPUT_BYTES.
        cur_group: list[_PendingZstdFrame] = []
        cur_out = 0
        for item in batch:
            if item.fcs is None or item.fcs < 0 or item.fcs > MAX_BATCH_OUTPUT_BYTES:
                if cur_group:
                    events.extend(self._run_cli_batch(cur_group))
                    cur_group.clear()
                    cur_out = 0
                events.extend(self._run_cli_single(item))
                continue
            if len(cur_group) >= MAX_BATCH_FRAMES or (cur_out + item.fcs > MAX_BATCH_OUTPUT_BYTES):
                events.extend(self._run_cli_batch(cur_group))
                cur_group.clear()
                cur_out = 0
            cur_group.append(item)
            cur_out += item.fcs

        if cur_group:
            events.extend(self._run_cli_batch(cur_group))
        return events

    def _run_cli_batch(self, items: list[_PendingZstdFrame]) -> list[dict[str, Any]]:
        if self._zstd_exe is None:
            self.skipped_zstd_frames += len(items)
            return []
        blob = b"".join(it.payload for it in items)
        expected_len = sum(it.fcs or 0 for it in items)
        try:
            proc = subprocess.run(
                [str(self._zstd_exe), "-d", "--stdout"],
                input=blob,
                capture_output=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            self.zstd_errors += len(items)
            return []

        if proc.returncode == 0 and len(proc.stdout) == expected_len:
            events: list[dict[str, Any]] = []
            off = 0
            for it in items:
                sz = it.fcs or 0
                dec = proc.stdout[off : off + sz]
                off += sz
                events.extend(self._decode_inner_payload(dec, it.ts, it.gateway_ip, it.link_group))
            return events

        # Fallback per-frame if a concatenated batch has a bad frame.
        events = []
        for it in items:
            events.extend(self._run_cli_single(it))
        return events

    def _run_cli_single(self, item: _PendingZstdFrame) -> list[dict[str, Any]]:
        if self._zstd_exe is None:
            self.skipped_zstd_frames += 1
            return []
        try:
            proc = subprocess.run(
                [str(self._zstd_exe), "-d", "--stdout"],
                input=item.payload,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            self.zstd_errors += 1
            return []
        if proc.returncode != 0:
            self.zstd_errors += 1
            return []
        return self._decode_inner_payload(proc.stdout, item.ts, item.gateway_ip, item.link_group)

    def _decode_inner_payload(
        self, dec: bytes, ts: float, gateway_ip: str, link_group: str
    ) -> list[dict[str, Any]]:
        if len(dec) < 3 or dec[0] != 0x70 or dec[1] != 0x00:
            return []
        try:
            mid, _ = read_varint(dec, 2)
        except ValueError:
            return []

        # Hard PII privacy boundary: drop mid=10208 before any text decode or regex.
        if mid in DROP_MIDS:
            self.dropped_pii_frames += 1
            return []
        if mid not in ALLOWLISTED_MIDS:
            return []

        events: list[dict[str, Any]] = []
        if mid == 20008:
            text = redact_pii(dec.decode("utf-8", "ignore"))
            for ep_str in _EP_RE.findall(text):
                if not _is_valid_ipv4_port(ep_str):
                    continue
                tip, _, tport_s = ep_str.rpartition(":")
                key = (round(ts, 2), ep_str)
                if key in self._seen_handover_keys:
                    continue
                self._seen_handover_keys.add(key)
                rec = {
                    "type": "LOBBY_HANDOVER",
                    "ts": ts,
                    "gateway_ip": gateway_ip,
                    "target_ip": tip,
                    "target_port": int(tport_s),
                    "target_ep": ep_str,
                    "link": link_group,
                    "summary": f"mid=20008 handover {gateway_ip}:30101 -> {ep_str}",
                }
                self.handovers.append(rec)
                events.append(rec)
            return events

        if mid in (10144, 11169, 11499):
            try:
                st, _ = parse_mlbb_struct(dec, 1)
            except ValueError:
                return []
            for name, geo in _extract_geo_cards(st):
                clean_name = redact_pii(name)
                clean_geo = redact_pii(geo)
                prev = self.lobby_geo_by_name.get(clean_name)
                if prev is None or _geo_specificity(clean_geo) > _geo_specificity(prev):
                    self.lobby_geo_by_name[clean_name] = clean_geo
                pair = (clean_name, clean_geo)
                if pair not in self._seen_geo_pairs:
                    self._seen_geo_pairs.add(pair)
                    events.append(
                        {
                            "type": "LOBBY_GEO",
                            "ts": ts,
                            "mid": mid,
                            "gateway_ip": gateway_ip,
                            "link": link_group,
                            "player": clean_name,
                            "geo": clean_geo,
                            "summary": f"mid={mid} lobby geo: {clean_name} -> {clean_geo}",
                        }
                    )
            return events

        if mid == 10017:
            text = dec.decode("utf-8", "ignore")
            hits = []
            for tok in _TRACE_RE.findall(text):
                if tok not in hits:
                    hits.append(tok)
            if hits:
                rec = {
                    "type": "LOBBY_TRACE",
                    "ts": ts,
                    "gateway_ip": gateway_ip,
                    "link": link_group,
                    "keywords": hits[:4],
                    "summary": f"mid=10017 trace: {', '.join(hits[:3])}",
                }
                if len(self.traces) < 200:
                    self.traces.append(rec)
                events.append(rec)
            return events

        return []
