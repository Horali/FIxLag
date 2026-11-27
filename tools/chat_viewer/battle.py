"""Battle tick subframe parser (01 75), TickReorderBuffer, and LZW-16 / raw decoder."""

from __future__ import annotations

from dataclasses import dataclass, field

from .protocol import (
    extract_events_from_struct_list,
    extract_events_from_tick_bytes,
    parse_mlbb_struct,
    read_varint,
)

LZW_CLEAR_CODE = 0x0100
LZW_FIRST_CODE = 0x0101
LZW_MAX_TABLE = 0x4000
STALL_GAP_THRESHOLD = 75


def parse_0175_subframes(payload: bytes) -> list[tuple[bytes, bytes]]:
    """Split coalesced `01 75 <conv:4> <plen:2 LE> <sub>` frames from one UDP packet."""
    out: list[tuple[bytes, bytes]] = []
    i = 0
    n = len(payload)
    while i + 8 <= n and payload[i] == 0x01 and payload[i + 1] == 0x75:
        conv = payload[i + 2 : i + 6]
        plen = int.from_bytes(payload[i + 6 : i + 8], "little")
        end = i + 8 + plen
        if end > n:
            break
        out.append((conv, payload[i + 8 : end]))
        i = end
    return out


def extract_ticks_from_subframe(subframe: bytes) -> list[tuple[int, str, bytes | list[object]]]:
    """Parse `03 01 46 <len> <inner>` into `(tick_idx, mode, payload)` tuples.

    `mode` is `'lzw'` for tags `0x42..0x46` (bytes) or `'raw'` for tags `0x52..0x56` (struct list).
    """
    j = subframe.find(b"\x03\x01\x46")
    if j < 0:
        return []
    try:
        ln, k = read_varint(subframe, j + 3)
    except ValueError:
        return []
    if k + ln > len(subframe):
        return []
    inner = subframe[k : k + ln]
    if not inner or inner[0] != 0x70:
        return []

    pos = 1
    if pos >= len(inner):
        return []
    if inner[pos] == 0x00:
        try:
            seq, pos = read_varint(inner, pos + 1)
        except ValueError:
            return []
    else:
        seq = 0

    # Field 0x01 packs 7-bit tick offsets for extra fields (0x43..0x46 / 0x53..0x56):
    # e.g. 386 (0x82 0x03) -> [2, 3], 82434 (0x82 0x84 0x05) -> [2, 4, 5].
    deltas: list[int] = [0]
    if pos < len(inner) and inner[pos] == 0x01:
        try:
            v1, pos = read_varint(inner, pos + 1)
        except ValueError:
            return []
        x = v1
        while x > 0:
            deltas.append(x & 0x7F)
            x >>= 7

    ticks: list[tuple[int, str, bytes | list[object]]] = []
    while pos < len(inner) and inner[pos] != 0x80:
        tag = inner[pos]
        pos += 1
        if 0x42 <= tag <= 0x46:
            try:
                flen, pos = read_varint(inner, pos)
            except ValueError:
                break
            if pos + flen > len(inner):
                break
            slot_i = tag - 0x42
            offset = deltas[slot_i] if slot_i < len(deltas) else slot_i
            ticks.append((seq + offset, "lzw", inner[pos : pos + flen]))
            pos += flen
        elif 0x52 <= tag <= 0x56:
            try:
                cnt, pos = read_varint(inner, pos)
            except ValueError:
                break
            items: list[object] = []
            ok = True
            for _ in range(cnt):
                if pos >= len(inner):
                    ok = False
                    break
                et = inner[pos]
                pos += 1
                if et == 0x70:
                    try:
                        sub, pos = parse_mlbb_struct(inner, pos)
                        items.append(sub)
                    except ValueError:
                        ok = False
                        break
                elif (et >> 4) in (0, 1, 2, 3):
                    try:
                        val, pos = read_varint(inner, pos)
                        items.append(val)
                    except ValueError:
                        ok = False
                        break
                elif (et >> 4) == 4:
                    try:
                        blen, pos = read_varint(inner, pos)
                        if pos + blen > len(inner):
                            ok = False
                            break
                        items.append(inner[pos : pos + blen])
                        pos += blen
                    except ValueError:
                        ok = False
                        break
                else:
                    ok = False
                    break
            if not ok:
                break
            slot_i = tag - 0x52
            offset = deltas[slot_i] if slot_i < len(deltas) else slot_i
            ticks.append((seq + offset, "raw", items))
        else:
            break
    return ticks


class Lzw16Decoder:
    """Session-persistent 16-bit big-endian LZW decoder (clear 0x0100, cap 0x4000)."""

    def __init__(self) -> None:
        self.table: dict[int, bytes] = {i: bytes([i]) for i in range(256)}
        self.next_code = LZW_FIRST_CODE
        self.reset_count = 0

    def reset(self) -> None:
        """Reset dictionary to initial 256-byte entries."""
        self.table = {i: bytes([i]) for i in range(256)}
        self.next_code = LZW_FIRST_CODE
        self.reset_count += 1

    def decode_words(self, words: list[int]) -> bytes:
        """Decode big-endian 16-bit LZW words within a single tick (`prev = None` at start)."""
        out = bytearray()
        prev: bytes | None = None
        table = self.table
        for w in words:
            if w == LZW_CLEAR_CODE:
                table = {i: bytes([i]) for i in range(256)}
                self.table = table
                self.next_code = LZW_FIRST_CODE
                prev = None
                continue
            if w in table:
                entry = table[w]
            elif w == self.next_code and prev is not None:
                entry = prev + prev[:1]
            else:
                raise KeyError(f"bad LZW code {w:#x} (next_code={self.next_code:#x})")
            out.extend(entry)
            if prev is not None and self.next_code < LZW_MAX_TABLE:
                table[self.next_code] = prev + entry[:1]
                self.next_code += 1
            prev = entry
        return bytes(out)

    def decode_tick(self, raw: bytes) -> bytes:
        """Decode one tick's compressed byte buffer."""
        if len(raw) % 2 != 0:
            raise ValueError(f"odd LZW byte count: {len(raw)}")
        words = [int.from_bytes(raw[k : k + 2], "big") for k in range(0, len(raw), 2)]
        return self.decode_words(words)


@dataclass(slots=True)
class TickEventOutput:
    """Decoded tick output or gap transition emitted by `BattleTickProcessor`."""

    kind: str  # "events" | "gap_open" | "gap_resolved" | "desync"
    tick: int
    ts: float
    events: list[dict[str, object]] = field(default_factory=list)
    gap_from: int | None = None
    gap_to: int | None = None
    sync_tick: int | None = None
    message: str = ""
    reason: str = "mid_match"


class BattleTickProcessor:
    """Per-match pre-decompression deduplicator, reorder buffer, and LZW/raw decoder."""

    def __init__(self) -> None:
        self.lzw = Lzw16Decoder()
        self.pending: dict[int, tuple[float, str, bytes | list[object]]] = {}
        self.next_tick: int | None = None
        self.max_tick_seen: int = -1
        self.mode: str | None = None  # "lzw" or "raw"
        self.fsm_state = "IDLE"  # IDLE, SYNCED, WAIT_CLEAR, VERIFYING_SYNC, SYNCED_MIDMATCH, DESYNC
        self.decoded_ticks = 0
        self.lzw_errors = 0
        self.session_reset_count = 0
        self.blind_from: int | None = None
        self._gap_reason: str = "mid_match"
        self._candidate_sync_tick: int | None = None
        self._candidate_suffix_events: list[dict[str, object]] = []
        self._seen_raw_ticks: set[int] = set()

    def reset_for_reconnect(self) -> None:
        """Reset reorder & LZW state when a full client reconnect restarts ticks from 0."""
        self.lzw = Lzw16Decoder()
        self.pending.clear()
        self._seen_raw_ticks.clear()
        self.next_tick = None
        self.blind_from = None
        self._gap_reason = "mid_match"
        self._candidate_sync_tick = None
        self._candidate_suffix_events.clear()
        self.fsm_state = "IDLE"
        self.session_reset_count += 1

    def on_tick(
        self,
        ts: float,
        tick_idx: int,
        tick_mode: str,
        payload: bytes | list[object],
    ) -> list[TickEventOutput]:
        """Accept a parsed tick from either Wi-Fi or cellular and drain contiguous work."""
        if self.mode is None:
            self.mode = tick_mode
        if tick_idx > self.max_tick_seen:
            self.max_tick_seen = tick_idx

        # Uncompressed 0x52..0x56 ticks have no cross-tick LZW dictionary state.
        if tick_mode == "raw":
            if tick_idx in self._seen_raw_ticks or tick_idx in self.pending:
                return []
            if self.next_tick is None:
                self.fsm_state = "SYNCED"
            self.pending[tick_idx] = (ts, tick_mode, payload)
            return self._drain_raw()

        outputs: list[TickEventOutput] = []
        if self.next_tick is None:
            self.next_tick = tick_idx
            if tick_idx == 0:
                self.fsm_state = "SYNCED"
            else:
                self.fsm_state = "WAIT_CLEAR"
                self.blind_from = tick_idx
                self._gap_reason = "mid_match"
                outputs.append(
                    TickEventOutput(
                        kind="gap_open",
                        tick=tick_idx,
                        ts=ts,
                        gap_from=tick_idx,
                        message=f"Cannot decode battle chat before next LZW reset (from tick {tick_idx})",
                        reason="mid_match",
                    )
                )

        if tick_idx < self.next_tick or tick_idx in self.pending:
            return outputs

        self.pending[tick_idx] = (ts, tick_mode, payload)

        # Detect permanent gap (> 75 ticks ahead of next_tick across all links).
        if self.pending and self.fsm_state in ("SYNCED", "SYNCED_MIDMATCH"):
            highest = max(self.pending)
            if highest - self.next_tick > STALL_GAP_THRESHOLD:
                gap_start = self.next_tick
                future_ticks = sorted(t for t in self.pending if t >= gap_start)
                if future_ticks:
                    self.next_tick = future_ticks[0]
                self.fsm_state = "WAIT_CLEAR"
                self.blind_from = gap_start
                self._gap_reason = "packet_loss"
                self._candidate_sync_tick = None
                self._candidate_suffix_events.clear()
                outputs.append(
                    TickEventOutput(
                        kind="gap_open",
                        tick=gap_start,
                        ts=ts,
                        gap_from=gap_start,
                        message=f"Missed battle packets before next LZW reset (from tick {gap_start})",
                        reason="packet_loss",
                    )
                )
        elif (
            self.pending
            and self.fsm_state == "WAIT_CLEAR"
            and self.next_tick not in self.pending
            and max(self.pending) - self.next_tick > 10
        ):
            # Do not stall waiting for missing pre-sync ticks; skip forward to search 0x0100.
            future_ticks = sorted(t for t in self.pending if t >= self.next_tick)
            if future_ticks:
                self.next_tick = future_ticks[0]

        outputs.extend(self._drain_lzw())
        return outputs

    def _drain_raw(self) -> list[TickEventOutput]:
        outputs: list[TickEventOutput] = []
        for t in sorted(self.pending):
            ts, _, items = self.pending.pop(t)
            self._seen_raw_ticks.add(t)
            self.next_tick = max(self.next_tick or 0, t + 1)
            self.decoded_ticks += 1
            if isinstance(items, list):
                evs = extract_events_from_struct_list(items)
                if evs:
                    outputs.append(TickEventOutput(kind="events", tick=t, ts=ts, events=evs))
        return outputs

    def _drain_lzw(self) -> list[TickEventOutput]:
        outputs: list[TickEventOutput] = []
        while self.next_tick is not None and self.next_tick in self.pending:
            t = self.next_tick
            ts, tick_mode, payload = self.pending.pop(t)
            self.next_tick = t + 1

            if tick_mode != "lzw" or not isinstance(payload, bytes):
                continue

            if self.fsm_state == "WAIT_CLEAR":
                res = self._handle_wait_clear_tick(t, ts, payload)
                if res is not None:
                    outputs.append(res)
                continue

            if self.fsm_state == "VERIFYING_SYNC":
                res = self._handle_verifying_tick(t, ts, payload)
                outputs.extend(res)
                continue

            # Normal synced decode
            try:
                dec = self.lzw.decode_tick(payload)
            except (KeyError, ValueError) as exc:
                self.lzw_errors += 1
                self.fsm_state = "WAIT_CLEAR"
                self.blind_from = t
                self._gap_reason = "desync"
                self._candidate_sync_tick = None
                self._candidate_suffix_events.clear()
                outputs.append(
                    TickEventOutput(
                        kind="desync",
                        tick=t,
                        ts=ts,
                        gap_from=t,
                        message=f"LZW desync at tick {t} ({exc}); waiting for next LZW reset",
                        reason="desync",
                    )
                )
                continue

            self.decoded_ticks += 1
            evs = extract_events_from_tick_bytes(dec, partial_suffix=False)
            if evs:
                outputs.append(TickEventOutput(kind="events", tick=t, ts=ts, events=evs))

        return outputs

    def _handle_wait_clear_tick(self, t: int, ts: float, payload: bytes) -> TickEventOutput | None:
        if len(payload) % 2 != 0:
            return None
        words = [int.from_bytes(payload[k : k + 2], "big") for k in range(0, len(payload), 2)]
        if LZW_CLEAR_CODE not in words:
            return None

        idx0 = words.index(LZW_CLEAR_CODE)
        suffix_words = words[idx0 + 1 :]
        self.lzw.reset()
        self.session_reset_count += 1
        try:
            dec = self.lzw.decode_words(suffix_words)
        except (KeyError, ValueError):
            return None

        self._candidate_sync_tick = t
        self._candidate_suffix_events = extract_events_from_tick_bytes(dec, partial_suffix=True)
        self.fsm_state = "VERIFYING_SYNC"
        return None

    def _handle_verifying_tick(self, t: int, ts: float, payload: bytes) -> list[TickEventOutput]:
        outputs: list[TickEventOutput] = []
        try:
            dec = self.lzw.decode_tick(payload)
            if not dec or dec[0] != 0x70:
                raise ValueError("post-sync tick does not start with 0x70")
        except (KeyError, ValueError):
            # False clear code; return to WAIT_CLEAR and discard candidate suffix.
            self.fsm_state = "WAIT_CLEAR"
            self._candidate_sync_tick = None
            self._candidate_suffix_events.clear()
            return outputs

        sync_tick = self._candidate_sync_tick if self._candidate_sync_tick is not None else t
        gap_from = self.blind_from if self.blind_from is not None else sync_tick
        gap_to = max(gap_from, sync_tick - 1)
        self.fsm_state = "SYNCED_MIDMATCH"
        # Count both T_sync and T_sync + 1 as cleanly decoded ticks.
        self.decoded_ticks += 2

        outputs.append(
            TickEventOutput(
                kind="gap_resolved",
                tick=t,
                ts=ts,
                gap_from=gap_from,
                gap_to=gap_to,
                sync_tick=sync_tick,
                message=f"Cannot decode battle chat before next LZW reset (ticks {gap_from}..{gap_to}; resynced at tick {sync_tick})",
                reason=self._gap_reason,
            )
        )
        if self._candidate_suffix_events:
            outputs.append(
                TickEventOutput(
                    kind="events",
                    tick=sync_tick,
                    ts=ts,
                    events=list(self._candidate_suffix_events),
                )
            )
        self._candidate_sync_tick = None
        self._candidate_suffix_events.clear()

        evs = extract_events_from_tick_bytes(dec, partial_suffix=False)
        if evs:
            outputs.append(TickEventOutput(kind="events", tick=t, ts=ts, events=evs))
        return outputs
