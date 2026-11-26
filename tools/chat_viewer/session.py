"""Composite multi-match session router, passive side attribution, and thread-safe MatchStore."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .battle import BattleTickProcessor, extract_ticks_from_subframe, parse_0175_subframes
from .kcp import KcpStreamReassembler, ReassembledKcpMessage
from .pcap_reader import UdpPacket
from .protocol import (
    extract_events_from_struct_list,
    global_pos_to_camp_seat,
    parse_chat_body,
    parse_mlbb_struct,
    read_varint,
)
from .templates import TemplateResolver

logger = logging.getLogger(__name__)

MATCH_PORT_LO = 5000
MATCH_PORT_HI = 5999
MDNS_PORT = 5353
IDLE_NEW_MATCH_SECONDS = 15.0

_PLAY_RE = re.compile(rb"Play_(\d+)_1")
_MLBB_PREFIXES = frozenset(
    {
        b"\x01\x51",
        b"\x41\x51",
        b"\x01\x52",
        b"\x41\x52",
        b"\x01\x71",
        b"\x01\x72",
        b"\x01\x73",
        b"\x01\x75",
        b"\x01\x76",
    }
)

_CHANNEL_LABELS = {
    1: "draft",
    2: "team",
    3: "all",
    4: "draft",
    10: "loading",
    22: "loading",
}


def channel_label(channel: int) -> str:
    """Return human-readable channel label for an MLBB chat channel id."""
    return _CHANNEL_LABELS.get(channel, f"ch{channel}")


@dataclass(slots=True)
class PlayerInfo:
    """Known player metadata from roster (`mid=1202`/`1203`), `ev=0x34`/`0x36`/`0x45`, or `msg_uid`."""

    uid: int
    name: str = ""
    camp: int | None = None
    seat: int | None = None
    hero_id: int | None = None
    hero_name: str = ""

    @property
    def slot(self) -> int | None:
        if self.camp is None:
            return None
        return (self.camp << 4) | (self.seat if self.seat is not None else 0)


@dataclass(slots=True)
class ChatEvent:
    """Normalized chat message emitted across draft, loading, and battle phases."""

    seq_id: int
    match_id: str
    ts: float
    phase: str  # "draft" | "loading" | "battle"
    tick: int | None
    channel: int
    channel_name: str
    slot: int | None
    camp: int | None
    sender_uid: int | None
    sender_name: str
    side: str  # "SELF" | "ALLY" | "ENEMY" | "CAMP 1" | "CAMP 2" | "UNKNOWN"
    raw_text: str
    display_text: str
    is_template: bool
    msg_uid: str = ""
    sender_hero_id: int | None = None
    sender_hero: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq_id": self.seq_id,
            "match_id": self.match_id,
            "ts": self.ts,
            "phase": self.phase,
            "tick": self.tick,
            "channel": self.channel,
            "channel_name": self.channel_name,
            "slot": self.slot,
            "camp": self.camp,
            "sender_uid": self.sender_uid,
            "sender_name": self.sender_name,
            "side": self.side,
            "raw_text": self.raw_text,
            "display_text": self.display_text,
            "is_template": self.is_template,
            "msg_uid": self.msg_uid,
            "sender_hero_id": self.sender_hero_id,
            "sender_hero": self.sender_hero,
        }


@dataclass(slots=True)
class GapBanner:
    """Inline warning banner for undecoded mid-match or dropped LZW ticks."""

    gap_id: str
    match_id: str
    ts: float
    from_tick: int
    to_tick: int | None
    sync_tick: int | None
    resolved: bool
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "match_id": self.match_id,
            "ts": self.ts,
            "from_tick": self.from_tick,
            "to_tick": self.to_tick,
            "sync_tick": self.sync_tick,
            "resolved": self.resolved,
            "message": self.message,
        }


@dataclass
class MatchSession:
    """All decoded state and attribution maps for one logical MLBB match."""

    match_id: str
    ep: tuple[str, int]
    first_ts: float
    last_ts: float
    battle_id: str | None = None
    phase: str = "IDLE"  # "IDLE" | "DRAFT" | "LOADING" | "BATTLE"
    battle: BattleTickProcessor = field(default_factory=BattleTickProcessor)
    convs: set[str] = field(default_factory=set)
    battle_convs: set[str] = field(default_factory=set)
    rebind_count: int = 0
    local_uid: int | None = None
    local_camp: int | None = None
    players_by_uid: dict[int, PlayerInfo] = field(default_factory=dict)
    slot_to_uid: dict[int, int] = field(default_factory=dict)
    slot_to_camp: dict[int, int] = field(default_factory=dict)
    events: list[ChatEvent] = field(default_factory=list)
    gaps: list[GapBanner] = field(default_factory=list)
    kcp_seen_digests: set[bytes] = field(default_factory=set)
    chat_dedup_keys: set[tuple[Any, ...]] = field(default_factory=set)
    pending_outbound_chats: list[tuple[float, int, str]] = field(default_factory=list)
    reconnect_expected: bool = False
    attribution_frozen: bool = False
    frozen_at_tick: int | None = None
    swapped_uids: set[int] = field(default_factory=set)
    swap_history: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    _next_seq_id: int = 1
    _next_gap_seq: int = 1

    @property
    def server_ip(self) -> str:
        return self.ep[0]

    @property
    def server_port(self) -> int:
        return self.ep[1]

    def summary_dict(self) -> dict[str, Any]:
        return {
            "match_id": self.match_id,
            "server_ip": self.ep[0],
            "server_port": self.ep[1],
            "battle_id": self.battle_id,
            "phase": self.phase,
            "fsm_state": self.battle.fsm_state,
            "battle_mode": self.battle.mode,
            "next_tick": self.battle.next_tick,
            "max_tick_seen": self.battle.max_tick_seen,
            "decoded_ticks": self.battle.decoded_ticks,
            "dict_next_code": f"0x{self.battle.lzw.next_code:04x}",
            "lzw_errors": self.battle.lzw_errors,
            "lzw_reset_count": self.battle.lzw.reset_count,
            "session_reset_count": self.battle.session_reset_count,
            "rebind_count": self.rebind_count,
            "convs": sorted(self.convs),
            "local_uid": self.local_uid,
            "local_camp": self.local_camp,
            "attribution_frozen": self.attribution_frozen,
            "frozen_at_tick": self.frozen_at_tick,
            "players": [
                {
                    "uid": p.uid,
                    "name": p.name,
                    "camp": p.camp,
                    "seat": p.seat,
                    "slot": p.slot,
                    "hero_id": p.hero_id,
                    "hero_name": p.hero_name,
                }
                for p in sorted(self.players_by_uid.values(), key=lambda x: (x.camp or 9, x.seat or 9, x.uid))
            ],
            "event_count": len(self.events),
            "gaps": [g.to_dict() for g in self.gaps],
            "swap_history": list(self.swap_history),
            "anomalies": list(self.anomalies),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
        }


class MatchStore:
    """Thread-safe RAM store + bounded per-subscriber SSE fan-out."""

    def __init__(self, max_replay_log: int = 10000) -> None:
        self._lock = threading.RLock()
        self._matches: dict[str, MatchSession] = {}
        self._match_order: list[str] = []
        self._active_match_id: str | None = None
        self._next_event_id = 1
        self._replay_log: list[tuple[int, str, dict[str, Any]]] = []
        self._max_replay_log = max_replay_log
        self._subscribers: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue[tuple[int, str, dict[str, Any]]]]] = []

        self._source_mode = "IDLE"
        self._source_detail = ""
        self._capture_alive = False
        self._last_pkt_mono: float | None = None
        self._last_error: str | None = None
        self._packets_processed = 0
        self._skipped_truncated = 0

    def reset_for_new_source(self, source_mode: str, source_detail: str) -> None:
        with self._lock:
            self._matches.clear()
            self._match_order.clear()
            self._active_match_id = None
            self._source_mode = source_mode
            self._source_detail = source_detail
            self._capture_alive = source_mode in ("LIVE (adb)", "FOLLOW (file)", "REPLAY (file)")
            self._last_pkt_mono = None
            self._last_error = None
            self._packets_processed = 0
            self._skipped_truncated = 0
            status = self.get_status()
        self.publish("source_reset", {"status": status})

    def set_capture_state(
        self,
        *,
        alive: bool,
        source_mode: str | None = None,
        source_detail: str | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            self._capture_alive = alive
            if source_mode is not None:
                self._source_mode = source_mode
            if source_detail is not None:
                self._source_detail = source_detail
            if error is not None:
                self._last_error = error
            status = self.get_status()
        self.publish("status", status)

    def note_packet_seen(self, *, skipped_truncated: int = 0) -> None:
        with self._lock:
            self._last_pkt_mono = time.monotonic()
            self._packets_processed += 1
            self._skipped_truncated = skipped_truncated

    def register_match(self, sess: MatchSession) -> None:
        with self._lock:
            self._matches[sess.match_id] = sess
            if sess.match_id not in self._match_order:
                self._match_order.append(sess.match_id)
            self._active_match_id = sess.match_id

    def set_active_match(self, match_id: str) -> None:
        with self._lock:
            if match_id in self._matches:
                self._active_match_id = match_id

    def allocate_event_id(self) -> int:
        """Allocate a strictly monotonic SSE event id without broadcasting."""
        with self._lock:
            eid = self._next_event_id
            self._next_event_id += 1
            return eid

    def publish(self, event_name: str, data: dict[str, Any]) -> int:
        with self._lock:
            eid = self._next_event_id
            self._next_event_id += 1
            if event_name != "status":
                self._replay_log.append((eid, event_name, data))
                if len(self._replay_log) > self._max_replay_log:
                    del self._replay_log[: len(self._replay_log) - self._max_replay_log]
            subs = list(self._subscribers)

        dead: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue[tuple[int, str, dict[str, Any]]]]] = []
        for loop, q in subs:
            if loop.is_closed():
                dead.append((loop, q))
                continue
            try:
                loop.call_soon_threadsafe(self._enqueue_nonblocking, q, (eid, event_name, data))
            except RuntimeError:
                dead.append((loop, q))

        if dead:
            with self._lock:
                for item in dead:
                    if item in self._subscribers:
                        self._subscribers.remove(item)
        return eid

    @staticmethod
    def _enqueue_nonblocking(
        q: asyncio.Queue[tuple[int, str, dict[str, Any]]],
        item: tuple[int, str, dict[str, Any]],
    ) -> None:
        if q.full():
            try:
                q.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            q.put_nowait(item)
        except asyncio.QueueFull:
            pass

    def subscribe(
        self,
        loop: asyncio.AbstractEventLoop,
        last_event_id: int | None = None,
    ) -> tuple[asyncio.Queue[tuple[int, str, dict[str, Any]]], list[tuple[int, str, dict[str, Any]]]]:
        q: asyncio.Queue[tuple[int, str, dict[str, Any]]] = asyncio.Queue(maxsize=512)
        with self._lock:
            if last_event_id is not None:
                missed = [item for item in self._replay_log if item[0] > last_event_id]
            else:
                missed = []
            self._subscribers.append((loop, q))
        return q, missed

    def unsubscribe(
        self,
        loop: asyncio.AbstractEventLoop,
        q: asyncio.Queue[tuple[int, str, dict[str, Any]]],
    ) -> None:
        with self._lock:
            pair = (loop, q)
            if pair in self._subscribers:
                self._subscribers.remove(pair)

    def get_matches_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            out: list[dict[str, Any]] = []
            for mid in self._match_order:
                sess = self._matches[mid]
                d = sess.summary_dict()
                d["events"] = [ev.to_dict() for ev in sess.events]
                out.append(d)
            return out

    def get_matches(self) -> list[MatchSession]:
        with self._lock:
            return [self._matches[mid] for mid in self._match_order]

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            active = self._matches.get(self._active_match_id) if self._active_match_id else None
            age_s = round(time.monotonic() - self._last_pkt_mono, 2) if self._last_pkt_mono is not None else None
            gap_info = [g.to_dict() for g in active.gaps if not g.resolved] if active else []
            fsm_state = active.battle.fsm_state if active else "IDLE"
            if active and active.phase in ("DRAFT", "LOADING") and fsm_state == "IDLE":
                fsm_state = active.phase
            return {
                "source_mode": self._source_mode,
                "source_detail": self._source_detail,
                "capture_alive": self._capture_alive,
                "last_pkt_age_s": age_s,
                "last_error": self._last_error,
                "packets_processed": self._packets_processed,
                "skipped_truncated": self._skipped_truncated,
                "active_match_id": active.match_id if active else None,
                "active_battle_id": active.battle_id if active else None,
                "active_server": f"{active.server_ip}:{active.server_port}" if active else None,
                "phase": active.phase if active else "IDLE",
                "fsm_state": fsm_state,
                "next_tick": active.battle.next_tick if active else None,
                "dict_next_code": f"0x{active.battle.lzw.next_code:04x}" if active else "0x0101",
                "gap_info": gap_info,
            }


def _classify_packet(pkt: UdpPacket) -> tuple[str, tuple[str, int]] | None:
    sport, dport = pkt.sport, pkt.dport
    if MATCH_PORT_LO <= sport <= MATCH_PORT_HI and sport != MDNS_PORT:
        direction = "in"
        ep = (pkt.src_ip, sport)
    elif MATCH_PORT_LO <= dport <= MATCH_PORT_HI and dport != MDNS_PORT:
        direction = "out"
        ep = (pkt.dst_ip, dport)
    else:
        return None

    payload = pkt.payload
    if len(payload) < 6 or payload[:2] not in _MLBB_PREFIXES:
        return None
    if payload[1] in (0x51, 0x52) and payload[0] == 0x01 and len(payload) < 24:
        return None
    if payload[:2] == b"\x01\x75" and len(payload) < 8:
        return None
    return direction, ep


class SessionRouter:
    """Routes UDP match streams into composite multi-match `MatchSession` objects."""

    def __init__(
        self,
        store: MatchStore | None = None,
        templates: TemplateResolver | None = None,
    ) -> None:
        self.store = store if store is not None else MatchStore()
        self.templates = templates if templates is not None else TemplateResolver()
        self.kcp = KcpStreamReassembler()
        self._active_by_ep: dict[tuple[str, int], MatchSession] = {}
        self._active_by_battle_id: dict[str, MatchSession] = {}
        self._match_seq = 0

    def reset(self) -> None:
        self.kcp = KcpStreamReassembler()
        self._active_by_ep.clear()
        self._active_by_battle_id.clear()
        self._match_seq = 0

    def _new_match(self, ep: tuple[str, int], ts: float, battle_id: str | None = None) -> MatchSession:
        self._match_seq += 1
        mid = f"m{self._match_seq}"
        sess = MatchSession(match_id=mid, ep=ep, first_ts=ts, last_ts=ts, battle_id=battle_id)
        self._active_by_ep[ep] = sess
        if battle_id:
            self._active_by_battle_id[battle_id] = sess
        self.store.register_match(sess)
        self.store.publish("match_new", sess.summary_dict())
        return sess

    def _get_or_create(self, ep: tuple[str, int], ts: float) -> MatchSession:
        sess = self._active_by_ep.get(ep)
        if sess is None:
            sess = self._new_match(ep, ts)
        return sess

    def on_packet(self, pkt: UdpPacket, *, skipped_truncated: int = 0) -> None:
        """Process one non-truncated UDP packet."""
        classified = _classify_packet(pkt)
        if classified is None:
            return
        direction, ep = classified
        self.store.note_packet_seen(skipped_truncated=skipped_truncated)

        payload = pkt.payload
        cmd2 = payload[:2]
        sess = self._get_or_create(ep, pkt.ts)
        self.store.set_active_match(sess.match_id)

        if cmd2 in (b"\x01\x71", b"\x01\x72"):
            conv_hex = payload[2:6].hex()
            if conv_hex not in sess.convs:
                sess.convs.add(conv_hex)
                if sess.phase == "BATTLE" or sess.battle.max_tick_seen >= 0:
                    sess.rebind_count += 1
            sess.last_ts = max(sess.last_ts, pkt.ts)
            return

        if cmd2 in (b"\x01\x73", b"\x01\x76"):
            sess.convs.add(payload[2:6].hex())
            sess.last_ts = max(sess.last_ts, pkt.ts)
            return

        if cmd2 in (b"\x01\x51", b"\x41\x51", b"\x01\x52", b"\x41\x52"):
            msgs = self.kcp.on_datagram(pkt.ts, ep, direction, payload)
            for msg in msgs:
                self._on_kcp_message(msg)
            return

        if cmd2 == b"\x01\x75":
            if direction == "out":
                self._on_outbound_0175(sess, pkt.ts, payload)
            else:
                self._on_inbound_0175(sess, pkt.ts, payload)

    def _bind_battle_id(self, sess: MatchSession, battle_id: str, ts: float, from_login: bool) -> MatchSession:
        if sess.battle_id == battle_id:
            if from_login and sess.phase == "BATTLE" and sess.battle.max_tick_seen > 100:
                sess.reconnect_expected = True
            return sess
        if sess.battle_id is None:
            sess.battle_id = battle_id
            self._active_by_battle_id[battle_id] = sess
            self.store.publish("match_update", sess.summary_dict())
            return sess
        existing = self._active_by_battle_id.get(battle_id)
        if existing is not None:
            self._active_by_ep[sess.ep] = existing
            if from_login and existing.phase == "BATTLE" and existing.battle.max_tick_seen > 100:
                existing.reconnect_expected = True
            return existing
        return self._new_match(sess.ep, ts, battle_id=battle_id)

    def _on_kcp_message(self, msg: ReassembledKcpMessage) -> None:
        if not msg.complete:
            return
        sess = self._get_or_create(msg.ep, msg.ts)
        conv_hex = msg.conv.hex()
        data = msg.payload
        if len(data) < 3 or data[0] != 0x70:
            sess.convs.add(conv_hex)
            sess.last_ts = max(sess.last_ts, msg.ts)
            return

        if msg.direction == "out":
            sess.convs.add(conv_hex)
            sess.last_ts = max(sess.last_ts, msg.ts)
            self._handle_outbound_kcp(sess, data)
            return

        mid = 0
        if data[1] == 0x00:
            try:
                mid, _ = read_varint(data, 2)
            except ValueError:
                mid = 0

        if mid == 0:
            m = _PLAY_RE.search(data)
            if m:
                battle_id = m.group(1).decode("ascii")
                sess = self._bind_battle_id(sess, battle_id, msg.ts, from_login=True)
            sess.convs.add(conv_hex)
            sess.last_ts = max(sess.last_ts, msg.ts)
            return

        sess.convs.add(conv_hex)
        sess.last_ts = max(sess.last_ts, msg.ts)

        digest = hashlib.sha256(data).digest()
        if digest in sess.kcp_seen_digests:
            return
        sess.kcp_seen_digests.add(digest)

        if mid == 1202:
            self._handle_roster_1202(sess, data)
            return

        if mid == 1203:
            self._handle_battle_roster_1203(sess, data)
            return

        if mid == 1101:
            self._handle_room_1101(sess, msg.ts, data)

    def _handle_outbound_kcp(self, sess: MatchSession, data: bytes) -> None:
        if data[:2] != b"\x70\x00":
            return
        try:
            mid, pos = read_varint(data, 2)
        except ValueError:
            return
        if mid != 1001:
            return
        idx = data.find(b"\x70\x00", pos)
        if idx < 0:
            return
        try:
            uid, _ = read_varint(data, idx + 2)
        except ValueError:
            return
        if uid > 0 and sess.local_uid != uid:
            sess.local_uid = uid
            self._refresh_local_attribution(sess)

    @staticmethod
    def _parse_roster_items(data: bytes) -> list[Any] | None:
        idx = data.find(b"\x70\x50")
        if idx < 0:
            return None
        try:
            root, _ = parse_mlbb_struct(data, idx + 1)
        except ValueError:
            return None
        players = root.get(("l", 0))
        return players if isinstance(players, list) else None

    @staticmethod
    def _apply_roster_player(sess: MatchSession, item: dict[Any, Any]) -> bool:
        uid = item.get(("v", 0))
        if not isinstance(uid, int):
            return False
        camp = item.get(("v", 1))
        seat = item.get(("v", 2), 0)
        name_raw = item.get(("b", 3))
        camp_val = camp if isinstance(camp, int) and camp in (1, 2) else None
        seat_val = seat if isinstance(seat, int) else 0
        name = name_raw.decode("utf-8", "replace") if isinstance(name_raw, bytes) else ""
        existing = sess.players_by_uid.get(uid)
        changed = False
        if sess.attribution_frozen or uid in sess.swapped_uids:
            if existing is None:
                sess.players_by_uid[uid] = PlayerInfo(uid=uid, name=name)
                changed = True
            elif name and not existing.name:
                existing.name = name
                changed = True
            return changed

        if existing is None:
            sess.players_by_uid[uid] = PlayerInfo(uid=uid, name=name, camp=camp_val, seat=seat_val)
            changed = True
        else:
            if name and not existing.name:
                existing.name = name
                changed = True
            if camp_val is not None and existing.camp is None:
                existing.camp = camp_val
                changed = True
            if existing.seat is None:
                existing.seat = seat_val
                changed = True
        if camp_val is not None:
            slot = (camp_val << 4) | seat_val
            if slot not in sess.slot_to_uid:
                sess.slot_to_uid[slot] = uid
                changed = True
            sess.slot_to_camp[slot] = camp_val
        return changed

    def _set_player_hero(self, sess: MatchSession, uid: int, hero_id: int) -> tuple[bool, bool]:
        if hero_id <= 0:
            return False, False
        hero_name = self.templates.heroes.get(str(hero_id), "")
        player = sess.players_by_uid.get(uid)
        if player is None:
            player = PlayerInfo(uid=uid, hero_id=hero_id, hero_name=hero_name)
            sess.players_by_uid[uid] = player
            player_changed = True
        else:
            player_changed = player.hero_id != hero_id or player.hero_name != hero_name
            player.hero_id = hero_id
            player.hero_name = hero_name

        events_changed = False
        for ev in sess.events:
            if ev.sender_uid == uid and (ev.sender_hero_id != hero_id or ev.sender_hero != hero_name):
                ev.sender_hero_id = hero_id
                ev.sender_hero = hero_name
                events_changed = True
        return player_changed, events_changed

    def _clear_player_hero(
        self,
        sess: MatchSession,
        uid: int,
        *,
        expected_hero_id: int | None = None,
    ) -> tuple[bool, bool]:
        player = sess.players_by_uid.get(uid)
        player_changed = False
        if player is not None and player.hero_id is not None:
            if expected_hero_id is None or player.hero_id == expected_hero_id:
                player.hero_id = None
                player.hero_name = ""
                player_changed = True

        events_changed = False
        for ev in sess.events:
            if ev.sender_uid == uid and ev.sender_hero_id is not None:
                if expected_hero_id is None or ev.sender_hero_id == expected_hero_id:
                    ev.sender_hero_id = None
                    ev.sender_hero = ""
                    events_changed = True
        return player_changed, events_changed

    def _publish_hero_update(self, sess: MatchSession, *, include_events: bool) -> None:
        payload = sess.summary_dict()
        if include_events:
            payload["events"] = [ev.to_dict() for ev in sess.events]
        self.store.publish("match_update", payload)

    def _handle_confirm_hero_0x34(self, sess: MatchSession, ev: dict[str, Any]) -> None:
        uid = ev.get("uid")
        hero_id = ev.get("hero_id")
        if isinstance(uid, int) and isinstance(hero_id, int) and hero_id > 0:
            p_chg, ev_chg = self._set_player_hero(sess, uid, hero_id)
            if p_chg or ev_chg:
                self._publish_hero_update(sess, include_events=ev_chg)

    def _handle_roster_1202(self, sess: MatchSession, data: bytes) -> None:
        players = self._parse_roster_items(data)
        if players is None:
            return
        # NOTE: mid=1202 player list is sorted by uid, not by seat; always read field ('v', 2).
        changed = False
        for item in players:
            if isinstance(item, dict) and self._apply_roster_player(sess, item):
                changed = True
        if changed:
            self._refresh_local_attribution(sess)

    def _handle_battle_roster_1203(self, sess: MatchSession, data: bytes) -> None:
        players = self._parse_roster_items(data)
        if players is None:
            return
        roster_changed = False
        hero_changed = False
        events_changed = False
        for item in players:
            if not isinstance(item, dict):
                continue
            uid = item.get(("v", 0))
            if not isinstance(uid, int):
                continue
            if self._apply_roster_player(sess, item):
                roster_changed = True
            hero_id = item.get(("v", 7))
            if isinstance(hero_id, int) and hero_id > 0:
                p_chg, ev_chg = self._set_player_hero(sess, uid, hero_id)
                hero_changed = hero_changed or p_chg
                events_changed = events_changed or ev_chg

        if roster_changed:
            self._refresh_local_attribution(sess)
        elif hero_changed or events_changed:
            self._publish_hero_update(sess, include_events=events_changed)

    @staticmethod
    def _set_player_slot(sess: MatchSession, uid: int, camp: int, seat: int) -> None:
        slot = (camp << 4) | seat
        for s_key in [k for k, v in sess.slot_to_uid.items() if v == uid and k != slot]:
            del sess.slot_to_uid[s_key]
        prev_uid = sess.slot_to_uid.get(slot)
        if prev_uid is not None and prev_uid != uid:
            prev_player = sess.players_by_uid.get(prev_uid)
            if prev_player is not None and prev_player.slot == slot:
                prev_player.seat = None
        player = sess.players_by_uid.get(uid)
        if player is None:
            sess.players_by_uid[uid] = PlayerInfo(uid=uid, camp=camp, seat=seat)
        else:
            player.camp = camp
            player.seat = seat
        sess.slot_to_uid[slot] = uid
        sess.slot_to_camp[slot] = camp

    def _resolve_uid_camp_seat(self, sess: MatchSession, uid: int) -> tuple[int, int] | None:
        player = sess.players_by_uid.get(uid)
        if player is not None and player.camp in (1, 2) and player.seat is not None:
            return player.camp, player.seat
        for s_key, s_uid in sess.slot_to_uid.items():
            if s_uid == uid:
                c = s_key >> 4
                if c in (1, 2):
                    return c, s_key & 0x0F
        return None

    def _handle_ready_select_0x36(self, sess: MatchSession, ev: dict[str, Any]) -> None:
        uid = ev.get("uid")
        camp = ev.get("camp")
        seat = ev.get("seat")
        slot = ev.get("slot")
        if isinstance(uid, int) and camp in (1, 2) and isinstance(seat, int) and 0 <= seat <= 4:
            norm_slot = (camp << 4) | seat
            sess.slot_to_camp[norm_slot] = camp
            if sess.attribution_frozen or uid in sess.swapped_uids:
                return
            existing = sess.players_by_uid.get(uid)
            changed = False
            if existing is None:
                sess.players_by_uid[uid] = PlayerInfo(uid=uid, camp=camp, seat=seat)
                changed = True
            else:
                if existing.camp is None:
                    existing.camp = camp
                    changed = True
                if existing.seat is None:
                    existing.seat = seat
                    changed = True
            if norm_slot not in sess.slot_to_uid:
                sess.slot_to_uid[norm_slot] = uid
                changed = True
            if changed:
                self._refresh_local_attribution(sess)
        elif isinstance(slot, int):
            camp_hint = slot >> 4
            if camp_hint in (1, 2):
                sess.slot_to_camp[slot] = camp_hint

    def _handle_help_select_0x45(
        self,
        sess: MatchSession,
        *,
        ts: float,
        phase: str,
        tick: int | None,
        ev: dict[str, Any],
    ) -> None:
        req_uid = ev.get("req_uid")
        ack_uid = ev.get("ack_uid")
        hero_id = ev.get("hero_id")
        req_pos = ev.get("req_pos")
        ack_pos = ev.get("ack_pos")
        if not isinstance(req_uid, int) or not isinstance(ack_uid, int):
            return

        if sess.attribution_frozen:
            msg = (
                f"Ignoring post-freeze ev=0x45 swap ({req_uid} <-> {ack_uid}) "
                f"after battle freeze at tick {sess.frozen_at_tick}"
            )
            logger.warning("%s (match=%s, phase=%s, tick=%s)", msg, sess.match_id, phase, tick)
            sess.anomalies.append(
                {
                    "kind": "post_freeze_swap",
                    "ts": ts,
                    "phase": phase,
                    "tick": tick,
                    "req_uid": req_uid,
                    "ack_uid": ack_uid,
                    "hero_id": hero_id,
                    "req_pos": req_pos,
                    "ack_pos": ack_pos,
                    "message": msg,
                }
            )
            self.store.publish("match_update", sess.summary_dict())
            return

        req_cs = global_pos_to_camp_seat(req_pos) if isinstance(req_pos, int) else None
        ack_cs = global_pos_to_camp_seat(ack_pos) if isinstance(ack_pos, int) else None
        if req_cs is not None and ack_cs is not None:
            req_old_camp, req_old_seat = req_cs
            ack_old_camp, ack_old_seat = ack_cs
        else:
            req_cur = self._resolve_uid_camp_seat(sess, req_uid)
            ack_cur = self._resolve_uid_camp_seat(sess, ack_uid)
            if req_cur is None or ack_cur is None:
                msg = f"Unresolved ev=0x45 swap ({req_uid} <-> {ack_uid}): missing seat positions"
                logger.warning("%s (match=%s)", msg, sess.match_id)
                sess.anomalies.append(
                    {
                        "kind": "unresolved_swap",
                        "ts": ts,
                        "phase": phase,
                        "tick": tick,
                        "req_uid": req_uid,
                        "ack_uid": ack_uid,
                        "hero_id": hero_id,
                        "req_pos": req_pos,
                        "ack_pos": ack_pos,
                        "message": msg,
                    }
                )
                return
            req_old_camp, req_old_seat = req_cur
            ack_old_camp, ack_old_seat = ack_cur

        req_old_slot = (req_old_camp << 4) | req_old_seat
        ack_old_slot = (ack_old_camp << 4) | ack_old_seat
        new_req_slot = ack_old_slot
        new_ack_slot = req_old_slot

        if sess.slot_to_uid.get(new_req_slot) == req_uid and sess.slot_to_uid.get(new_ack_slot) == ack_uid:
            if isinstance(hero_id, int) and hero_id > 0:
                p_chg_req, ev_chg_req = self._set_player_hero(sess, req_uid, hero_id)
                p_chg_ack, ev_chg_ack = self._clear_player_hero(sess, ack_uid, expected_hero_id=hero_id)
                if p_chg_req or p_chg_ack or ev_chg_req or ev_chg_ack:
                    self._publish_hero_update(sess, include_events=ev_chg_req or ev_chg_ack)
            return

        # Clear any stale slot pointers for both swapping players before assigning targets.
        for s_key in [k for k, v in sess.slot_to_uid.items() if v in (req_uid, ack_uid)]:
            del sess.slot_to_uid[s_key]

        req_player = sess.players_by_uid.get(req_uid)
        if req_player is None:
            sess.players_by_uid[req_uid] = PlayerInfo(uid=req_uid, camp=ack_old_camp, seat=ack_old_seat)
        else:
            req_player.camp = ack_old_camp
            req_player.seat = ack_old_seat

        ack_player = sess.players_by_uid.get(ack_uid)
        if ack_player is None:
            sess.players_by_uid[ack_uid] = PlayerInfo(uid=ack_uid, camp=req_old_camp, seat=req_old_seat)
        else:
            ack_player.camp = req_old_camp
            ack_player.seat = req_old_seat

        sess.slot_to_uid[new_req_slot] = req_uid
        sess.slot_to_camp[new_req_slot] = ack_old_camp
        sess.slot_to_uid[new_ack_slot] = ack_uid
        sess.slot_to_camp[new_ack_slot] = req_old_camp
        sess.swapped_uids.add(req_uid)
        sess.swapped_uids.add(ack_uid)
        sess.swap_history.append(
            {
                "ts": ts,
                "phase": phase,
                "req_uid": req_uid,
                "ack_uid": ack_uid,
                "hero_id": hero_id,
                "req_old_slot": req_old_slot,
                "req_new_slot": new_req_slot,
                "ack_old_slot": ack_old_slot,
                "ack_new_slot": new_ack_slot,
            }
        )
        ev_chg = False
        if isinstance(hero_id, int) and hero_id > 0:
            _, ev_chg_req = self._set_player_hero(sess, req_uid, hero_id)
            _, ev_chg_ack = self._clear_player_hero(sess, ack_uid, expected_hero_id=hero_id)
            ev_chg = ev_chg_req or ev_chg_ack
        self._publish_hero_update(sess, include_events=ev_chg)

    def _dispatch_subevents(
        self,
        sess: MatchSession,
        events: list[dict[str, Any]],
        *,
        ts: float,
        phase: str,
        tick: int | None,
    ) -> MatchSession:
        for ev in events:
            ev_type = ev.get("ev_type")
            if ev_type == 0x45:
                self._handle_help_select_0x45(sess, ts=ts, phase=phase, tick=tick, ev=ev)
                continue
            if ev_type == 0x36:
                self._handle_ready_select_0x36(sess, ev)
                continue
            if ev_type == 0x34:
                self._handle_confirm_hero_0x34(sess, ev)
                continue
            slot = ev.get("slot")
            if ev_type == 0x0B and isinstance(slot, int):
                camp = slot >> 4
                if camp in (1, 2):
                    sess.slot_to_camp[slot] = camp
                continue
            if ev_type == 0x06:
                sess = self._emit_chat_event(sess, ts=ts, phase=phase, tick=tick, ev=ev)
        return sess

    def _handle_room_1101(self, sess: MatchSession, ts: float, data: bytes) -> None:
        m = re.search(rb"\x03(.)\x46", data)
        if not m:
            return
        phase_byte = m.group(1)[0]
        try:
            ln, pos = read_varint(data, m.end())
        except ValueError:
            return
        if pos + ln > len(data):
            return
        inner = data[pos : pos + ln]
        if not inner or inner[0] != 0x70:
            return

        try:
            st, _ = parse_mlbb_struct(inner, 1, require_terminator=True)
        except ValueError:
            return
        items = st.get(("l", 1))
        if not isinstance(items, list):
            return

        if phase_byte == 0x02:
            if sess.phase == "BATTLE" and sess.battle.max_tick_seen >= 0:
                sess = self._new_match(sess.ep, ts)
            if sess.phase == "IDLE":
                sess.phase = "DRAFT"
            phase_name = "draft"
        elif phase_byte == 0x03:
            if sess.phase in ("IDLE", "DRAFT"):
                sess.phase = "LOADING"
            phase_name = "loading"
        else:
            phase_name = sess.phase.lower() if sess.phase != "IDLE" else "draft"

        self._dispatch_subevents(sess, extract_events_from_struct_list(items), ts=ts, phase=phase_name, tick=None)

    def _on_outbound_0175(self, sess: MatchSession, ts: float, payload: bytes) -> None:
        for conv, sub in parse_0175_subframes(payload):
            sess.convs.add(conv.hex())
            sess.last_ts = max(sess.last_ts, ts)
            if b"\x01\x06\x43" not in sub:
                continue
            idx = sub.find(b"\x01\x06\x43")
            while idx >= 0:
                try:
                    elen, k = read_varint(sub, idx + 3)
                except ValueError:
                    break
                body = sub[k : k + elen]
                chat = parse_chat_body(body)
                if chat is not None:
                    ch = int(chat["channel"])
                    raw_text = str(chat["raw_text"])
                    sess.pending_outbound_chats.append((ts, ch, raw_text))
                    if len(sess.pending_outbound_chats) > 64:
                        del sess.pending_outbound_chats[:-64]
                idx = sub.find(b"\x01\x06\x43", idx + 3)

    def _on_inbound_0175(self, sess: MatchSession, ts: float, payload: bytes) -> None:
        for conv, sub in parse_0175_subframes(payload):
            conv_hex = conv.hex()
            sess.convs.add(conv_hex)
            sess.battle_convs.add(conv_hex)
            ticks = extract_ticks_from_subframe(sub)
            if not ticks:
                sess.last_ts = max(sess.last_ts, ts)
                continue

            for tick_idx, mode, t_payload in ticks:
                if tick_idx == 0 and sess.battle.max_tick_seen > 100:
                    if sess.reconnect_expected:
                        sess.battle.reset_for_reconnect()
                        sess.reconnect_expected = False
                        self.store.publish("match_update", sess.summary_dict())
                    elif ts - sess.last_ts > IDLE_NEW_MATCH_SECONDS:
                        sess = self._new_match(sess.ep, ts)
                        sess.convs.add(conv_hex)
                        sess.battle_convs.add(conv_hex)

                if sess.phase != "BATTLE":
                    sess.phase = "BATTLE"
                    if not sess.attribution_frozen:
                        sess.attribution_frozen = True
                        sess.frozen_at_tick = tick_idx
                    self.store.publish("match_update", sess.summary_dict())
                elif not sess.attribution_frozen:
                    sess.attribution_frozen = True
                    sess.frozen_at_tick = tick_idx
                sess.last_ts = max(sess.last_ts, ts)

                for out in sess.battle.on_tick(ts, tick_idx, mode, t_payload):
                    if out.kind in ("gap_open", "desync"):
                        gap_id = f"{sess.match_id}-g{sess._next_gap_seq}"
                        sess._next_gap_seq += 1
                        gap = GapBanner(
                            gap_id=gap_id,
                            match_id=sess.match_id,
                            ts=out.ts,
                            from_tick=out.gap_from if out.gap_from is not None else out.tick,
                            to_tick=None,
                            sync_tick=None,
                            resolved=False,
                            message=out.message,
                        )
                        sess.gaps.append(gap)
                        self.store.publish("gap", gap.to_dict())
                    elif out.kind == "gap_resolved":
                        target_gap = next((g for g in reversed(sess.gaps) if not g.resolved), None)
                        if target_gap is None:
                            gap_id = f"{sess.match_id}-g{sess._next_gap_seq}"
                            sess._next_gap_seq += 1
                            target_gap = GapBanner(
                                gap_id=gap_id,
                                match_id=sess.match_id,
                                ts=out.ts,
                                from_tick=out.gap_from or out.tick,
                                to_tick=out.gap_to,
                                sync_tick=out.sync_tick,
                                resolved=True,
                                message=out.message,
                            )
                            sess.gaps.append(target_gap)
                        else:
                            target_gap.to_tick = out.gap_to
                            target_gap.sync_tick = out.sync_tick
                            target_gap.resolved = True
                            target_gap.message = out.message
                        self.store.publish("gap", target_gap.to_dict())
                    elif out.kind == "events":
                        sess = self._dispatch_subevents(
                            sess, out.events, ts=out.ts, phase="battle", tick=out.tick
                        )

    def _emit_chat_event(
        self,
        sess: MatchSession,
        *,
        ts: float,
        phase: str,
        tick: int | None,
        ev: dict[str, Any],
    ) -> MatchSession:
        battle_id = ev.get("battle_id")
        if isinstance(battle_id, str) and battle_id:
            sess = self._bind_battle_id(sess, battle_id, ts, from_login=False)

        slot = ev.get("slot")
        slot_val = slot if isinstance(slot, int) else None
        ch = int(ev.get("channel") or 0)
        raw_text = str(ev.get("raw_text") or "")
        msg_uid = str(ev.get("msg_uid") or "")
        ev_uid = ev.get("uid") if isinstance(ev.get("uid"), int) else None

        # Match-level deduplication (Wi-Fi/cellular + mid-match reconnect replay).
        if msg_uid:
            dedup_key: tuple[Any, ...] = ("uid", phase, msg_uid)
        elif tick is not None:
            dedup_key = ("tick", phase, tick, ch, slot_val, raw_text)
        else:
            dedup_key = ("ts", phase, round(ts, 1), ch, slot_val, raw_text)
        if dedup_key in sess.chat_dedup_keys:
            return sess
        sess.chat_dedup_keys.add(dedup_key)

        camp: int | None = None
        if slot_val is not None:
            c = slot_val >> 4
            if c in (1, 2):
                camp = c
                sess.slot_to_camp[slot_val] = c

        uid = ev_uid
        if uid is not None and slot_val is not None:
            prev_uid = sess.slot_to_uid.get(slot_val)
            if prev_uid is not None and prev_uid != uid:
                msg = (
                    f"Slot 0x{slot_val:02x} attribution mismatch: roster had uid={prev_uid}, "
                    f"msg_uid has uid={uid} (phase={phase}, tick={tick}, frozen={sess.attribution_frozen})"
                )
                logger.warning("%s (match=%s)", msg, sess.match_id)
                sess.anomalies.append(
                    {
                        "kind": "slot_uid_mismatch",
                        "ts": ts,
                        "phase": phase,
                        "tick": tick,
                        "slot": slot_val,
                        "expected_uid": prev_uid,
                        "actual_uid": uid,
                        "frozen": sess.attribution_frozen,
                        "message": msg,
                    }
                )
                if not sess.attribution_frozen:
                    override_camp = slot_val >> 4
                    if override_camp in (1, 2):
                        self._set_player_slot(sess, uid, override_camp, slot_val & 0x0F)
                    else:
                        sess.slot_to_uid[slot_val] = uid
                    sess.swapped_uids.add(prev_uid)
                    sess.swapped_uids.add(uid)
                    self.store.publish("match_update", sess.summary_dict())
            elif prev_uid is None:
                sess.slot_to_uid[slot_val] = uid
        elif uid is None and slot_val is not None:
            uid = sess.slot_to_uid.get(slot_val)

        # Outbound 0x44c fallback for mid-match starts before mid=1001/1202.
        if sess.local_camp is None and sess.pending_outbound_chats:
            matched_idx = None
            for idx_out, (o_ts, o_ch, o_txt) in enumerate(sess.pending_outbound_chats):
                if o_ch == ch and o_txt == raw_text and abs(ts - o_ts) <= 5.0:
                    matched_idx = idx_out
                    break
            if matched_idx is not None:
                sess.pending_outbound_chats.pop(matched_idx)
                if uid is not None and sess.local_uid is None:
                    sess.local_uid = uid
                if camp is not None:
                    sess.local_camp = camp
                    self._refresh_local_attribution(sess)

        sender_hero_id: int | None = None
        sender_hero = ""
        if uid is not None and uid in sess.players_by_uid:
            p = sess.players_by_uid[uid]
            sender_name = p.name or f"uid:{uid}"
            sender_hero_id = p.hero_id
            sender_hero = p.hero_name
            if camp is None:
                camp = p.camp
        elif uid is not None:
            sender_name = f"uid:{uid}"
        elif slot_val is not None:
            sender_name = f"slot 0x{slot_val:02x}"
        else:
            sender_name = "unknown"

        if camp is not None and sess.local_uid is not None and uid == sess.local_uid and sess.local_camp is None:
            sess.local_camp = camp
            self._refresh_local_attribution(sess)

        side = self._resolve_side(sess, uid=uid, camp=camp)
        display_text, is_template = self.templates.format_text(raw_text, channel=ch)

        seq_id = sess._next_seq_id
        sess._next_seq_id += 1
        chat_ev = ChatEvent(
            seq_id=seq_id,
            match_id=sess.match_id,
            ts=ts,
            phase=phase,
            tick=tick,
            channel=ch,
            channel_name=channel_label(ch),
            slot=slot_val,
            camp=camp,
            sender_uid=uid,
            sender_name=sender_name,
            side=side,
            raw_text=raw_text,
            display_text=display_text,
            is_template=is_template,
            msg_uid=msg_uid,
            sender_hero_id=sender_hero_id,
            sender_hero=sender_hero,
        )
        sess.events.append(chat_ev)
        self.store.publish("chat", chat_ev.to_dict())
        return sess

    @staticmethod
    def _resolve_side(sess: MatchSession, *, uid: int | None, camp: int | None) -> str:
        if sess.local_uid is not None and uid is not None and uid == sess.local_uid:
            return "SELF"
        if sess.local_camp is not None and camp is not None:
            return "ALLY" if camp == sess.local_camp else "ENEMY"
        if camp in (1, 2):
            return f"CAMP {camp}"
        return "UNKNOWN"

    def _refresh_local_attribution(self, sess: MatchSession) -> None:
        if sess.local_camp is None and sess.local_uid is not None:
            p = sess.players_by_uid.get(sess.local_uid)
            if p is not None and p.camp in (1, 2):
                sess.local_camp = p.camp

        updated = False
        for ev in sess.events:
            new_uid = ev.sender_uid
            if new_uid is None and ev.slot is not None:
                new_uid = sess.slot_to_uid.get(ev.slot)
                if new_uid is not None:
                    ev.sender_uid = new_uid
                    updated = True
            if new_uid is not None and new_uid in sess.players_by_uid:
                p = sess.players_by_uid[new_uid]
                if p.name and ev.sender_name != p.name:
                    ev.sender_name = p.name
                    updated = True
                if p.hero_id is not None and (ev.sender_hero_id != p.hero_id or ev.sender_hero != p.hero_name):
                    ev.sender_hero_id = p.hero_id
                    ev.sender_hero = p.hero_name
                    updated = True
                if ev.camp is None and p.camp in (1, 2):
                    ev.camp = p.camp
                    updated = True
            if ev.camp is not None and sess.local_uid is not None and new_uid == sess.local_uid and sess.local_camp is None:
                sess.local_camp = ev.camp
            new_side = self._resolve_side(sess, uid=ev.sender_uid, camp=ev.camp)
            if ev.side != new_side:
                ev.side = new_side
                updated = True

        if updated or sess.players_by_uid:
            payload = sess.summary_dict()
            payload["events"] = [ev.to_dict() for ev in sess.events]
            self.store.publish("match_update", payload)
