"""Persistent Past Games archive and cached PCAP indexer for MLBB chat viewer."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .pcap_reader import IncrementalPcapReader, InvalidPcapMagicError
from .session import MatchStore, SessionRouter
from .templates import TemplateResolver

DEFAULT_HISTORY_DIR = Path(__file__).resolve().parents[2] / "data" / "chat_history"
MIN_PCAP_BYTES = 100
CACHE_SCHEMA_VERSION = 6


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.tmp.{os.getpid()}.{threading.get_ident()}")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def _read_json_safe(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _best_preview(events: list[dict[str, Any]]) -> str:
    if not events:
        return ""

    def _fmt(ev: dict[str, Any]) -> str:
        sender = str(ev.get("sender_name") or "Player")
        text = str(ev.get("display_text") or ev.get("raw_text") or "")
        return f"{sender}: {text}" if text else sender

    for ev in events:
        if ev.get("side") == "ENEMY" and ev.get("channel") == 2 and not ev.get("is_template"):
            return _fmt(ev)
    for ev in events:
        if ev.get("side") == "ENEMY" and ev.get("channel") in (2, 4) and not ev.get("is_template"):
            return _fmt(ev)
    for ev in events:
        if ev.get("side") == "ENEMY" and ev.get("channel") in (2, 4):
            return _fmt(ev)
    for ev in events:
        if not ev.get("is_template"):
            return _fmt(ev)
    return _fmt(events[0])


def _summarize_game(record: dict[str, Any]) -> dict[str, Any]:
    events = record.get("events") or []
    gaps = record.get("gaps") or []
    players = record.get("players") or []
    local_uid = record.get("local_uid")
    local_camp = record.get("local_camp")
    ally_camp = local_camp if local_camp in (1, 2) else 1
    enemy_camp = 2 if ally_camp == 1 else 1

    ally_names: list[str] = []
    enemy_names: list[str] = []
    for p in players:
        name = str(p.get("name") or f"uid:{p.get('uid')}")
        camp = p.get("camp")
        if camp == ally_camp:
            if local_uid is not None and p.get("uid") == local_uid:
                ally_names.insert(0, name)
            else:
                ally_names.append(name)
        elif camp == enemy_camp:
            enemy_names.append(name)

    first_ts = float(record.get("first_ts") or 0.0)
    last_ts = float(record.get("last_ts") or first_ts)
    typed_count = sum(1 for ev in events if not ev.get("is_template"))
    quickchat_count = len(events) - typed_count
    enemy_team_count = sum(
        1 for ev in events if ev.get("side") == "ENEMY" and ev.get("channel") in (2, 4)
    )

    return {
        "game_id": record["game_id"],
        "origin": record["origin"],
        "source_name": record["source_name"],
        "battle_id": record.get("battle_id"),
        "server_ip": record.get("server_ip"),
        "server_port": record.get("server_port"),
        "phase": record.get("phase") or "IDLE",
        "fsm_state": record.get("fsm_state") or "IDLE",
        "started_at": first_ts,
        "ended_at": last_ts,
        "duration_s": max(0.0, round(last_ts - first_ts, 1)),
        "local_uid": local_uid,
        "local_camp": local_camp,
        "mode_label": record.get("mode_label") or "",
        "party_label": record.get("party_label") or "",
        "country_counts": record.get("country_counts") or {},
        "ally_players": ally_names,
        "enemy_players": enemy_names,
        "typed_count": typed_count,
        "quickchat_count": quickchat_count,
        "enemy_team_count": enemy_team_count,
        "total_events": len(events),
        "has_gaps": bool(gaps),
        "preview": _best_preview(events),
    }


def _same_match_record(a: dict[str, Any], b: dict[str, Any]) -> bool:
    bid_a = str(a.get("battle_id") or "").strip()
    bid_b = str(b.get("battle_id") or "").strip()
    if bid_a and bid_b:
        return bid_a == bid_b
    ip_a = a.get("server_ip")
    if ip_a and ip_a == b.get("server_ip") and a.get("server_port") == b.get("server_port"):
        ts_a = float(a.get("first_ts") or 0.0)
        ts_b = float(b.get("first_ts") or 0.0)
        return abs(ts_a - ts_b) <= 5.0
    return False


def _record_quality(rec: dict[str, Any]) -> tuple[int, int, int, int, float]:
    events_count = len(rec.get("events") or [])
    heroes_count = sum(
        1
        for p in (rec.get("players") or [])
        if isinstance(p, dict) and (p.get("hero_id") or p.get("hero_name"))
    )
    players_count = len(rec.get("players") or [])
    is_pcap = 1 if rec.get("origin") == "pcap" else 0
    last_ts = float(rec.get("last_ts") or rec.get("first_ts") or 0.0)
    return (events_count, heroes_count, players_count, is_pcap, last_ts)


def _is_real_player_name(name: Any) -> bool:
    if not isinstance(name, str):
        return False
    s = name.strip()
    return bool(s) and not s.startswith("uid:") and not s.startswith("slot 0x") and s != "unknown"


def _event_dedup_key(ev: dict[str, Any]) -> tuple[Any, ...]:
    phase = ev.get("phase") or ""
    msg_uid = str(ev.get("msg_uid") or "")
    if msg_uid:
        return ("uid", phase, msg_uid)
    tick = ev.get("tick")
    ch = int(ev.get("channel") or 0)
    slot = ev.get("slot")
    raw_text = str(ev.get("raw_text") or "")
    if tick is not None:
        return ("tick", phase, tick, ch, slot, raw_text)
    return ("ts", phase, round(float(ev.get("ts") or 0.0), 1), ch, slot, raw_text)


def _merge_match_cluster(
    cluster: list[dict[str, Any]],
    uid_names: dict[int, str] | None = None,
) -> dict[str, Any]:
    best = max(cluster, key=_record_quality)
    merged = dict(best)
    if len(cluster) == 1:
        players = [dict(p) for p in (best.get("players") or []) if isinstance(p, dict)]
        events = [dict(e) for e in (best.get("events") or []) if isinstance(e, dict)]
        merged["players"] = players
        merged["events"] = events
        merged["gaps"] = [dict(g) for g in (best.get("gaps") or []) if isinstance(g, dict)]
    else:
        ordered = sorted(cluster, key=_record_quality)
        merged["players"] = []
        merged["events"] = []
        merged["gaps"] = [dict(g) for g in (best.get("gaps") or []) if isinstance(g, dict)]

        first_candidates = [float(r.get("first_ts") or 0.0) for r in cluster if float(r.get("first_ts") or 0.0) > 0]
        last_candidates = [float(r.get("last_ts") or 0.0) for r in cluster if float(r.get("last_ts") or 0.0) > 0]
        if first_candidates:
            merged["first_ts"] = min(first_candidates)
        if last_candidates:
            merged["last_ts"] = max(last_candidates)

        for key in ("battle_id", "local_uid", "local_camp", "mode_label", "pvp_type", "map_id", "local_party_size", "party_label", "country_counts"):
            val = merged.get(key)
            if not val:
                for cand in reversed(ordered):
                    if cand.get(key):
                        merged[key] = cand[key]
                        break

        # Merge players by uid across all records in cluster; richer/pcap record breaks ties.
        by_uid: dict[int, dict[str, Any]] = {}
        for rec in ordered:
            for raw_p in rec.get("players") or []:
                if not isinstance(raw_p, dict):
                    continue
                uid = raw_p.get("uid")
                if not isinstance(uid, int) or uid <= 0:
                    continue
                cur = by_uid.get(uid)
                if cur is None:
                    by_uid[uid] = dict(raw_p)
                    continue
                if _is_real_player_name(raw_p.get("name")):
                    cur["name"] = raw_p["name"]
                for fld in ("hero_id", "hero_name", "country", "zone_id", "room_id", "party_size"):
                    if raw_p.get(fld):
                        cur[fld] = raw_p[fld]
                if raw_p.get("is_bot"):
                    cur["is_bot"] = True
                if raw_p.get("camp") in (1, 2) and (not cur.get("camp") or rec.get("origin") == "pcap"):
                    cur["camp"] = raw_p["camp"]
                if raw_p.get("seat") is not None and (cur.get("seat") is None or rec.get("origin") == "pcap"):
                    cur["seat"] = raw_p["seat"]
                if cur.get("camp") in (1, 2) and cur.get("seat") is not None:
                    cur["slot"] = (int(cur["camp"]) << 4) | int(cur["seat"])

        players = sorted(
            by_uid.values(),
            key=lambda p: (p.get("camp") if p.get("camp") in (1, 2) else 9, p.get("seat") if isinstance(p.get("seat"), int) else 9, int(p["uid"])),
        )
        merged["players"] = players

        # Merge & deduplicate events sorted chronologically.
        by_ev_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        for rec in ordered:
            for raw_e in rec.get("events") or []:
                if not isinstance(raw_e, dict):
                    continue
                k = _event_dedup_key(raw_e)
                ev_copy = dict(raw_e)
                prev = by_ev_key.get(k)
                if prev is None:
                    by_ev_key[k] = ev_copy
                else:
                    if prev.get("sender_uid") is None and ev_copy.get("sender_uid") is not None:
                        prev["sender_uid"] = ev_copy["sender_uid"]
                    if not _is_real_player_name(prev.get("sender_name")) and _is_real_player_name(ev_copy.get("sender_name")):
                        prev["sender_name"] = ev_copy["sender_name"]
                    if not prev.get("sender_hero") and ev_copy.get("sender_hero"):
                        prev["sender_hero"] = ev_copy["sender_hero"]
                        prev["sender_hero_id"] = ev_copy.get("sender_hero_id")
                    if prev.get("side") in (None, "UNKNOWN", "CAMP 1", "CAMP 2") and ev_copy.get("side") in ("SELF", "ALLY", "ENEMY"):
                        prev["side"] = ev_copy["side"]

        events = sorted(by_ev_key.values(), key=lambda e: (float(e.get("ts") or 0.0), int(e.get("seq_id") or 0)))
        merged["events"] = events
        merged["event_count"] = len(events)

        # Prefer 0-gap view only if a record in cluster has equal/more events with no gaps.
        best_ev_len = len(best.get("events") or [])
        no_gap_full = [r for r in cluster if not (r.get("gaps") or []) and len(r.get("events") or []) >= best_ev_len]
        if no_gap_full:
            merged["gaps"] = []

    # Backfill player names, hero badges, and sides across merged/single record events.
    players_by_uid: dict[int, dict[str, Any]] = {}
    slot_to_uid: dict[int, int] = {}
    for p in merged["players"]:
        uid = p.get("uid")
        if isinstance(uid, int) and uid > 0:
            if not _is_real_player_name(p.get("name")) and uid_names and uid in uid_names:
                p["name"] = uid_names[uid]
            players_by_uid[uid] = p
            slot = p.get("slot")
            if isinstance(slot, int):
                slot_to_uid[slot] = uid
            elif p.get("camp") in (1, 2) and isinstance(p.get("seat"), int):
                slot_to_uid[(int(p["camp"]) << 4) | int(p["seat"])] = uid
    for ev in merged["events"]:
        ev_uid = ev.get("sender_uid")
        ev_slot = ev.get("slot")
        if isinstance(ev_uid, int) and isinstance(ev_slot, int) and ev_slot not in slot_to_uid:
            slot_to_uid[ev_slot] = ev_uid

    local_uid = merged.get("local_uid")
    local_camp = merged.get("local_camp")
    for ev in merged["events"]:
        uid = ev.get("sender_uid")
        if uid is None and isinstance(ev.get("slot"), int):
            uid = slot_to_uid.get(ev["slot"])
            if uid is not None:
                ev["sender_uid"] = uid
        if isinstance(uid, int):
            p = players_by_uid.get(uid)
            if p is not None:
                if _is_real_player_name(p.get("name")):
                    ev["sender_name"] = p["name"]
                elif not _is_real_player_name(ev.get("sender_name")) and uid_names and uid in uid_names:
                    ev["sender_name"] = uid_names[uid]
                if p.get("hero_id") and not ev.get("sender_hero"):
                    ev["sender_hero_id"] = p["hero_id"]
                    ev["sender_hero"] = p.get("hero_name") or ""
                if ev.get("camp") is None and p.get("camp") in (1, 2):
                    ev["camp"] = p["camp"]
            elif not _is_real_player_name(ev.get("sender_name")):
                if uid_names and uid in uid_names:
                    ev["sender_name"] = uid_names[uid]
                else:
                    ev["sender_name"] = f"uid:{uid}"
        camp = ev.get("camp")
        if local_uid is not None and uid == local_uid:
            ev["side"] = "SELF"
        elif local_camp in (1, 2) and camp in (1, 2):
            ev["side"] = "ALLY" if camp == local_camp else "ENEMY"
    return merged


def _dedup_records(
    records: list[dict[str, Any]],
    *,
    uid_names: dict[int, str] | None = None,
) -> list[dict[str, Any]]:
    clusters: list[list[dict[str, Any]]] = []
    for rec in records:
        matched_idxs = [
            idx
            for idx, cluster in enumerate(clusters)
            if any(_same_match_record(existing, rec) for existing in cluster)
        ]
        if not matched_idxs:
            clusters.append([rec])
            continue
        merged = [rec]
        for idx in reversed(matched_idxs):
            merged.extend(clusters.pop(idx))
        clusters.append(merged)
    return [_merge_match_cluster(cluster, uid_names=uid_names) for cluster in clusters]


def _decode_pcap_to_records(path: Path, templates: TemplateResolver) -> list[dict[str, Any]]:
    store = MatchStore()
    router = SessionRouter(store=store, templates=templates)
    reader = IncrementalPcapReader()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(131072)
            if not chunk:
                break
            for pkt in reader.feed(chunk):
                router.on_packet(pkt, skipped_truncated=reader.skipped_truncated)

    records: list[dict[str, Any]] = []
    for m in store.get_matches_snapshot():
        rec = dict(m)
        rec["game_id"] = f"pcap:{path.name}:{m['match_id']}"
        rec["origin"] = "pcap"
        rec["source_name"] = path.name
        records.append(rec)
    return records


class MatchHistoryStore:
    """Thread-safe persistent archive of live games and cached PCAP captures."""

    def __init__(
        self,
        captures_dir: Path,
        history_dir: Path | None = None,
        templates: TemplateResolver | None = None,
        on_change: Callable[[], None] | None = None,
    ) -> None:
        self.captures_dir = Path(captures_dir)
        self.history_dir = Path(history_dir) if history_dir is not None else DEFAULT_HISTORY_DIR
        self.templates = templates if templates is not None else TemplateResolver()
        self.on_change = on_change

        self._live_path = self.history_dir / "live_games.json"
        self._cache_path = self.history_dir / "pcap_cache.json"
        self._lock = threading.RLock()
        self._io_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._scan_thread: threading.Thread | None = None

        self._live_games: dict[str, dict[str, Any]] = {}
        self._pcap_cache: dict[str, dict[str, Any]] = {}
        self._scan_state: dict[str, Any] = {
            "scanning": False,
            "done": 0,
            "total": 0,
            "current_file": "",
        }
        self._load_disk()

    def _templates_signature(self) -> list[int] | None:
        tpath = self.templates.path
        if not tpath or not tpath.is_file():
            return None
        try:
            st = tpath.stat()
            return [st.st_size, st.st_mtime_ns]
        except OSError:
            return None

    def _load_disk(self) -> None:
        live_raw = _read_json_safe(self._live_path)
        games_map = live_raw.get("games") if isinstance(live_raw.get("games"), dict) else live_raw
        if isinstance(games_map, dict):
            for gid, rec in games_map.items():
                if isinstance(gid, str) and gid.startswith("live:") and isinstance(rec, dict):
                    rec.setdefault("game_id", gid)
                    rec.setdefault("origin", "live")
                    rec.setdefault("source_name", "Live capture")
                    if self.templates.loaded:
                        hero_by_uid: dict[Any, tuple[int, str]] = {}
                        for p in rec.get("players") or []:
                            if not isinstance(p, dict):
                                continue
                            hid = p.get("hero_id")
                            if isinstance(hid, int) and hid > 0:
                                hname = self.templates.heroes.get(str(hid), "")
                                p["hero_name"] = hname
                                if p.get("uid") is not None:
                                    hero_by_uid[p["uid"]] = (hid, hname)
                        for ev in rec.get("events") or []:
                            if not isinstance(ev, dict):
                                continue
                            if ev.get("raw_text"):
                                disp, is_tmpl = self.templates.format_text(
                                    str(ev["raw_text"]), channel=ev.get("channel")
                                )
                                ev["display_text"] = disp
                                ev["is_template"] = is_tmpl
                            uid_key = ev.get("sender_uid")
                            ev_hid = ev.get("sender_hero_id")
                            if isinstance(ev_hid, int) and ev_hid > 0:
                                ev["sender_hero"] = self.templates.heroes.get(str(ev_hid), "")
                            elif uid_key in hero_by_uid:
                                hid, hname = hero_by_uid[uid_key]
                                ev["sender_hero_id"] = hid
                                ev["sender_hero"] = hname
                    self._live_games[gid] = rec

        cache_raw = _read_json_safe(self._cache_path)
        if cache_raw.get("version") != CACHE_SCHEMA_VERSION:
            return
        files_map = cache_raw.get("files") if isinstance(cache_raw.get("files"), dict) else {}
        if isinstance(files_map, dict):
            for fname, entry in files_map.items():
                if (
                    isinstance(fname, str)
                    and isinstance(entry, dict)
                    and isinstance(entry.get("games"), list)
                ):
                    self._pcap_cache[fname] = entry

    def _persist_live(self) -> None:
        with self._lock:
            snap = {"version": 1, "games": dict(self._live_games)}
        with self._io_lock:
            _atomic_write_json(self._live_path, snap)

    def _persist_pcap_cache(self) -> None:
        with self._lock:
            snap = {"version": CACHE_SCHEMA_VERSION, "files": dict(self._pcap_cache)}
        with self._io_lock:
            _atomic_write_json(self._cache_path, snap)

    def _notify_change(self) -> None:
        cb = self.on_change
        if cb is not None:
            try:
                cb()
            except Exception:
                pass

    def save_live_matches(self, matches: list[dict[str, Any]]) -> bool:
        """Persist any live/followed match containing chat events or gap warnings."""
        changed = False
        with self._lock:
            for m in matches:
                if not m.get("events") and not m.get("gaps"):
                    continue
                bid = m.get("battle_id")
                if bid:
                    gid = f"live:{bid}"
                else:
                    ts_key = int(float(m.get("first_ts") or time.time()))
                    gid = f"live:{ts_key}:{m.get('server_ip') or '0.0.0.0'}:{m.get('server_port') or 0}"
                rec = dict(m)
                rec["game_id"] = gid
                rec["origin"] = "live"
                rec["source_name"] = "Live capture"
                self._live_games[gid] = rec
                changed = True
        if changed:
            self._persist_live()
            self._notify_change()
        return changed

    def delete_live_game(self, game_id: str) -> bool:
        """Delete a saved live game by `live:...` id; refuse `pcap:...` items."""
        if not game_id.startswith("live:"):
            raise ValueError("Only saved live games can be deleted from history")
        with self._lock:
            removed = self._live_games.pop(game_id, None) is not None
        if removed:
            self._persist_live()
            self._notify_change()
        return removed

    def index_pcap_file(self, path: Path) -> bool:
        """Decode and cache a single PCAP inside `captures_dir`."""
        try:
            cap_root = self.captures_dir.resolve()
            target = Path(path).resolve()
            target.relative_to(cap_root)
        except (OSError, ValueError):
            return False
        if not target.is_file() or target.stat().st_size < MIN_PCAP_BYTES:
            return False
        st = target.stat()
        try:
            records = _decode_pcap_to_records(target, self.templates)
        except (OSError, InvalidPcapMagicError):
            return False
        with self._lock:
            self._pcap_cache[target.name] = {
                "size": st.st_size,
                "mtime_ns": st.st_mtime_ns,
                "templates_sig": self._templates_signature(),
                "games": records,
            }
        self._persist_pcap_cache()
        self._notify_change()
        return True

    def stop_scan(self, timeout: float = 2.0) -> None:
        """Stop background PCAP indexing cleanly on shutdown."""
        self._stop_event.set()
        t = self._scan_thread
        if t is not None and t.is_alive():
            t.join(timeout=timeout)

    def start_background_scan(self, force: bool = False) -> dict[str, Any]:
        """Start background PCAP indexing if not already running."""
        with self._lock:
            if self._scan_thread is not None and self._scan_thread.is_alive():
                return dict(self._scan_state)
            self._stop_event.clear()
            t = threading.Thread(
                target=self._scan_worker,
                args=(force,),
                name="chat-viewer-history-scan",
                daemon=True,
            )
            self._scan_thread = t
            self._scan_state = {"scanning": True, "done": 0, "total": 0, "current_file": ""}
            t.start()
            return dict(self._scan_state)

    def _scan_worker(self, force: bool) -> None:
        any_changed = False
        try:
            if not self.captures_dir.is_dir():
                with self._lock:
                    if self._pcap_cache:
                        self._pcap_cache.clear()
                        any_changed = True
                if any_changed:
                    self._persist_pcap_cache()
                return
            files = sorted(
                (p for p in self.captures_dir.glob("*.pcap") if p.is_file() and p.stat().st_size >= MIN_PCAP_BYTES),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            present = {p.name for p in files}
            pruned = False
            with self._lock:
                stale = [fname for fname in self._pcap_cache if fname not in present]
                for fname in stale:
                    del self._pcap_cache[fname]
                    pruned = True
                    any_changed = True
                self._scan_state = {
                    "scanning": True,
                    "done": 0,
                    "total": len(files),
                    "current_file": "",
                }
            if pruned:
                self._persist_pcap_cache()

            for idx, p in enumerate(files, 1):
                if self._stop_event.is_set():
                    break
                st = p.stat()
                sig = (st.st_size, st.st_mtime_ns)
                tmpl_sig = self._templates_signature()
                with self._lock:
                    cached = self._pcap_cache.get(p.name)
                    self._scan_state["current_file"] = p.name
                if (
                    not force
                    and cached is not None
                    and cached.get("size") == sig[0]
                    and cached.get("mtime_ns") == sig[1]
                    and cached.get("templates_sig") == tmpl_sig
                ):
                    with self._lock:
                        self._scan_state["done"] = idx
                    continue

                try:
                    records = _decode_pcap_to_records(p, self.templates)
                except (OSError, InvalidPcapMagicError):
                    records = []

                entry = {
                    "size": sig[0],
                    "mtime_ns": sig[1],
                    "templates_sig": tmpl_sig,
                    "games": records,
                }
                with self._lock:
                    self._pcap_cache[p.name] = entry
                    self._scan_state["done"] = idx
                any_changed = True
                self._persist_pcap_cache()
                self._notify_change()
        finally:
            with self._lock:
                self._scan_state["scanning"] = False
                self._scan_state["current_file"] = ""
            if any_changed:
                self._notify_change()

    def _build_uid_name_map_locked(self) -> dict[int, str]:
        recs: list[dict[str, Any]] = []
        recs.extend(self._live_games.values())
        for entry in self._pcap_cache.values():
            recs.extend(entry.get("games") or [])
        recs.sort(key=lambda r: float(r.get("last_ts") or r.get("first_ts") or 0.0))
        uid_names: dict[int, str] = {}
        for rec in recs:
            for p in rec.get("players") or []:
                if not isinstance(p, dict):
                    continue
                uid = p.get("uid")
                name = p.get("name")
                if isinstance(uid, int) and uid > 0 and _is_real_player_name(name):
                    uid_names[uid] = str(name)
        return uid_names

    def lookup_player_name(self, uid: int) -> str | None:
        """Return the latest known real player name for `uid` from history, if any."""
        with self._lock:
            return self._build_uid_name_map_locked().get(uid)

    def lookup_match_roster(
        self,
        battle_id: str | None,
        ep: tuple[str, int],
        ts: float,
    ) -> dict[str, Any] | None:
        """Return merged roster & match metadata for a matching `battle_id` or recent draft endpoint."""
        with self._lock:
            all_records: list[dict[str, Any]] = []
            all_records.extend(self._live_games.values())
            for entry in self._pcap_cache.values():
                all_records.extend(entry.get("games") or [])

            seeds: list[dict[str, Any]] = []
            bid = str(battle_id or "").strip()
            for rec in all_records:
                rec_bid = str(rec.get("battle_id") or "").strip()
                if bid and rec_bid == bid:
                    seeds.append(rec)
                elif (
                    not rec_bid
                    and (rec.get("players") or [])
                    and rec.get("server_ip") == ep[0]
                    and rec.get("server_port") == ep[1]
                ):
                    r_first = float(rec.get("first_ts") or 0.0)
                    r_last = float(rec.get("last_ts") or r_first)
                    if -5.0 <= (ts - r_first) <= 2400.0 and (ts - r_last) <= 600.0:
                        seeds.append(rec)

            if not seeds:
                return None
            # Expand seeds to all same-match cluster peers (e.g. a battle_id record bridging a bid=None draft record).
            candidates: list[dict[str, Any]] = []
            for rec in all_records:
                if any(rec is s or _same_match_record(s, rec) for s in seeds):
                    candidates.append(rec)
            uid_names = self._build_uid_name_map_locked()
            merged = _merge_match_cluster(candidates, uid_names=uid_names)
            if not (merged.get("players") or []) and merged.get("local_camp") not in (1, 2):
                return None
            return {
                "players": merged.get("players") or [],
                "local_uid": merged.get("local_uid"),
                "local_camp": merged.get("local_camp"),
                "mode_label": merged.get("mode_label") or "",
                "pvp_type": merged.get("pvp_type"),
                "map_id": merged.get("map_id"),
            }

    def list_games(self, *, include_empty: bool = False) -> dict[str, Any]:
        """Return newest-first deduplicated and merged game summaries across live history and cached PCAPs."""
        all_records: list[dict[str, Any]] = []
        with self._lock:
            all_records.extend(self._live_games.values())
            for entry in self._pcap_cache.values():
                all_records.extend(entry.get("games") or [])
            scan = dict(self._scan_state)
            uid_names = self._build_uid_name_map_locked()

        deduped = _dedup_records(all_records, uid_names=uid_names)
        summaries = [_summarize_game(r) for r in deduped]
        summaries.sort(key=lambda g: (g["started_at"], g["game_id"]), reverse=True)
        total_all = len(summaries)
        with_chat = [g for g in summaries if g["total_events"] > 0]
        visible = summaries if include_empty else with_chat
        return {
            "games": visible,
            "total_with_chat": len(with_chat),
            "total_all": total_all,
            "scan": scan,
        }

    def get_game(self, game_id: str) -> dict[str, Any] | None:
        """Return full merged game record (summary + players + events + gaps) by id."""
        with self._lock:
            all_records: list[dict[str, Any]] = []
            all_records.extend(self._live_games.values())
            for entry in self._pcap_cache.values():
                all_records.extend(entry.get("games") or [])

            target_rec: dict[str, Any] | None = None
            if game_id in self._live_games:
                target_rec = self._live_games[game_id]
            else:
                for entry in self._pcap_cache.values():
                    for rec in entry.get("games") or []:
                        if rec.get("game_id") == game_id:
                            target_rec = rec
                            break
                    if target_rec is not None:
                        break

            if target_rec is not None:
                cluster = [r for r in all_records if r is target_rec or _same_match_record(target_rec, r)]
                uid_names = self._build_uid_name_map_locked()
                out = _merge_match_cluster(cluster, uid_names=uid_names)
                out["game_id"] = target_rec.get("game_id", game_id)
                out["origin"] = target_rec.get("origin", out.get("origin"))
                out["source_name"] = target_rec.get("source_name", out.get("source_name"))
                out["summary"] = _summarize_game(out)
                return out

        # Lazy single-file decode if requested before background scan finishes.
        if game_id.startswith("pcap:"):
            parts = game_id.split(":", 2)
            if len(parts) == 3:
                fname = parts[1]
                target = (self.captures_dir / fname).resolve()
                try:
                    target.relative_to(self.captures_dir.resolve())
                except ValueError:
                    return None
                if target.is_file() and target.stat().st_size >= MIN_PCAP_BYTES:
                    st = target.stat()
                    try:
                        records = _decode_pcap_to_records(target, self.templates)
                    except (OSError, InvalidPcapMagicError):
                        return None
                    with self._lock:
                        self._pcap_cache[target.name] = {
                            "size": st.st_size,
                            "mtime_ns": st.st_mtime_ns,
                            "templates_sig": self._templates_signature(),
                            "games": records,
                        }
                        all_records = list(self._live_games.values())
                        for entry in self._pcap_cache.values():
                            all_records.extend(entry.get("games") or [])
                        uid_names = self._build_uid_name_map_locked()
                    self._persist_pcap_cache()
                    for rec in records:
                        if rec.get("game_id") == game_id:
                            cluster = [r for r in all_records if r is rec or _same_match_record(rec, r)]
                            out = _merge_match_cluster(cluster, uid_names=uid_names)
                            out["game_id"] = rec.get("game_id", game_id)
                            out["origin"] = rec.get("origin", out.get("origin"))
                            out["source_name"] = rec.get("source_name", out.get("source_name"))
                            out["summary"] = _summarize_game(out)
                            return out
        return None
