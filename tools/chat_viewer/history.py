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
CACHE_SCHEMA_VERSION = 4


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


def _dedup_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
    return [max(cluster, key=_record_quality) for cluster in clusters]


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

    def list_games(self, *, include_empty: bool = False) -> dict[str, Any]:
        """Return newest-first deduplicated game summaries across live history and cached PCAPs."""
        all_records: list[dict[str, Any]] = []
        with self._lock:
            all_records.extend(self._live_games.values())
            for entry in self._pcap_cache.values():
                all_records.extend(entry.get("games") or [])
            scan = dict(self._scan_state)

        deduped = _dedup_records(all_records)
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
        """Return full game record (summary + players + events + gaps) by id."""
        with self._lock:
            if game_id in self._live_games:
                rec = dict(self._live_games[game_id])
                rec["summary"] = _summarize_game(rec)
                return rec
            for entry in self._pcap_cache.values():
                for rec in entry.get("games") or []:
                    if rec.get("game_id") == game_id:
                        out = dict(rec)
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
                    self._persist_pcap_cache()
                    for rec in records:
                        if rec.get("game_id") == game_id:
                            out = dict(rec)
                            out["summary"] = _summarize_game(out)
                            return out
        return None
