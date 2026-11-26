"""Background PCAP cache indexer, matches.csv + notes merger, server map, and party-vs-ping aggregator."""

from __future__ import annotations

import csv
import datetime
import json
import os
import re
import statistics
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from tools.chat_viewer.pcap_reader import InvalidPcapMagicError
from tools.chat_viewer.templates import TemplateResolver

from .classifier import classify_ip, is_public_ipv4
from .detector import LagPacketEngine
from .pcap_net import IncrementalNetPcapReader
from .tcp_lobby import find_zstd

DEFAULT_CAPTURES_DIR = Path(__file__).resolve().parents[2] / "captures"
DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
MIN_PCAP_BYTES = 100
CACHE_SCHEMA_VERSION = 1

_PARTY_SIZE_RE = re.compile(r"\b(\d+)q\b", re.IGNORECASE)
_COUNTRY_TOKEN_RE = re.compile(r"\b(ID|MY|SG|IN|MV|PH|US|AU|JP|TR|KZ)\b")


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


def _parse_iso_ts(raw: str) -> float:
    text = raw.strip()
    if not text:
        return 0.0
    try:
        dt = datetime.datetime.fromisoformat(text)
        return dt.timestamp()
    except ValueError:
        return 0.0


def _infer_party_from_csv(party_text: str) -> tuple[int | None, str, dict[str, int]]:
    low = party_text.lower()
    size: int | None = None
    m_size = _PARTY_SIZE_RE.search(party_text)
    if m_size:
        size = int(m_size.group(1))
    elif "solo" in low:
        size = 1
    elif "duo" in low:
        size = 2
    elif "trio" in low:
        size = 3

    label = {1: "Solo", 2: "Duo", 3: "Trio", 4: "4-stack", 5: "5-stack"}.get(size or 0, "")
    cc_counts: dict[str, int] = {}
    for tok in _COUNTRY_TOKEN_RE.findall(party_text):
        cc_counts[tok] = cc_counts.get(tok, 0) + 1

    # Handle shorthand like "2 MY" in CSV notes.
    for cnt_s, cc in re.findall(r"\b(\d+)\s+(ID|MY|SG|IN|MV|PH|US)\b", party_text):
        cnt = int(cnt_s)
        if cnt > cc_counts.get(cc, 0):
            cc_counts[cc] = cnt

    if cc_counts:
        cc_str = " + ".join(
            f"{cnt} {cc}" if cnt > 1 else cc
            for cc, cnt in sorted(cc_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        )
        mix = f"{label}: {cc_str}" if label else cc_str
    else:
        mix = label or party_text.strip() or "Unknown"
    return size, mix, cc_counts


def _record_richness(rec: dict[str, Any]) -> tuple[int, int, int, float, int]:
    rtt_cnt = int(((rec.get("rtt") or {}).get("links") or {}).get("Combined", {}).get("sample_count") or 0)
    players_cnt = len(rec.get("players") or [])
    dur = float(rec.get("duration_s") or 0.0)
    is_pcap = 1 if rec.get("origin") == "pcap" else 0
    is_live = 1 if rec.get("origin") == "live" else 0
    return (is_pcap + is_live, rtt_cnt, players_cnt, dur, int(bool(rec.get("handover"))))


def _same_capture_match(a: dict[str, Any], b: dict[str, Any]) -> bool:
    bid_a = str(a.get("battle_id") or "").strip()
    bid_b = str(b.get("battle_id") or "").strip()
    if bid_a and bid_b:
        return bid_a == bid_b
    ip_a = a.get("server_ip")
    if ip_a and ip_a == b.get("server_ip") and a.get("server_port") == b.get("server_port"):
        ts_a = float(a.get("first_ts") or 0.0)
        ts_b = float(b.get("first_ts") or 0.0)
        return abs(ts_a - ts_b) <= 15.0
    return False


def _decode_pcap_for_lag(
    path: Path,
    *,
    templates: TemplateResolver,
    zstd_path: Any = None,
    use_default_zstd: bool = True,
) -> dict[str, Any]:
    engine = (
        LagPacketEngine(templates=templates, live_mode=False, record_feed=False)
        if use_default_zstd
        else LagPacketEngine(templates=templates, zstd_path=zstd_path, live_mode=False, record_feed=False)
    )
    reader = IncrementalNetPcapReader()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(131072)
            if not chunk:
                break
            for pkt in reader.feed(chunk):
                engine.on_packet(pkt, skipped_truncated=reader.skipped_truncated)
    engine.flush()
    matches = engine.build_match_records(source_name=path.name, origin="pcap")
    for m in matches:
        m["match_key"] = m["match_key"] if m.get("battle_id") else f"pcap:{path.name}:{m['match_id']}"
    probes = engine.get_probes_list()
    return {"matches": matches, "probes": probes}


class LagAggregator:
    """Thread-safe repository of PCAP captures, `data/matches.csv`, live overlay, and user notes."""

    def __init__(
        self,
        *,
        captures_dir: Path | None = None,
        data_dir: Path | None = None,
        templates: TemplateResolver | None = None,
        on_change: Callable[[], None] | None = None,
    ) -> None:
        self.captures_dir = Path(captures_dir) if captures_dir is not None else DEFAULT_CAPTURES_DIR
        self.data_dir = Path(data_dir) if data_dir is not None else DEFAULT_DATA_DIR
        self.templates = templates if templates is not None else TemplateResolver()
        self.on_change = on_change

        self._cache_path = self.data_dir / "lag_mapper_cache.json"
        self._notes_path = self.data_dir / "lag_mapper_notes.json"
        self._csv_path = self.data_dir / "matches.csv"

        self._lock = threading.RLock()
        self._io_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._scan_thread: threading.Thread | None = None

        self._pcap_cache: dict[str, dict[str, Any]] = {}
        self._notes: dict[str, dict[str, Any]] = {}
        self._live_matches: list[dict[str, Any]] = []
        self._live_probes: list[dict[str, Any]] = []
        self._scan_state: dict[str, Any] = {"scanning": False, "done": 0, "total": 0, "current_file": ""}

        z_backend, _ = find_zstd()
        self.zstd_available = z_backend is not None
        self._load_disk()

    def _load_disk(self) -> None:
        notes_raw = _read_json_safe(self._notes_path)
        notes_map = notes_raw.get("notes") if isinstance(notes_raw.get("notes"), dict) else notes_raw
        if isinstance(notes_map, dict):
            for k, v in notes_map.items():
                if isinstance(k, str) and isinstance(v, dict):
                    self._notes[k] = dict(v)

        cache_raw = _read_json_safe(self._cache_path)
        if cache_raw.get("version") != CACHE_SCHEMA_VERSION:
            return
        files_map = cache_raw.get("files") if isinstance(cache_raw.get("files"), dict) else {}
        for fname, entry in files_map.items():
            if isinstance(fname, str) and isinstance(entry, dict) and isinstance(entry.get("matches"), list):
                self._pcap_cache[fname] = entry

    def _persist_cache(self) -> None:
        with self._lock:
            snap = {"version": CACHE_SCHEMA_VERSION, "files": dict(self._pcap_cache)}
        with self._io_lock:
            _atomic_write_json(self._cache_path, snap)

    def _persist_notes(self) -> None:
        with self._lock:
            snap = {"version": 1, "notes": dict(self._notes)}
        with self._io_lock:
            _atomic_write_json(self._notes_path, snap)

    def _notify_change(self) -> None:
        cb = self.on_change
        if cb is not None:
            try:
                cb()
            except Exception:
                pass

    def set_live_snapshot(self, matches: list[dict[str, Any]], probes: list[dict[str, Any]]) -> None:
        """Overlay active live/followed matches and probes into aggregated views."""
        with self._lock:
            self._live_matches = [dict(m) for m in matches]
            self._live_probes = [dict(p) for p in probes]

    def save_note(
        self,
        match_key: str,
        *,
        host: str | None = None,
        displayed_ping_ms: float | str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Persist user host/ping/note metadata for *match_key* in `data/lag_mapper_notes.json`."""
        clean_key = match_key.strip()
        if not clean_key:
            raise ValueError("match_key must be non-empty")

        ping_val: float | None = None
        if displayed_ping_ms not in (None, ""):
            try:
                ping_val = round(float(displayed_ping_ms), 1)
            except (TypeError, ValueError) as exc:
                raise ValueError("displayed_ping_ms must be numeric") from exc

        with self._lock:
            entry = dict(self._notes.get(clean_key, {}))
            if host is not None:
                entry["host"] = str(host).strip()
            if displayed_ping_ms is not None:
                entry["displayed_ping_ms"] = ping_val
            if note is not None:
                entry["note"] = str(note).strip()
            entry["updated_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
            self._notes[clean_key] = entry
        self._persist_notes()
        self._notify_change()
        return entry

    def index_pcap_file(self, path: Path) -> bool:
        """Decode and cache a single `.pcap` file inside `captures_dir`."""
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
            decoded = _decode_pcap_for_lag(target, templates=self.templates)
        except (OSError, InvalidPcapMagicError):
            return False
        with self._lock:
            self._pcap_cache[target.name] = {
                "size": st.st_size,
                "mtime_ns": st.st_mtime_ns,
                "zstd_available": self.zstd_available,
                "matches": decoded["matches"],
                "probes": decoded["probes"],
            }
        self._persist_cache()
        self._notify_change()
        return True

    def start_background_scan(self, force: bool = False) -> dict[str, Any]:
        """Scan `captures/*.pcap` on a background thread using size/mtime cache."""
        with self._lock:
            if self._scan_thread is not None and self._scan_thread.is_alive():
                return dict(self._scan_state)
            self._stop_event.clear()
            t = threading.Thread(
                target=self._scan_worker,
                args=(force,),
                name="lag-mapper-scan",
                daemon=True,
            )
            self._scan_thread = t
            self._scan_state = {"scanning": True, "done": 0, "total": 0, "current_file": ""}
            t.start()
            return dict(self._scan_state)

    def stop_scan(self, timeout: float = 2.0) -> None:
        """Stop background PCAP indexing cleanly on shutdown."""
        self._stop_event.set()
        t = self._scan_thread
        if t is not None and t.is_alive():
            t.join(timeout=timeout)

    def _scan_worker(self, force: bool) -> None:
        any_changed = False
        try:
            if not self.captures_dir.is_dir():
                with self._lock:
                    if self._pcap_cache:
                        self._pcap_cache.clear()
                        any_changed = True
                if any_changed:
                    self._persist_cache()
                return

            files = sorted(
                (p for p in self.captures_dir.glob("*.pcap") if p.is_file() and p.stat().st_size >= MIN_PCAP_BYTES),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            present = {p.name for p in files}
            pruned = False
            with self._lock:
                stale = [fn for fn in self._pcap_cache if fn not in present]
                for fn in stale:
                    del self._pcap_cache[fn]
                    pruned = True
                    any_changed = True
                self._scan_state = {"scanning": True, "done": 0, "total": len(files), "current_file": ""}
            if pruned:
                self._persist_cache()

            for idx, p in enumerate(files, 1):
                if self._stop_event.is_set():
                    break
                st = p.stat()
                with self._lock:
                    cached = self._pcap_cache.get(p.name)
                    self._scan_state["current_file"] = p.name
                if (
                    not force
                    and cached is not None
                    and cached.get("size") == st.st_size
                    and cached.get("mtime_ns") == st.st_mtime_ns
                    and cached.get("zstd_available") == self.zstd_available
                ):
                    with self._lock:
                        self._scan_state["done"] = idx
                    continue

                try:
                    decoded = _decode_pcap_for_lag(p, templates=self.templates)
                except (OSError, InvalidPcapMagicError):
                    decoded = {"matches": [], "probes": []}

                with self._lock:
                    self._pcap_cache[p.name] = {
                        "size": st.st_size,
                        "mtime_ns": st.st_mtime_ns,
                        "zstd_available": self.zstd_available,
                        "matches": decoded["matches"],
                        "probes": decoded["probes"],
                    }
                    self._scan_state["done"] = idx
                any_changed = True
                self._persist_cache()
                self._notify_change()
        finally:
            with self._lock:
                self._scan_state["scanning"] = False
                self._scan_state["current_file"] = ""
            if any_changed:
                self._notify_change()

    def _load_csv_rows(self) -> list[dict[str, Any]]:
        if not self._csv_path.is_file():
            return []
        rows: list[dict[str, Any]] = []
        try:
            with self._csv_path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for idx, row in enumerate(reader, 1):
                    ep_ip = str(row.get("endpoint") or "").strip()
                    if not ep_ip or not is_public_ipv4(ep_ip):
                        continue
                    try:
                        ep_port = int(str(row.get("port") or "0").strip())
                    except ValueError:
                        ep_port = 0
                    ts = _parse_iso_ts(str(row.get("ts") or ""))
                    ping_raw = str(row.get("displayed_ping_ms") or "").strip()
                    ping_ms: float | None = None
                    if ping_raw:
                        try:
                            ping_ms = round(float(ping_raw), 1)
                        except ValueError:
                            ping_ms = None
                    dur_raw = str(row.get("duration_s") or "").strip()
                    dur_s = float(dur_raw) if dur_raw else 0.0
                    out_pkts = int(row["out_pkts"]) if str(row.get("out_pkts") or "").strip().isdigit() else 0
                    in_pkts = int(row["in_pkts"]) if str(row.get("in_pkts") or "").strip().isdigit() else 0
                    ifaces = [x.strip() for x in str(row.get("ifaces") or "").split(",") if x.strip()]
                    party_txt = str(row.get("party") or "").strip()
                    p_size, p_mix, cc_counts = _infer_party_from_csv(party_txt)
                    cls = classify_ip(ep_ip)
                    label = str(row.get("label") or "").strip()
                    host = str(row.get("host") or "").strip()
                    note = str(row.get("note") or "").strip()

                    # Prefer live classifier when CSV says unknown, else keep verified CSV city/provider context.
                    provider = cls["provider"] if cls["confidence"] == "known" else (str(row.get("provider") or "").strip() or cls["provider"])
                    city = cls["city"] if cls["confidence"] == "known" else (str(row.get("city_geo") or "").strip() or cls["city"])
                    conf = cls["confidence"] if cls["confidence"] == "known" else (str(row.get("confidence") or "").strip() or "csv")

                    rows.append(
                        {
                            "match_key": f"csv:{idx}:{ep_ip}:{ep_port}",
                            "origin": "csv",
                            "source_name": "matches.csv",
                            "match_id": f"csv-{idx}",
                            "battle_id": None,
                            "server_ip": ep_ip,
                            "server_port": ep_port,
                            "subnet": cls["subnet"],
                            "provider": provider,
                            "city": city,
                            "confidence": conf,
                            "cluster_key": cls["cluster_key"],
                            "approx_coords": cls["approx_coords"],
                            "first_ts": ts,
                            "last_ts": ts + dur_s,
                            "duration_s": round(dur_s, 1),
                            "phase": "CSV",
                            "mode_label": "",
                            "pvp_type": None,
                            "map_id": None,
                            "party_label": {1: "Solo", 2: "Duo", 3: "Trio", 4: "4-stack", 5: "5-stack"}.get(p_size or 0, ""),
                            "party_mix_label": p_mix,
                            "local_party_size": p_size,
                            "ally_party_countries": cc_counts,
                            "ally_party_players": [],
                            "enemy_stack_sizes": [],
                            "country_counts": cc_counts,
                            "local_uid": None,
                            "local_camp": None,
                            "players": [],
                            "battle_mode": None,
                            "max_tick_seen": None,
                            "convs": [],
                            "rebind_count": 0,
                            "ifaces": ifaces,
                            "multipath": {
                                "wifi_out_pkts": out_pkts if "wlan0" in ifaces else 0,
                                "wifi_in_pkts": in_pkts if "wlan0" in ifaces else 0,
                                "cell_out_pkts": 0,
                                "cell_in_pkts": 0,
                                "other_out_pkts": 0,
                                "other_in_pkts": 0,
                                "wifi_pkts": out_pkts + in_pkts if "wlan0" in ifaces else 0,
                                "cell_pkts": 0,
                                "other_pkts": 0,
                            },
                            "rtt": {"links": {"Wi-Fi": {}, "Cellular": {}, "Combined": {}}, "by_iface_ip": {}, "series": []},
                            "tcp_mirror": None,
                            "handover": None,
                            "probes": [],
                            "probe_count": 0,
                            "host": host,
                            "displayed_ping_ms": ping_ms,
                            "note": note,
                            "label": label,
                            "csv_party": party_txt,
                            "csv_matched": True,
                        }
                    )
        except OSError:
            return []
        return rows

    def get_matches(self) -> list[dict[str, Any]]:
        """Return newest-first deduplicated matches merging PCAP, live, `matches.csv`, and user notes."""
        with self._lock:
            raw_records: list[dict[str, Any]] = [dict(m) for m in self._live_matches]
            for entry in self._pcap_cache.values():
                for m in entry.get("matches") or []:
                    raw_records.append(dict(m))
            notes_snap = {k: dict(v) for k, v in self._notes.items()}

        # Deduplicate live vs PCAP matches.
        clusters: list[list[dict[str, Any]]] = []
        for rec in raw_records:
            matched_idxs = [
                idx
                for idx, cluster in enumerate(clusters)
                if any(_same_capture_match(existing, rec) for existing in cluster)
            ]
            if not matched_idxs:
                clusters.append([rec])
            else:
                merged = [rec]
                for idx in reversed(matched_idxs):
                    merged.extend(clusters.pop(idx))
                clusters.append(merged)

        deduped = [dict(max(cluster, key=_record_richness)) for cluster in clusters]

        # Merge data/matches.csv rows within +/- 180s on same (endpoint, port).
        csv_rows = self._load_csv_rows()
        standalone_csv: list[dict[str, Any]] = []
        for crow in csv_rows:
            c_ts = float(crow["first_ts"] or 0.0)
            c_ip = crow["server_ip"]
            c_port = int(crow["server_port"] or 0)
            best_match: dict[str, Any] | None = None
            best_dt = 180.0001
            for rec in deduped:
                if rec["server_ip"] != c_ip or int(rec.get("server_port") or 0) != c_port:
                    continue
                dt = min(
                    abs(c_ts - float(rec.get("first_ts") or 0.0)),
                    abs(c_ts - float(rec.get("last_ts") or 0.0)),
                )
                if dt <= 180.0 and dt < best_dt:
                    best_dt = dt
                    best_match = rec
            if best_match is not None:
                if crow.get("host") and not best_match.get("host"):
                    best_match["host"] = crow["host"]
                if crow.get("displayed_ping_ms") is not None and best_match.get("displayed_ping_ms") is None:
                    best_match["displayed_ping_ms"] = crow["displayed_ping_ms"]
                if crow.get("label"):
                    best_match["label"] = crow["label"]
                if crow.get("csv_party"):
                    best_match["csv_party"] = crow["csv_party"]
                if crow.get("note"):
                    best_match["note"] = crow["note"]
                best_match["csv_matched"] = True
            else:
                standalone_csv.append(crow)

        combined = deduped + standalone_csv
        for rec in combined:
            saved = notes_snap.get(rec["match_key"])
            if saved:
                if "host" in saved:
                    rec["host"] = saved["host"]
                if "displayed_ping_ms" in saved:
                    rec["displayed_ping_ms"] = saved["displayed_ping_ms"]
                if "note" in saved:
                    rec["note"] = saved["note"]

        combined.sort(key=lambda r: (float(r.get("first_ts") or 0.0), str(r.get("match_key") or "")), reverse=True)
        return combined

    def get_servers(self) -> list[dict[str, Any]]:
        """Aggregate visited MLBB match servers across all matches and `:30190` probe counts."""
        matches = self.get_matches()
        with self._lock:
            probe_counts: dict[str, int] = defaultdict(int)
            for p in self._live_probes:
                if p.get("ip"):
                    probe_counts[str(p["ip"])] += 1
            for entry in self._pcap_cache.values():
                for p in entry.get("probes") or []:
                    if p.get("ip"):
                        probe_counts[str(p["ip"])] += 1

        by_ip: dict[str, dict[str, Any]] = {}
        for m in matches:
            ip = str(m.get("server_ip") or "")
            if not is_public_ipv4(ip):
                continue
            row = by_ip.get(ip)
            if row is None:
                cls = classify_ip(ip)
                row = {
                    "ip": ip,
                    "subnet": cls["subnet"],
                    "provider": m.get("provider") or cls["provider"],
                    "city": m.get("city") or cls["city"],
                    "confidence": cls["confidence"] if cls["confidence"] == "known" else (m.get("confidence") or cls["confidence"]),
                    "cluster_key": cls["cluster_key"],
                    "approx_coords": cls["approx_coords"],
                    "ports": set(),
                    "match_count": 0,
                    "modes": set(),
                    "wifi_medians": [],
                    "cell_medians": [],
                    "overall_medians": [],
                    "displayed_pings": [],
                    "probe_count": probe_counts.get(ip, 0),
                    "last_seen_ts": 0.0,
                }
                by_ip[ip] = row

            row["match_count"] += 1
            port = int(m.get("server_port") or 0)
            if port > 0:
                row["ports"].add(port)
            mode = str(m.get("mode_label") or "").strip()
            if mode:
                row["modes"].add(mode)
            links = (m.get("rtt") or {}).get("links") or {}
            w_med = (links.get("Wi-Fi") or {}).get("median_ms")
            c_med = (links.get("Cellular") or {}).get("median_ms")
            all_med = (links.get("Combined") or {}).get("median_ms")
            if isinstance(w_med, (int, float)):
                row["wifi_medians"].append(float(w_med))
            if isinstance(c_med, (int, float)):
                row["cell_medians"].append(float(c_med))
            if isinstance(all_med, (int, float)):
                row["overall_medians"].append(float(all_med))
            disp = m.get("displayed_ping_ms")
            if isinstance(disp, (int, float)):
                row["displayed_pings"].append(round(float(disp), 1))
            row["last_seen_ts"] = max(row["last_seen_ts"], float(m.get("last_ts") or m.get("first_ts") or 0.0))

        out: list[dict[str, Any]] = []
        for row in by_ip.values():
            w_med = round(statistics.median(row["wifi_medians"]), 1) if row["wifi_medians"] else None
            c_med = round(statistics.median(row["cell_medians"]), 1) if row["cell_medians"] else None
            o_med = round(statistics.median(row["overall_medians"]), 1) if row["overall_medians"] else None
            disp_med = round(statistics.median(row["displayed_pings"]), 1) if row["displayed_pings"] else None
            out.append(
                {
                    "ip": row["ip"],
                    "subnet": row["subnet"],
                    "provider": row["provider"],
                    "city": row["city"],
                    "confidence": row["confidence"],
                    "cluster_key": row["cluster_key"],
                    "approx_coords": row["approx_coords"],
                    "ports": sorted(row["ports"]),
                    "match_count": row["match_count"],
                    "modes": sorted(row["modes"]),
                    "wifi_median_ms": w_med,
                    "cell_median_ms": c_med,
                    "overall_median_ms": o_med,
                    "displayed_pings": row["displayed_pings"],
                    "displayed_ping_median_ms": disp_med,
                    "effective_rtt_ms": o_med if o_med is not None else disp_med,
                    "probe_count": row["probe_count"],
                    "last_seen_ts": row["last_seen_ts"],
                }
            )
        out.sort(key=lambda r: (-r["match_count"], r["effective_rtt_ms"] or 9999.0, r["ip"]))
        return out

    def get_correlations(self) -> dict[str, Any]:
        """Group matches by `(Mode, Party Mix, Host)` and compare against Solo baseline RTT."""
        matches = self.get_matches()
        solo_rtts: list[float] = []
        all_rtts: list[float] = []

        for m in matches:
            o_med = ((m.get("rtt") or {}).get("links") or {}).get("Combined", {}).get("median_ms")
            eff = float(o_med) if isinstance(o_med, (int, float)) else (
                float(m["displayed_ping_ms"]) if isinstance(m.get("displayed_ping_ms"), (int, float)) else None
            )
            if eff is None:
                continue
            all_rtts.append(eff)
            if m.get("local_party_size") == 1 or str(m.get("party_label") or "").lower() == "solo":
                solo_rtts.append(eff)

        if solo_rtts:
            baseline_ms = round(statistics.median(solo_rtts), 1)
            baseline_label = "Solo baseline"
        elif all_rtts:
            baseline_ms = round(statistics.median(all_rtts), 1)
            baseline_label = "All-match median"
        else:
            baseline_ms = None
            baseline_label = "No RTT baseline yet"

        groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        for m in matches:
            mode = str(m.get("mode_label") or "").strip() or ("CSV" if m.get("origin") == "csv" else "Unknown")
            party_mix = str(m.get("party_mix_label") or m.get("party_label") or "Unknown").strip()
            host = str(m.get("host") or "").strip() or "Unspecified"
            gkey = (mode, party_mix, host)
            g = groups.get(gkey)
            if g is None:
                g = {
                    "mode": mode,
                    "party_mix": party_mix,
                    "host": host,
                    "match_count": 0,
                    "servers": {},
                    "udp_rtts": [],
                    "disp_pings": [],
                    "probe_counts": [],
                    "match_keys": [],
                }
                groups[gkey] = g

            g["match_count"] += 1
            g["match_keys"].append(m["match_key"])
            ip = str(m.get("server_ip") or "")
            srv_entry = g["servers"].get(ip)
            if srv_entry is None:
                srv_entry = {
                    "ip": ip,
                    "provider": m.get("provider") or "Observed",
                    "city": m.get("city") or "Unknown",
                    "count": 0,
                }
                g["servers"][ip] = srv_entry
            srv_entry["count"] += 1

            o_med = ((m.get("rtt") or {}).get("links") or {}).get("Combined", {}).get("median_ms")
            if isinstance(o_med, (int, float)):
                g["udp_rtts"].append(float(o_med))
            if isinstance(m.get("displayed_ping_ms"), (int, float)):
                g["disp_pings"].append(float(m["displayed_ping_ms"]))
            g["probe_counts"].append(int(m.get("probe_count") or 0))

        rows: list[dict[str, Any]] = []
        for g in groups.values():
            med_udp = round(statistics.median(g["udp_rtts"]), 1) if g["udp_rtts"] else None
            med_disp = round(statistics.median(g["disp_pings"]), 1) if g["disp_pings"] else None
            eff = med_udp if med_udp is not None else med_disp
            delta = round(eff - baseline_ms, 1) if (eff is not None and baseline_ms is not None) else None
            srvs = sorted(g["servers"].values(), key=lambda s: (-s["count"], s["ip"]))
            rows.append(
                {
                    "mode": g["mode"],
                    "party_mix": g["party_mix"],
                    "host": g["host"],
                    "match_count": g["match_count"],
                    "servers": srvs,
                    "median_udp_rtt_ms": med_udp,
                    "median_displayed_ping_ms": med_disp,
                    "delta_vs_baseline_ms": delta,
                    "max_probe_targets": max(g["probe_counts"]) if g["probe_counts"] else 0,
                    "sample_match_keys": g["match_keys"],
                }
            )
        rows.sort(key=lambda r: (-r["match_count"], r["mode"], r["party_mix"]))
        return {
            "baseline_ms": baseline_ms,
            "baseline_label": baseline_label,
            "groups": rows,
        }

    def get_overview(self, live_status: dict[str, Any]) -> dict[str, Any]:
        """Return global KPI summary, background scan progress, and active server info."""
        servers = self.get_servers()
        matches = self.get_matches()
        with self._lock:
            scan = dict(self._scan_state)

        best_server = None
        best_rtt: float | None = None
        for s in servers:
            r = s.get("effective_rtt_ms")
            if isinstance(r, (int, float)) and (best_rtt is None or r < best_rtt):
                best_rtt = float(r)
                best_server = {"ip": s["ip"], "provider": s["provider"], "city": s["city"], "rtt_ms": round(r, 1)}

        return {
            "total_servers": len(servers),
            "total_matches": len(matches),
            "best_server": best_server,
            "scan": scan,
            "zstd_available": self.zstd_available,
            "live_status": live_status,
        }
