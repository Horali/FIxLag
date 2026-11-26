"""ADB live tcpdump pipe, PCAP replay/follow controller, and thread-safe SSE LiveStore."""

from __future__ import annotations

import asyncio
import datetime
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from tools.chat_viewer.ingest import find_adb, list_adb_devices
from tools.chat_viewer.pcap_reader import InvalidPcapMagicError
from tools.chat_viewer.templates import TemplateResolver

from .aggregator import LagAggregator
from .detector import LagPacketEngine
from .pcap_net import IncrementalNetPcapReader

DEFAULT_BPF = (
    "(udp portrange 5000-5999 and not port 5353) "
    "or udp port 30190 "
    "or tcp port 30101 "
    "or tcp portrange 5000-6049"
)

__all__ = [
    "DEFAULT_BPF",
    "LagIngestController",
    "LiveStore",
    "build_adb_tcpdump_command",
    "find_adb",
    "list_adb_devices",
]


def build_adb_tcpdump_command(adb_path: Path, serial: str, bpf: str = DEFAULT_BPF) -> list[str]:
    """Build binary-clean `adb -s <serial> exec-out` command streaming raw PCAP bytes."""
    remote = f"su -c '/system/bin/tcpdump -i any -U -s 0 -w - \"{bpf}\" 2>/dev/null'"
    return [str(adb_path), "-s", serial, "exec-out", remote]


class LiveStore:
    """Thread-safe RAM store wrapping `LagPacketEngine` + bounded SSE replay fan-out."""

    def __init__(
        self,
        *,
        templates: TemplateResolver | None = None,
        max_replay_log: int = 10000,
    ) -> None:
        self._lock = threading.RLock()
        self.engine = LagPacketEngine(templates=templates, live_mode=False, record_feed=True)
        self._next_event_id = 1
        self._replay_log: list[tuple[int, str, dict[str, Any]]] = []
        self._max_replay_log = max_replay_log
        self._subscribers: list[
            tuple[asyncio.AbstractEventLoop, asyncio.Queue[tuple[int, str, dict[str, Any]]]]
        ] = []

        self._source_mode = "IDLE"
        self._source_detail = ""
        self._capture_alive = False
        self._last_pkt_mono: float | None = None
        self._last_error: str | None = None

    def reset_for_new_source(self, source_mode: str, source_detail: str, *, live_mode: bool) -> None:
        """Reset engine and status for a newly started capture/replay source."""
        with self._lock:
            self.engine.reset()
            self.engine.lobby.live_mode = live_mode
            self._source_mode = source_mode
            self._source_detail = source_detail
            self._capture_alive = source_mode in ("LIVE (adb)", "FOLLOW (file)", "REPLAY (file)")
            self._last_pkt_mono = None
            self._last_error = None
            status = self.get_status()
        self.publish("status", status)

    def set_capture_state(
        self,
        *,
        alive: bool,
        source_mode: str | None = None,
        source_detail: str | None = None,
        error: str | None = None,
    ) -> None:
        """Update capture status fields and emit an SSE `status` event."""
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

    def process_packet(self, pkt: Any, *, skipped_truncated: int = 0) -> dict[str, Any]:
        """Thread-safely feed one `NetPacket` into `LagPacketEngine`."""
        with self._lock:
            self._last_pkt_mono = time.monotonic()
            return self.engine.on_packet(pkt, skipped_truncated=skipped_truncated)

    def flush_engine(self) -> list[dict[str, Any]]:
        """Thread-safely flush deferred TCP :30101 Zstd batches."""
        with self._lock:
            return self.engine.flush()

    def build_live_records(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Return `(matches, probes)` snapshot from current live engine."""
        with self._lock:
            return (
                self.engine.build_match_records(source_name=self._source_detail or "Live capture", origin="live"),
                self.engine.get_probes_list(),
            )

    def get_live_packets(self) -> dict[str, Any]:
        """Return live 7-lane telemetry, multipath stats, RTT series, probes, and feed."""
        with self._lock:
            snap = self.engine.get_live_packets_snapshot()
            snap["status"] = self.get_status()
            return snap

    def get_status(self) -> dict[str, Any]:
        """Return current ingest status summary."""
        with self._lock:
            age_s = round(time.monotonic() - self._last_pkt_mono, 2) if self._last_pkt_mono is not None else None
            matches = self.engine.session_store.get_matches()
            active = matches[-1] if matches else None
            return {
                "source_mode": self._source_mode,
                "source_detail": self._source_detail,
                "capture_alive": self._capture_alive,
                "last_pkt_age_s": age_s,
                "last_error": self._last_error,
                "packets_processed": self.engine.packets_processed,
                "skipped_truncated": self.engine.skipped_truncated,
                "active_server": f"{active.server_ip}:{active.server_port}" if active else None,
                "active_battle_id": active.battle_id if active else None,
                "phase": active.phase if active else "IDLE",
            }

    def allocate_event_id(self) -> int:
        """Allocate a strictly monotonic SSE event id."""
        with self._lock:
            eid = self._next_event_id
            self._next_event_id += 1
            return eid

    def publish(self, event_name: str, data: dict[str, Any]) -> int:
        """Broadcast an SSE event and record non-heartbeat events in the replay ring."""
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
        """Register an SSE client queue and return any missed events since *last_event_id*."""
        q: asyncio.Queue[tuple[int, str, dict[str, Any]]] = asyncio.Queue(maxsize=512)
        with self._lock:
            missed = (
                [item for item in self._replay_log if item[0] > last_event_id]
                if last_event_id is not None
                else []
            )
            self._subscribers.append((loop, q))
        return q, missed

    def unsubscribe(
        self,
        loop: asyncio.AbstractEventLoop,
        q: asyncio.Queue[tuple[int, str, dict[str, Any]]],
    ) -> None:
        """Remove an SSE client subscription."""
        with self._lock:
            pair = (loop, q)
            if pair in self._subscribers:
                self._subscribers.remove(pair)


class LagIngestController:
    """Manages a single background worker streaming ADB tcpdump or local `.pcap` files."""

    def __init__(
        self,
        *,
        store: LiveStore,
        aggregator: LagAggregator,
        captures_dir: Path,
        adb_path: Path | str | None = None,
    ) -> None:
        self.store = store
        self.aggregator = aggregator
        self.captures_dir = Path(captures_dir)
        self.adb_path_override = adb_path

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen[bytes] | None = None

    def stop(self, timeout: float = 3.0) -> None:
        """Stop any running PCAP or ADB capture thread and terminate child processes."""
        with self._lock:
            self._stop_event.set()
            proc = self._proc
            thread = self._thread
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except (OSError, subprocess.SubprocessError):
                try:
                    proc.kill()
                except OSError:
                    pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        with self._lock:
            self._proc = None
            self._thread = None

    def start_pcap(self, path: Path, follow: bool = False) -> None:
        """Start static PCAP replay or `--follow` tailing on a background thread."""
        pcap_path = Path(path)
        if not pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        self.stop()
        with self._lock:
            self._stop_event = threading.Event()
            stop_ev = self._stop_event
            mode = "FOLLOW (file)" if follow else "REPLAY (file)"
            self.store.reset_for_new_source(mode, pcap_path.name, live_mode=follow)
            t = threading.Thread(
                target=self._run_pcap_worker,
                args=(pcap_path, follow, stop_ev),
                name="lag-mapper-pcap",
                daemon=True,
            )
            self._thread = t
            t.start()

    def start_adb(self, serial: str, tee: bool = False) -> None:
        """Start live `adb exec-out` tcpdump capture on a background thread."""
        clean_serial = serial.strip()
        if not clean_serial:
            raise ValueError("ADB serial must be non-empty")
        adb = find_adb(self.adb_path_override)
        if adb is None:
            raise FileNotFoundError("adb executable not found")

        self.stop()
        tee_path: Path | None = None
        if tee:
            self.captures_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            tee_path = self.captures_dir / f"live_lag_{stamp}.pcap"

        cmd = build_adb_tcpdump_command(adb, clean_serial)
        with self._lock:
            self._stop_event = threading.Event()
            stop_ev = self._stop_event
            detail = f"{clean_serial}" + (f" -> {tee_path.name}" if tee_path else "")
            self.store.reset_for_new_source("LIVE (adb)", detail, live_mode=True)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            self._proc = proc
            t = threading.Thread(
                target=self._run_adb_worker,
                args=(proc, tee_path, stop_ev),
                name="lag-mapper-adb",
                daemon=True,
            )
            self._thread = t
            t.start()

    def _emit_batch(
        self,
        pending_feed: list[dict[str, Any]],
        pending_rtt: list[dict[str, Any]],
        match_changed: bool,
        *,
        force: bool = False,
        last_push: float,
    ) -> tuple[float, bool]:
        now = time.monotonic()
        if not force and (now - last_push) < 0.25 and len(pending_feed) < 40:
            return last_push, match_changed

        if pending_feed:
            self.store.publish("packet_batch", {"items": list(pending_feed)})
            pending_feed.clear()
        if pending_rtt:
            self.store.publish("rtt_point", {"points": list(pending_rtt[-40:])})
            pending_rtt.clear()
        if match_changed or force:
            live_matches, live_probes = self.store.build_live_records()
            self.aggregator.set_live_snapshot(live_matches, live_probes)
            if live_matches:
                self.store.publish("match_update", {"match": live_matches[-1]})
            match_changed = False
        return now, match_changed

    def _run_pcap_worker(self, pcap_path: Path, follow: bool, stop_ev: threading.Event) -> None:
        reader = IncrementalNetPcapReader()
        mode = "FOLLOW (file)" if follow else "REPLAY (file)"
        pending_feed: list[dict[str, Any]] = []
        pending_rtt: list[dict[str, Any]] = []
        match_changed = False
        last_push = time.monotonic()
        try:
            with pcap_path.open("rb") as fh:
                while not stop_ev.is_set():
                    chunk = fh.read(65536)
                    if chunk:
                        for pkt in reader.feed(chunk):
                            if stop_ev.is_set():
                                break
                            res = self.store.process_packet(pkt, skipped_truncated=reader.skipped_truncated)
                            pending_feed.extend(res["feed"])
                            pending_rtt.extend(res["rtt"])
                            match_changed = match_changed or res["match_changed"]
                        last_push, match_changed = self._emit_batch(
                            pending_feed, pending_rtt, match_changed, last_push=last_push
                        )
                        continue
                    if not follow:
                        break
                    pending_feed.extend(self.store.flush_engine())
                    last_push, match_changed = self._emit_batch(
                        pending_feed, pending_rtt, match_changed, force=True, last_push=last_push
                    )
                    stop_ev.wait(0.05)
        except (InvalidPcapMagicError, OSError) as exc:
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=str(exc))
            return
        finally:
            pending_feed.extend(self.store.flush_engine())
            self._emit_batch(pending_feed, pending_rtt, True, force=True, last_push=last_push)

        self.store.set_capture_state(alive=False, source_mode=mode)
        self.store.publish("history_updated", {"ts": time.time()})

    def _run_adb_worker(
        self,
        proc: subprocess.Popen[bytes],
        tee_path: Path | None,
        stop_ev: threading.Event,
    ) -> None:
        reader = IncrementalNetPcapReader()
        tee_fh = None
        first_chunk = True
        pending_feed: list[dict[str, Any]] = []
        pending_rtt: list[dict[str, Any]] = []
        match_changed = False
        last_push = time.monotonic()
        try:
            if tee_path is not None:
                tee_fh = tee_path.open("wb")
            stdout = proc.stdout
            if stdout is None:
                self.store.set_capture_state(
                    alive=False, source_mode="CAPTURE STOPPED", error="adb stdout missing"
                )
                return
            while not stop_ev.is_set():
                chunk = stdout.read1(16384) if hasattr(stdout, "read1") else stdout.read(4096)
                if not chunk:
                    break
                if first_chunk:
                    first_chunk = False
                if tee_fh is not None:
                    tee_fh.write(chunk)
                    tee_fh.flush()
                for pkt in reader.feed(chunk):
                    if stop_ev.is_set():
                        break
                    res = self.store.process_packet(pkt, skipped_truncated=reader.skipped_truncated)
                    pending_feed.extend(res["feed"])
                    pending_rtt.extend(res["rtt"])
                    match_changed = match_changed or res["match_changed"]
                last_push, match_changed = self._emit_batch(
                    pending_feed, pending_rtt, match_changed, last_push=last_push
                )
        except (InvalidPcapMagicError, OSError) as exc:
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=str(exc))
            return
        finally:
            pending_feed.extend(self.store.flush_engine())
            self._emit_batch(pending_feed, pending_rtt, True, force=True, last_push=last_push)
            if tee_fh is not None:
                try:
                    tee_fh.close()
                except OSError:
                    pass
            if tee_path is not None and tee_path.is_file():
                self.aggregator.index_pcap_file(tee_path)

        if stop_ev.is_set():
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED")
            return

        rc = proc.poll()
        stderr_txt = ""
        if proc.stderr is not None:
            try:
                stderr_txt = proc.stderr.read().decode("utf-8", "replace").strip()
            except OSError:
                pass
        if first_chunk or not reader.header_parsed or (rc not in (None, 0)):
            detail = stderr_txt or f"tcpdump ended before PCAP header (exit={rc})"
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=detail)
        else:
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=stderr_txt or None)
