"""Live ADB tcpdump pipe and local PCAP file/follow ingest running on a dedicated thread."""

from __future__ import annotations

import datetime
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .pcap_reader import IncrementalPcapReader, InvalidPcapMagicError
from .session import MatchStore, SessionRouter

DEFAULT_ADB_PATH = Path(r"C:\Users\child\AppData\Local\Android\Sdk\platform-tools\adb.exe")
DEFAULT_BPF = "udp portrange 5000-5999 and not port 5353"
HANDOFF_OVERLAP_SECONDS = 0.5


def find_adb(override: Path | str | None = None) -> Path | None:
    """Locate `adb.exe` / `adb` without probing network or modifying device state."""
    if override is not None:
        p = Path(override)
        if p.is_file():
            return p
    if DEFAULT_ADB_PATH.is_file():
        return DEFAULT_ADB_PATH
    which = shutil.which("adb")
    return Path(which) if which else None


def list_adb_devices(adb_path: Path | str | None = None) -> list[dict[str, str]]:
    """Return connected ADB devices reported by `adb devices -l`."""
    adb = find_adb(adb_path)
    if adb is None:
        return []
    try:
        res = subprocess.run(
            [str(adb), "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    devices: list[dict[str, str]] = []
    for raw_line in res.stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        info: dict[str, str] = {
            "serial": serial,
            "state": state,
            "transport": "wireless" if ":" in serial else "usb",
            "model": "",
            "device": "",
        }
        for tok in parts[2:]:
            if ":" in tok:
                k, v = tok.split(":", 1)
                if k in ("model", "device", "product"):
                    info[k] = v
        devices.append(info)
    return devices


def build_adb_tcpdump_command(adb_path: Path, serial: str, bpf: str = DEFAULT_BPF) -> list[str]:
    """Build binary-clean `adb exec-out` command streaming raw PCAP bytes to stdout."""
    remote = f"su -c '/system/bin/tcpdump -i any -U -s 0 -w - \"{bpf}\" 2>/dev/null'"
    return [str(adb_path), "-s", serial, "exec-out", remote]


class _PcapTeeWriter:
    """Writes complete raw PCAP records continuously across zero-drop ADB handoffs."""

    def __init__(self, captures_dir: Path) -> None:
        self.captures_dir = Path(captures_dir)
        self._lock = threading.Lock()
        self._fh: Any = None
        self._header: bytes | None = None
        self._paths: list[Path] = []

    def _next_path(self) -> Path:
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        cand = self.captures_dir / f"live_{stamp}.pcap"
        idx = 2
        while cand.exists() or cand in self._paths:
            cand = self.captures_dir / f"live_{stamp}_{idx}.pcap"
            idx += 1
        return cand

    def write_record(self, global_header: bytes, raw_record: bytes) -> None:
        if not global_header or not raw_record:
            return
        with self._lock:
            if self._fh is None or self._header != global_header:
                if self._fh is not None:
                    try:
                        self._fh.close()
                    except OSError:
                        pass
                    self._fh = None
                path = self._next_path()
                self._fh = path.open("wb")
                self._fh.write(global_header)
                self._header = global_header
                self._paths.append(path)
            self._fh.write(raw_record)
            self._fh.flush()

    def current_name(self) -> str | None:
        with self._lock:
            if self._fh is not None and self._paths:
                return self._paths[-1].name
            return None

    def close(self) -> list[Path]:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
            self._header = None
            out = list(self._paths)
            self._paths.clear()
            return out


@dataclass
class _AdbStream:
    gen: int
    serial: str
    proc: subprocess.Popen[bytes]
    stop_ev: threading.Event
    thread: threading.Thread | None = None
    handoff_from: "_AdbStream | None" = None
    promoted: bool = False
    timer: threading.Timer | None = None


class IngestController:
    """Manages PCAP replay/follow and zero-drop make-before-break ADB tcpdump streaming."""

    def __init__(
        self,
        router: SessionRouter,
        store: MatchStore,
        captures_dir: Path,
        adb_path: Path | str | None = None,
        on_live_snapshot: Callable[[list[dict[str, Any]]], Any] | None = None,
        on_tee_finished: Callable[[Path], Any] | None = None,
        handoff_overlap_seconds: float = HANDOFF_OVERLAP_SECONDS,
    ) -> None:
        self.router = router
        self.store = store
        self.captures_dir = Path(captures_dir)
        self.adb_path_override = adb_path
        self.on_live_snapshot = on_live_snapshot
        self.on_tee_finished = on_tee_finished
        self.handoff_overlap_seconds = max(0.05, float(handoff_overlap_seconds))

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._is_live_mode = False

        self._next_gen = 0
        self._active_gen = 0
        self._active_stream: _AdbStream | None = None
        self._extra_streams: list[_AdbStream] = []
        self._tee_writer: _PcapTeeWriter | None = None

    def _maybe_flush_live(
        self,
        last_flush: float,
        last_sig: tuple[Any, ...],
        *,
        force: bool = False,
    ) -> tuple[float, tuple[Any, ...]]:
        if self.on_live_snapshot is None:
            return last_flush, last_sig
        now = time.monotonic()
        if not force and now - last_flush < 5.0:
            return last_flush, last_sig
        matches = self.store.get_matches_snapshot()
        sig = tuple(
            (
                str(m.get("match_id")),
                len(m.get("events") or []),
                len(m.get("gaps") or []),
                tuple((p.get("uid"), p.get("hero_id")) for p in (m.get("players") or [])),
            )
            for m in matches
        )
        if not sig or sig == last_sig:
            return last_flush, last_sig
        if any(ev_cnt > 0 or gap_cnt > 0 for _, ev_cnt, gap_cnt, _ in sig):
            self.on_live_snapshot(matches)
        return now, sig

    @staticmethod
    def _terminate_stream(stream: _AdbStream) -> None:
        stream.stop_ev.set()
        proc = stream.proc
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except (OSError, subprocess.SubprocessError):
                try:
                    proc.kill()
                except OSError:
                    pass

    def _close_tee_and_notify(self) -> None:
        with self._lock:
            tee_w = self._tee_writer
            self._tee_writer = None
        if tee_w is None:
            return
        written = tee_w.close()
        if self.on_tee_finished is not None:
            for path in written:
                try:
                    if path.is_file():
                        self.on_tee_finished(path)
                except OSError:
                    pass

    def stop(self, timeout: float = 3.0) -> None:
        """Stop all running PCAP or ADB ingest threads and child processes."""
        with self._lock:
            self._stop_event.set()
            was_live = self._is_live_mode
            streams: list[_AdbStream] = []
            if self._active_stream is not None:
                streams.append(self._active_stream)
            for extra in self._extra_streams:
                if extra not in streams:
                    streams.append(extra)
            pcap_thread = self._thread if self._active_stream is None else None
            pcap_proc = self._proc if self._active_stream is None else None

            self._active_gen = 0
            self._active_stream = None
            self._extra_streams.clear()
            for st in streams:
                st.stop_ev.set()
                if st.timer is not None:
                    st.timer.cancel()
                    st.timer = None

        for st in streams:
            self._terminate_stream(st)
        for st in streams:
            if st.thread is not None and st.thread.is_alive() and st.thread is not threading.current_thread():
                st.thread.join(timeout=timeout)

        if pcap_proc is not None and pcap_proc.poll() is None:
            try:
                pcap_proc.terminate()
                pcap_proc.wait(timeout=1.5)
            except (OSError, subprocess.SubprocessError):
                try:
                    pcap_proc.kill()
                except OSError:
                    pass
        if pcap_thread is not None and pcap_thread.is_alive() and pcap_thread is not threading.current_thread():
            pcap_thread.join(timeout=timeout)

        if was_live:
            self._maybe_flush_live(0.0, (), force=True)
        self._close_tee_and_notify()

        with self._lock:
            self._proc = None
            self._thread = None
            self._is_live_mode = False

    def start_pcap(self, path: Path, follow: bool = False) -> None:
        """Start static PCAP replay or `--follow` tailing on a background thread."""
        pcap_path = Path(path)
        if not pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        self.stop()
        with self._lock:
            self._stop_event = threading.Event()
            stop_ev = self._stop_event
            self.router.reset()
            mode = "FOLLOW (file)" if follow else "REPLAY (file)"
            self._is_live_mode = follow
            self.store.reset_for_new_source(mode, str(pcap_path))
            t = threading.Thread(
                target=self._run_pcap_worker,
                args=(pcap_path, follow, stop_ev),
                name="chat-viewer-pcap",
                daemon=True,
            )
            self._thread = t
            t.start()

    def start_adb(self, serial: str, tee: bool = False, *, preserve_session: bool = False) -> None:
        """Start live ADB streaming, or hot-switch transports without losing state."""
        clean_serial = serial.strip()
        if not clean_serial:
            raise ValueError("ADB serial must be non-empty")
        adb = find_adb(self.adb_path_override)
        if adb is None:
            raise FileNotFoundError("adb executable not found")

        cmd = build_adb_tcpdump_command(adb, clean_serial)

        if preserve_session:
            with self._lock:
                cur = self._active_stream
                cur_alive = (
                    cur is not None
                    and not cur.stop_ev.is_set()
                    and cur.thread is not None
                    and cur.thread.is_alive()
                )
                if cur_alive and cur is not None:
                    if cur.serial == clean_serial:
                        return
                    if tee and self._tee_writer is None:
                        self._tee_writer = _PcapTeeWriter(self.captures_dir)
                    self._next_gen += 1
                    new_gen = self._next_gen
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        bufsize=0,
                    )
                    new_stream = _AdbStream(
                        gen=new_gen,
                        serial=clean_serial,
                        proc=proc,
                        stop_ev=threading.Event(),
                        handoff_from=cur,
                        promoted=False,
                    )
                    self._extra_streams.append(new_stream)
                    t = threading.Thread(
                        target=self._run_adb_worker,
                        args=(new_stream,),
                        name="chat-viewer-adb-switch",
                        daemon=True,
                    )
                    new_stream.thread = t
                    t.start()
                    old_serial = cur.serial
                    self.store.set_capture_state(
                        alive=True,
                        source_mode="LIVE (adb)",
                        source_detail=f"{old_serial} -> switching to {clean_serial}...",
                        error=None,
                        active_serial=old_serial,
                        switching_to=clean_serial,
                    )
                    return

        # Either fresh start (`preserve_session=False`) or resume after previous stream stopped.
        self.stop()
        with self._lock:
            self._stop_event = threading.Event()
            if not preserve_session:
                self.router.reset()
                self.store.reset_for_new_source("LIVE (adb)", clean_serial)
            if tee:
                self._tee_writer = _PcapTeeWriter(self.captures_dir)
            self._next_gen += 1
            new_gen = self._next_gen
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
            stream = _AdbStream(
                gen=new_gen,
                serial=clean_serial,
                proc=proc,
                stop_ev=threading.Event(),
                handoff_from=None,
                promoted=True,
            )
            self._active_gen = new_gen
            self._active_stream = stream
            self._proc = proc
            self._is_live_mode = True
            t = threading.Thread(
                target=self._run_adb_worker,
                args=(stream,),
                name="chat-viewer-adb",
                daemon=True,
            )
            stream.thread = t
            self._thread = t
            t.start()
        self.store.set_capture_state(
            alive=True,
            source_mode="LIVE (adb)",
            source_detail=clean_serial,
            error=None,
            active_serial=clean_serial,
            switching_to=None,
        )

    def _promote_stream(self, stream: _AdbStream) -> None:
        old_stream: _AdbStream | None = None
        with self._lock:
            if stream.stop_ev.is_set() or stream.promoted:
                return
            stream.promoted = True
            old_stream = stream.handoff_from
            self._active_gen = stream.gen
            self._active_stream = stream
            self._proc = stream.proc
            self._thread = stream.thread
            if stream in self._extra_streams:
                self._extra_streams.remove(stream)
            if old_stream is not None and old_stream not in self._extra_streams:
                self._extra_streams.append(old_stream)
            tee_name = self._tee_writer.current_name() if self._tee_writer is not None else None

        detail = f"{stream.serial}" + (f" -> {tee_name}" if tee_name else "")
        self.store.set_capture_state(
            alive=True,
            source_mode="LIVE (adb)",
            source_detail=detail,
            error=None,
            active_serial=stream.serial,
            switching_to=None,
        )
        if old_stream is not None:
            timer = threading.Timer(self.handoff_overlap_seconds, self._terminate_stream, args=(old_stream,))
            timer.daemon = True
            with self._lock:
                old_stream.timer = timer
            timer.start()

    def _run_pcap_worker(self, pcap_path: Path, follow: bool, stop_ev: threading.Event) -> None:
        reader = IncrementalPcapReader()
        mode = "FOLLOW (file)" if follow else "REPLAY (file)"
        last_flush = time.monotonic()
        last_sig: tuple[Any, ...] = ()
        try:
            with pcap_path.open("rb") as fh:
                while not stop_ev.is_set():
                    chunk = fh.read(65536)
                    if chunk:
                        packets = reader.feed(chunk)
                        for pkt in packets:
                            if stop_ev.is_set():
                                break
                            self.router.on_packet(pkt, skipped_truncated=reader.skipped_truncated)
                        if follow:
                            last_flush, last_sig = self._maybe_flush_live(last_flush, last_sig)
                        continue
                    if not follow:
                        break
                    last_flush, last_sig = self._maybe_flush_live(last_flush, last_sig)
                    stop_ev.wait(0.05)
        except InvalidPcapMagicError as exc:
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=str(exc))
            return
        except OSError as exc:
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=str(exc))
            return
        finally:
            if follow:
                self._maybe_flush_live(last_flush, last_sig, force=True)

        self.store.set_capture_state(alive=False, source_mode=mode)

    def _run_adb_worker(self, stream: _AdbStream) -> None:
        reader = IncrementalPcapReader()
        proc = stream.proc
        stop_ev = stream.stop_ev
        first_chunk = True
        promoted_notified = stream.promoted
        tee_name_reported = False
        last_flush = time.monotonic()
        last_sig: tuple[Any, ...] = ()
        fail_reason: str | None = None

        def _on_record(raw_rec: bytes) -> None:
            nonlocal promoted_notified, tee_name_reported
            if not promoted_notified:
                promoted_notified = True
                if stream.handoff_from is not None:
                    self._promote_stream(stream)
            with self._lock:
                is_active = self._active_gen == stream.gen
                tee_w = self._tee_writer
            if is_active and tee_w is not None and reader.global_header:
                tee_w.write_record(reader.global_header, raw_rec)
                if not tee_name_reported:
                    tname = tee_w.current_name()
                    if tname:
                        tee_name_reported = True
                        self.store.set_capture_state(
                            alive=True,
                            source_mode="LIVE (adb)",
                            source_detail=f"{stream.serial} -> {tname}",
                        )

        try:
            stdout = proc.stdout
            if stdout is None:
                fail_reason = "adb process opened without stdout pipe"
                return
            while not stop_ev.is_set():
                chunk = stdout.read1(16384) if hasattr(stdout, "read1") else stdout.read(4096)
                if not chunk:
                    break
                if first_chunk:
                    first_chunk = False
                packets = reader.feed(chunk, on_record=_on_record)
                if reader.header_parsed and not promoted_notified:
                    promoted_notified = True
                    if stream.handoff_from is not None:
                        self._promote_stream(stream)
                for pkt in packets:
                    if stop_ev.is_set():
                        break
                    self.router.on_packet(pkt, skipped_truncated=reader.skipped_truncated)
                last_flush, last_sig = self._maybe_flush_live(last_flush, last_sig)
        except InvalidPcapMagicError as exc:
            fail_reason = f"Invalid live PCAP magic from adb exec-out: {exc}"
        except OSError as exc:
            fail_reason = str(exc)
        finally:
            if fail_reason is None and not stop_ev.is_set():
                rc = proc.poll()
                stderr_txt = ""
                if proc.stderr is not None:
                    try:
                        stderr_txt = proc.stderr.read().decode("utf-8", "replace").strip()
                    except OSError:
                        pass
                if first_chunk or not reader.header_parsed or (rc not in (None, 0)):
                    fail_reason = stderr_txt or f"tcpdump stream ended before valid PCAP header (exit={rc})"
                elif stderr_txt:
                    fail_reason = stderr_txt

            with self._lock:
                is_current = self._active_stream is stream
                fallback_stream = self._active_stream
                if stream in self._extra_streams:
                    self._extra_streams.remove(stream)
                if is_current:
                    self._active_stream = None
                    self._active_gen = 0
                    self._proc = None
                    self._thread = None
                    self._is_live_mode = False

            if not stream.promoted:
                # Candidate hot-switch stream failed before promotion: keep previous stream alive!
                if not stop_ev.is_set() and fallback_stream is not None and not fallback_stream.stop_ev.is_set():
                    detail = fail_reason or "switch stream exited before PCAP header"
                    tee_name = self._tee_writer.current_name() if self._tee_writer is not None else None
                    keep_detail = f"{fallback_stream.serial}" + (f" -> {tee_name}" if tee_name else "")
                    self.store.set_capture_state(
                        alive=True,
                        source_mode="LIVE (adb)",
                        source_detail=keep_detail,
                        active_serial=fallback_stream.serial,
                        switching_to=None,
                        error=f"Switch to {stream.serial} failed: {detail}",
                    )
            elif is_current:
                self._maybe_flush_live(last_flush, last_sig, force=True)
                self._close_tee_and_notify()
                if stop_ev.is_set():
                    self.store.set_capture_state(
                        alive=False,
                        source_mode="CAPTURE STOPPED",
                        switching_to=None,
                    )
                else:
                    self.store.set_capture_state(
                        alive=False,
                        source_mode="CAPTURE STOPPED",
                        error=fail_reason,
                        switching_to=None,
                    )
