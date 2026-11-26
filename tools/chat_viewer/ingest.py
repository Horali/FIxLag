"""Live ADB tcpdump pipe and local PCAP file/follow ingest running on a dedicated thread."""

from __future__ import annotations

import datetime
import shutil
import subprocess
import threading
from pathlib import Path

from .pcap_reader import IncrementalPcapReader, InvalidPcapMagicError
from .session import MatchStore, SessionRouter

DEFAULT_ADB_PATH = Path(r"C:\Users\child\AppData\Local\Android\Sdk\platform-tools\adb.exe")
DEFAULT_BPF = "udp portrange 5000-5999 and not port 5353"


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
        info: dict[str, str] = {"serial": serial, "state": state, "model": "", "device": ""}
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


class IngestController:
    """Manages a single background reader thread feeding `IncrementalPcapReader` -> `SessionRouter`."""

    def __init__(
        self,
        router: SessionRouter,
        store: MatchStore,
        captures_dir: Path,
        adb_path: Path | str | None = None,
    ) -> None:
        self.router = router
        self.store = store
        self.captures_dir = Path(captures_dir)
        self.adb_path_override = adb_path
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen[bytes] | None = None

    def stop(self, timeout: float = 3.0) -> None:
        """Stop any running PCAP or ADB ingest thread and terminate child processes."""
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
            self.router.reset()
            mode = "FOLLOW (file)" if follow else "REPLAY (file)"
            self.store.reset_for_new_source(mode, str(pcap_path))
            t = threading.Thread(
                target=self._run_pcap_worker,
                args=(pcap_path, follow, stop_ev),
                name="chat-viewer-pcap",
                daemon=True,
            )
            self._thread = t
            t.start()

    def start_adb(self, serial: str, tee: bool = False) -> None:
        """Start binary-clean live `adb exec-out` tcpdump streaming on a background thread."""
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
            tee_path = self.captures_dir / f"live_{stamp}.pcap"

        cmd = build_adb_tcpdump_command(adb, clean_serial)
        with self._lock:
            self._stop_event = threading.Event()
            stop_ev = self._stop_event
            self.router.reset()
            self.store.reset_for_new_source("LIVE (adb)", f"{clean_serial}" + (f" -> {tee_path.name}" if tee_path else ""))
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
            self._proc = proc
            t = threading.Thread(
                target=self._run_adb_worker,
                args=(proc, tee_path, stop_ev),
                name="chat-viewer-adb",
                daemon=True,
            )
            self._thread = t
            t.start()

    def _run_pcap_worker(self, pcap_path: Path, follow: bool, stop_ev: threading.Event) -> None:
        reader = IncrementalPcapReader()
        mode = "FOLLOW (file)" if follow else "REPLAY (file)"
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
                        continue
                    if not follow:
                        break
                    stop_ev.wait(0.05)
        except InvalidPcapMagicError as exc:
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=str(exc))
            return
        except OSError as exc:
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=str(exc))
            return

        self.store.set_capture_state(alive=False, source_mode=mode)

    def _run_adb_worker(
        self,
        proc: subprocess.Popen[bytes],
        tee_path: Path | None,
        stop_ev: threading.Event,
    ) -> None:
        reader = IncrementalPcapReader()
        tee_fh = None
        first_chunk = True
        try:
            if tee_path is not None:
                tee_fh = tee_path.open("wb")
            stdout = proc.stdout
            if stdout is None:
                self.store.set_capture_state(
                    alive=False,
                    source_mode="CAPTURE STOPPED",
                    error="adb process opened without stdout pipe",
                )
                return
            while not stop_ev.is_set():
                chunk = stdout.read1(16384) if hasattr(stdout, "read1") else stdout.read(4096)
                if not chunk:
                    break
                if first_chunk:
                    first_chunk = False
                packets = reader.feed(chunk)
                if tee_fh is not None:
                    tee_fh.write(chunk)
                    tee_fh.flush()
                for pkt in packets:
                    if stop_ev.is_set():
                        break
                    self.router.on_packet(pkt, skipped_truncated=reader.skipped_truncated)
        except InvalidPcapMagicError as exc:
            err_msg = f"Invalid live PCAP magic from adb exec-out: {exc}"
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=err_msg)
            return
        except OSError as exc:
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=str(exc))
            return
        finally:
            if tee_fh is not None:
                try:
                    tee_fh.close()
                except OSError:
                    pass

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
            detail = stderr_txt or f"tcpdump stream ended before valid PCAP header (exit={rc})"
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=detail)
        else:
            self.store.set_capture_state(alive=False, source_mode="CAPTURE STOPPED", error=stderr_txt or None)
