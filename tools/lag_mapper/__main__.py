"""CLI entrypoint for `python -m tools.lag_mapper`."""

from __future__ import annotations

import argparse
import threading
import webbrowser
from pathlib import Path
from typing import Sequence

from tools.chat_viewer.templates import DEFAULT_TEMPLATES_PATH

from .aggregator import DEFAULT_CAPTURES_DIR, DEFAULT_DATA_DIR
from .server import DEFAULT_PORT, LOOPBACK_HOST, pick_loopback_port, run_server


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI parser for the localhost FIxLag Server & Live Packet Mapper."""
    ap = argparse.ArgumentParser(
        prog="python -m tools.lag_mapper",
        description="Localhost-only (127.0.0.1) passive MLBB Server Map & Live Packet Mapper",
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--pcap", type=Path, help="Replay or follow an archived .pcap file")
    src.add_argument("--serial", metavar="SERIAL", help="Live stream via adb -s <SERIAL> exec-out tcpdump")
    ap.add_argument("--follow", action="store_true", help="Keep tailing --pcap as new packets arrive")
    ap.add_argument("--tee", action="store_true", help="Tee live --serial bytes to captures/live_lag_<ts>.pcap")
    ap.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"Localhost port on 127.0.0.1 (default: {DEFAULT_PORT}; auto-picks next free port if busy)",
    )
    ap.add_argument("--captures-dir", type=Path, default=DEFAULT_CAPTURES_DIR, help="Directory holding .pcap files")
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="Directory holding matches.csv, cache, and notes")
    ap.add_argument("--templates", type=Path, default=DEFAULT_TEMPLATES_PATH, help="Optional chat_templates.json path")
    ap.add_argument("--adb-path", type=Path, default=None, help="Override path to adb executable")
    ap.add_argument("--no-browser", action="store_true", help="Do not open a browser window automatically")
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, optionally open browser, and launch the 127.0.0.1 server."""
    args = build_arg_parser().parse_args(argv)
    if args.follow and not args.pcap:
        raise SystemExit("--follow requires --pcap <path>")
    if args.tee and not args.serial:
        raise SystemExit("--tee requires --serial <serial>")

    if args.port is None:
        try:
            chosen_port = pick_loopback_port(DEFAULT_PORT, allow_fallback=True)
        except OSError as exc:
            raise SystemExit(str(exc)) from exc
        if chosen_port != DEFAULT_PORT:
            print(f"Port {DEFAULT_PORT} is already in use; starting on http://{LOOPBACK_HOST}:{chosen_port}/")
    else:
        try:
            chosen_port = pick_loopback_port(args.port, allow_fallback=False)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        except OSError as exc:
            raise SystemExit(
                f"Port {args.port} is already in use on {LOOPBACK_HOST}. "
                "Omit --port to auto-pick a free port, or pass another --port."
            ) from exc

    initial_source: dict[str, object] | None = None
    if args.pcap:
        initial_source = {"mode": "pcap", "path": str(args.pcap), "follow": bool(args.follow)}
    elif args.serial:
        initial_source = {"mode": "adb", "serial": str(args.serial), "tee": bool(args.tee)}

    timer: threading.Timer | None = None
    if not args.no_browser:
        url = f"http://{LOOPBACK_HOST}:{chosen_port}/"
        timer = threading.Timer(0.6, webbrowser.open, args=(url,))
        timer.daemon = True
        timer.start()

    try:
        run_server(
            host=LOOPBACK_HOST,
            port=chosen_port,
            captures_dir=args.captures_dir,
            data_dir=args.data_dir,
            templates_path=args.templates,
            initial_source=initial_source,
            adb_path=args.adb_path,
        )
    finally:
        if timer is not None:
            timer.cancel()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
