"""CLI entrypoint for `python -m tools.chat_viewer`."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .server import DEFAULT_CAPTURES_DIR, LOOPBACK_HOST, run_server
from .templates import DEFAULT_TEMPLATES_PATH


def build_arg_parser() -> argparse.ArgumentParser:
    """Create CLI parser for the localhost passive MLBB chat viewer."""
    ap = argparse.ArgumentParser(
        prog="python -m tools.chat_viewer",
        description="Localhost-only (127.0.0.1) passive live MLBB chat viewer",
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--pcap", type=Path, help="Replay an archived or growing .pcap file")
    src.add_argument("--adb", metavar="SERIAL", help="Live stream via adb -s <SERIAL> exec-out tcpdump")
    ap.add_argument("--follow", action="store_true", help="Keep tailing --pcap as new packets arrive")
    ap.add_argument("--tee", action="store_true", help="Tee live --adb bytes to captures/live_<ts>.pcap")
    ap.add_argument("--port", type=int, default=8765, help="Localhost port on 127.0.0.1 (default: 8765)")
    ap.add_argument("--captures-dir", type=Path, default=DEFAULT_CAPTURES_DIR, help="Directory holding .pcap files")
    ap.add_argument("--templates", type=Path, default=DEFAULT_TEMPLATES_PATH, help="Optional chat_templates.json path")
    ap.add_argument("--adb-path", type=Path, default=None, help="Override path to adb executable")
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and start the 127.0.0.1 web server."""
    args = build_arg_parser().parse_args(argv)
    if args.follow and not args.pcap:
        raise SystemExit("--follow requires --pcap <path>")
    if args.tee and not args.adb:
        raise SystemExit("--tee requires --adb <serial>")

    initial_source: dict[str, object] | None = None
    if args.pcap:
        initial_source = {"mode": "pcap", "path": str(args.pcap), "follow": bool(args.follow)}
    elif args.adb:
        initial_source = {"mode": "adb", "serial": str(args.adb), "tee": bool(args.tee)}

    run_server(
        host=LOOPBACK_HOST,
        port=args.port,
        captures_dir=args.captures_dir,
        templates_path=args.templates,
        initial_source=initial_source,
        adb_path=args.adb_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
