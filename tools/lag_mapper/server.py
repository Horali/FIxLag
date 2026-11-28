"""Localhost-only (127.0.0.1:8766) Starlette + Uvicorn REST and SSE server."""

from __future__ import annotations

import asyncio
import json
import socket
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.routing import Route

from tools.chat_viewer.templates import TemplateResolver

from .aggregator import DEFAULT_CAPTURES_DIR, DEFAULT_DATA_DIR, LagAggregator
from .classifier import CITY_CLUSTERS
from .ingest import LagIngestController, LiveStore, list_adb_devices
from tools.chat_viewer.ingest import adb_model_filter
from .ui import INDEX_HTML
from .wireless_adb import TRUSTED_SSIDS, disable_wireless_adb, ensure_wireless_adb

LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8766


def validate_loopback_host(host: str) -> str:
    """Strictly enforce `127.0.0.1` binding so passive mapper is never exposed on LAN."""
    if host != LOOPBACK_HOST:
        raise ValueError(f"Refusing non-loopback bind host {host!r}; only '127.0.0.1' is allowed")
    return host


def _can_bind_loopback(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind((LOOPBACK_HOST, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def pick_loopback_port(
    preferred_port: int = DEFAULT_PORT,
    *,
    allow_fallback: bool = True,
    max_tries: int = 20,
) -> int:
    """Return *preferred_port* if free on `127.0.0.1`, else probe subsequent ports when allowed."""
    if not (1 <= preferred_port <= 65535):
        raise ValueError(f"Port must be in 1..65535, got {preferred_port}")
    if _can_bind_loopback(preferred_port):
        return preferred_port
    if not allow_fallback:
        raise OSError(f"Port {preferred_port} is already in use on {LOOPBACK_HOST}")
    for offset in range(1, max(1, max_tries)):
        candidate = preferred_port + offset
        if candidate > 65535:
            break
        if _can_bind_loopback(candidate):
            return candidate
    raise OSError(f"No free loopback port found near {preferred_port} on {LOOPBACK_HOST}")


def _format_sse(event_id: int, event_name: str, data: dict[str, Any]) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    return f"id: {event_id}\nevent: {event_name}\ndata: {payload}\n\n"


def create_app(
    *,
    captures_dir: Path | None = None,
    data_dir: Path | None = None,
    templates_path: Path | None = None,
    initial_source: dict[str, Any] | None = None,
    heartbeat_interval: float = 1.0,
    adb_path: Path | str | None = None,
    auto_scan: bool = True,
) -> Starlette:
    """Build the Starlette ASGI app exposing `/`, `/events`, and `/api/*` endpoints."""
    cap_dir = Path(captures_dir) if captures_dir is not None else DEFAULT_CAPTURES_DIR
    d_dir = Path(data_dir) if data_dir is not None else DEFAULT_DATA_DIR
    templates = TemplateResolver(templates_path)
    store = LiveStore(templates=templates)

    def _notify_history() -> None:
        store.publish("history_updated", {"ts": time.time()})

    aggregator = LagAggregator(
        captures_dir=cap_dir,
        data_dir=d_dir,
        templates=templates,
        on_change=_notify_history,
    )
    ingest = LagIngestController(
        store=store,
        aggregator=aggregator,
        captures_dir=cap_dir,
        adb_path=adb_path,
    )

    async def index(_request: Request) -> HTMLResponse:
        return HTMLResponse(INDEX_HTML)

    async def api_overview(_request: Request) -> JSONResponse:
        return JSONResponse(aggregator.get_overview(store.get_status()))

    async def api_servers(_request: Request) -> JSONResponse:
        return JSONResponse({"servers": aggregator.get_servers(), "clusters": CITY_CLUSTERS})

    async def api_matches(_request: Request) -> JSONResponse:
        return JSONResponse({"matches": aggregator.get_matches(), "status": store.get_status()})

    async def api_correlations(_request: Request) -> JSONResponse:
        return JSONResponse(aggregator.get_correlations())

    async def api_live_packets(_request: Request) -> JSONResponse:
        return JSONResponse(store.get_live_packets())

    async def api_pcaps(_request: Request) -> JSONResponse:
        pcaps: list[dict[str, Any]] = []
        if cap_dir.is_dir():
            files = sorted(cap_dir.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)
            for p in files:
                st = p.stat()
                pcaps.append(
                    {
                        "name": p.name,
                        "path": str(p),
                        "size_bytes": st.st_size,
                        "mtime": st.st_mtime,
                    }
                )
        return JSONResponse({"pcaps": pcaps})

    async def api_devices(_request: Request) -> JSONResponse:
        return JSONResponse({"devices": list_adb_devices(adb_path)})

    async def api_adb_wireless(request: Request) -> JSONResponse:
        body: dict[str, Any] = {}
        try:
            parsed = await request.json()
            if isinstance(parsed, dict):
                body = parsed
        except ValueError:
            body = {}

        action = str(body.get("action") or "connect").strip().lower()
        if action == "connect":
            res = await asyncio.to_thread(ensure_wireless_adb, adb_path)
            return JSONResponse(res)
        if action == "disable":
            raw_serial = body.get("serial")
            serial_arg = str(raw_serial).strip() if raw_serial else None
            res = await asyncio.to_thread(disable_wireless_adb, adb_path, serial=serial_arg)
            return JSONResponse(res)
        return JSONResponse(
            {"error": f"Unknown wireless action {action!r}", "trusted_ssids": list(TRUSTED_SSIDS)},
            status_code=400,
        )

    async def api_source(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "JSON object required"}, status_code=400)

        mode = str(body.get("mode") or "").strip().lower()
        try:
            if mode == "stop":
                ingest.stop()
                store.set_capture_state(alive=False, source_mode="IDLE", source_detail="", error=None)
                return JSONResponse({"ok": True, "status": store.get_status()})

            if mode == "pcap":
                raw_path = body.get("path")
                if not raw_path:
                    return JSONResponse({"error": "Missing 'path'"}, status_code=400)
                follow = bool(body.get("follow", False))
                ingest.start_pcap(Path(str(raw_path)), follow=follow)
                return JSONResponse({"ok": True, "status": store.get_status()})

            if mode == "adb":
                serial = str(body.get("serial") or "").strip()
                if not serial:
                    return JSONResponse({"error": "Missing 'serial'"}, status_code=400)
                if adb_model_filter() and serial not in {
                    d["serial"] for d in await asyncio.to_thread(list_adb_devices, adb_path)
                }:
                    return JSONResponse(
                        {"error": f"{serial} is not the {adb_model_filter()} phone (FIXLAG_ADB_MODEL)"},
                        status_code=400,
                    )
                tee = bool(body.get("tee", False))
                ingest.start_adb(serial, tee=tee)
                return JSONResponse({"ok": True, "status": store.get_status()})

            return JSONResponse({"error": f"Unknown mode {mode!r}"}, status_code=400)
        except (FileNotFoundError, ValueError, OSError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def api_notes(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "JSON object required"}, status_code=400)

        match_key = str(body.get("match_key") or "").strip()
        if not match_key:
            return JSONResponse({"error": "Missing 'match_key'"}, status_code=400)

        try:
            saved = aggregator.save_note(
                match_key,
                host=body.get("host") if "host" in body else None,
                displayed_ping_ms=body.get("displayed_ping_ms") if "displayed_ping_ms" in body else None,
                note=body.get("note") if "note" in body else None,
            )
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        return JSONResponse({"ok": True, "match_key": match_key, "saved": saved})

    async def api_rescan(request: Request) -> JSONResponse:
        force = False
        try:
            body = await request.json()
            if isinstance(body, dict):
                force = bool(body.get("force", False))
        except ValueError:
            force = False
        scan = aggregator.start_background_scan(force=force)
        return JSONResponse({"ok": True, "scan": scan})

    async def sse_events(request: Request) -> StreamingResponse:
        raw_last = request.headers.get("last-event-id") or request.query_params.get("lastEventId")
        last_id: int | None = None
        if raw_last is not None and raw_last.strip():
            try:
                last_id = int(raw_last.strip())
            except ValueError:
                last_id = None

        once = request.query_params.get("once", "").strip().lower() in ("1", "true", "yes")
        max_events: int | None = None
        raw_max = request.query_params.get("max_events")
        if raw_max is not None and raw_max.strip():
            try:
                parsed_max = int(raw_max.strip())
                if parsed_max > 0:
                    max_events = parsed_max
            except ValueError:
                max_events = None

        loop = asyncio.get_running_loop()
        q, missed = store.subscribe(loop, last_event_id=last_id)

        async def event_stream():
            emitted = 0
            try:
                if last_id is None:
                    snap_id = store.allocate_event_id()
                    yield _format_sse(
                        snap_id,
                        "snapshot",
                        {
                            "overview": aggregator.get_overview(store.get_status()),
                            "live": store.get_live_packets(),
                        },
                    )
                    emitted += 1
                    if once or (max_events is not None and emitted >= max_events):
                        return
                else:
                    for eid, ename, edata in missed:
                        yield _format_sse(eid, ename, edata)
                        emitted += 1
                        if max_events is not None and emitted >= max_events:
                            return
                    hb_id = store.allocate_event_id()
                    yield _format_sse(hb_id, "status", store.get_status())
                    emitted += 1
                    if once or (max_events is not None and emitted >= max_events):
                        return

                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        eid, ename, edata = await asyncio.wait_for(q.get(), timeout=heartbeat_interval)
                        yield _format_sse(eid, ename, edata)
                    except asyncio.TimeoutError:
                        hb_id = store.allocate_event_id()
                        yield _format_sse(hb_id, "status", store.get_status())
                    emitted += 1
                    if max_events is not None and emitted >= max_events:
                        break
            except asyncio.CancelledError:
                return
            finally:
                store.unsubscribe(loop, q)

        headers = {
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
        return StreamingResponse(event_stream(), media_type="text/event-stream", headers=headers)

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        if auto_scan:
            aggregator.start_background_scan(force=False)
        if initial_source:
            mode = str(initial_source.get("mode") or "").lower()
            if mode == "pcap" and initial_source.get("path"):
                ingest.start_pcap(
                    Path(str(initial_source["path"])),
                    follow=bool(initial_source.get("follow", False)),
                )
            elif mode == "adb" and initial_source.get("serial"):
                ingest.start_adb(
                    str(initial_source["serial"]),
                    tee=bool(initial_source.get("tee", False)),
                )
        try:
            yield
        finally:
            ingest.stop()
            aggregator.stop_scan()

    app = Starlette(
        debug=False,
        routes=[
            Route("/", index, methods=["GET"]),
            Route("/events", sse_events, methods=["GET"]),
            Route("/api/overview", api_overview, methods=["GET"]),
            Route("/api/servers", api_servers, methods=["GET"]),
            Route("/api/matches", api_matches, methods=["GET"]),
            Route("/api/correlations", api_correlations, methods=["GET"]),
            Route("/api/live/packets", api_live_packets, methods=["GET"]),
            Route("/api/pcaps", api_pcaps, methods=["GET"]),
            Route("/api/devices", api_devices, methods=["GET"]),
            Route("/api/adb/wireless", api_adb_wireless, methods=["POST"]),
            Route("/api/source", api_source, methods=["POST"]),
            Route("/api/notes", api_notes, methods=["POST"]),
            Route("/api/rescan", api_rescan, methods=["POST"]),
        ],
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.aggregator = aggregator
    app.state.ingest = ingest
    return app


def run_server(
    *,
    host: str = LOOPBACK_HOST,
    port: int = DEFAULT_PORT,
    captures_dir: Path | None = None,
    data_dir: Path | None = None,
    templates_path: Path | None = None,
    initial_source: dict[str, Any] | None = None,
    adb_path: Path | str | None = None,
    auto_scan: bool = True,
) -> None:
    """Run Uvicorn strictly on `127.0.0.1`."""
    safe_host = validate_loopback_host(host)
    app = create_app(
        captures_dir=captures_dir,
        data_dir=data_dir,
        templates_path=templates_path,
        initial_source=initial_source,
        adb_path=adb_path,
        auto_scan=auto_scan,
    )
    uvicorn.run(app, host=safe_host, port=port, log_level="info")
