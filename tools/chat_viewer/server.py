"""Localhost-only (127.0.0.1) Starlette + Uvicorn web & SSE server."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.routing import Route

from .ingest import IngestController, list_adb_devices
from .session import MatchStore, SessionRouter
from .templates import TemplateResolver
from .ui import INDEX_HTML

LOOPBACK_HOST = "127.0.0.1"
DEFAULT_CAPTURES_DIR = Path(__file__).resolve().parents[2] / "captures"


def validate_loopback_host(host: str) -> str:
    """Strictly enforce `127.0.0.1` binding so passive viewer is never exposed on LAN."""
    if host != LOOPBACK_HOST:
        raise ValueError(f"Refusing non-loopback bind host {host!r}; only '127.0.0.1' is allowed")
    return host


def _format_sse(event_id: int, event_name: str, data: dict[str, Any]) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    return f"id: {event_id}\nevent: {event_name}\ndata: {payload}\n\n"


def create_app(
    *,
    captures_dir: Path | None = None,
    templates_path: Path | None = None,
    initial_source: dict[str, Any] | None = None,
    heartbeat_interval: float = 1.0,
    adb_path: Path | str | None = None,
) -> Starlette:
    """Build the Starlette ASGI app exposing `/`, `/events`, and JSON control/status APIs."""
    cap_dir = Path(captures_dir) if captures_dir is not None else DEFAULT_CAPTURES_DIR
    templates = TemplateResolver(templates_path)
    store = MatchStore()
    router = SessionRouter(store=store, templates=templates)
    ingest = IngestController(router=router, store=store, captures_dir=cap_dir, adb_path=adb_path)

    async def index(_request: Request) -> HTMLResponse:
        return HTMLResponse(INDEX_HTML)

    async def api_matches(_request: Request) -> JSONResponse:
        return JSONResponse({"matches": store.get_matches_snapshot(), "status": store.get_status()})

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
                store.set_capture_state(alive=False, source_mode="IDLE", error=None)
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
                tee = bool(body.get("tee", False))
                ingest.start_adb(serial, tee=tee)
                return JSONResponse({"ok": True, "status": store.get_status()})

            return JSONResponse({"error": f"Unknown mode {mode!r}"}, status_code=400)
        except (FileNotFoundError, ValueError, OSError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def sse_events(request: Request) -> StreamingResponse:
        raw_last = request.headers.get("last-event-id") or request.query_params.get("lastEventId")
        last_id: int | None = None
        if raw_last is not None and raw_last.strip():
            try:
                last_id = int(raw_last.strip())
            except ValueError:
                last_id = None

        loop = asyncio.get_running_loop()
        q, missed = store.subscribe(loop, last_event_id=last_id)

        async def event_stream():
            try:
                if last_id is None:
                    snap_id = store.allocate_event_id()
                    yield _format_sse(
                        snap_id,
                        "snapshot",
                        {"matches": store.get_matches_snapshot(), "status": store.get_status()},
                    )
                else:
                    for eid, ename, edata in missed:
                        yield _format_sse(eid, ename, edata)
                    hb_id = store.allocate_event_id()
                    yield _format_sse(hb_id, "status", store.get_status())

                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        eid, ename, edata = await asyncio.wait_for(q.get(), timeout=heartbeat_interval)
                        yield _format_sse(eid, ename, edata)
                    except asyncio.TimeoutError:
                        hb_id = store.allocate_event_id()
                        yield _format_sse(hb_id, "status", store.get_status())
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
        if initial_source:
            mode = str(initial_source.get("mode") or "").lower()
            if mode == "pcap" and initial_source.get("path"):
                ingest.start_pcap(Path(str(initial_source["path"])), follow=bool(initial_source.get("follow", False)))
            elif mode == "adb" and initial_source.get("serial"):
                ingest.start_adb(str(initial_source["serial"]), tee=bool(initial_source.get("tee", False)))
        try:
            yield
        finally:
            ingest.stop()

    app = Starlette(
        debug=False,
        routes=[
            Route("/", index, methods=["GET"]),
            Route("/events", sse_events, methods=["GET"]),
            Route("/api/matches", api_matches, methods=["GET"]),
            Route("/api/pcaps", api_pcaps, methods=["GET"]),
            Route("/api/devices", api_devices, methods=["GET"]),
            Route("/api/source", api_source, methods=["POST"]),
        ],
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.router = router
    app.state.ingest = ingest
    return app


def run_server(
    *,
    host: str = LOOPBACK_HOST,
    port: int = 8765,
    captures_dir: Path | None = None,
    templates_path: Path | None = None,
    initial_source: dict[str, Any] | None = None,
    adb_path: Path | str | None = None,
) -> None:
    """Run Uvicorn bound strictly to `127.0.0.1`."""
    safe_host = validate_loopback_host(host)
    app = create_app(
        captures_dir=captures_dir,
        templates_path=templates_path,
        initial_source=initial_source,
        adb_path=adb_path,
    )
    uvicorn.run(app, host=safe_host, port=port, log_level="info")
