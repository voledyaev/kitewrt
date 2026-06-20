"""WebSocket push channel — GET /ws.

The browser opens one socket; kitewrt pushes `state` frames (the full snapshot,
on every change — so toggle / server-switch feedback is instant without
polling) and `metrics` frames (live Clash stats, pumped ~1/s while the VPN is
on). The metrics pump and the state listener both live in the lifespan
(`kitewrt.api`); this endpoint just drains the per-connection queue to the wire.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from kitewrt.security import is_local_host
from kitewrt.state import redacted_state_dict

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    app = websocket.app
    hub = getattr(app.state, "kitewrt_hub", None)
    state = getattr(app.state, "kitewrt_state", None)
    metrics_store = getattr(app.state, "kitewrt_metrics_store", None)
    if hub is None or state is None:
        await websocket.close(code=1011)
        return

    # The WebSocket handshake is NOT subject to same-origin policy and the HTTP
    # `_guard` middleware doesn't intercept the websocket scope, so mirror its
    # rebinding + cross-origin defense here: reject a non-local Host, then a
    # cross-origin Origin. A same-origin SPA passes both; a non-browser client
    # sends neither header.
    if not is_local_host(websocket.headers.get("host", "")):
        await websocket.close(code=1008)
        return
    origin = websocket.headers.get("origin")
    if origin is not None and urlparse(origin).netloc != websocket.headers.get("host", ""):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    queue = hub.register()
    try:
        # Prime with the current snapshot so the UI renders immediately
        # (secret-redacted — the WS bypasses CORS).
        await websocket.send_json({"type": "state", "data": redacted_state_dict(state.snapshot())})
        # Prime with the latest metrics frame too (server-cached). This is
        # what makes the dashboard render with rates + sparkline immediately
        # on page reload instead of waiting up to a second for the next
        # pump tick — and the sparkline starts populated rather than after
        # 30 seconds of warm-up.
        if metrics_store is not None:
            latest = metrics_store.latest_frame()
            if latest is not None:
                await websocket.send_json({"type": "metrics", "data": latest})

        async def pump() -> None:
            while True:
                msg = await queue.get()
                await websocket.send_json(msg)

        async def watch() -> None:
            # We don't expect client messages; this only detects disconnect.
            while True:
                await websocket.receive_text()

        tasks = [asyncio.create_task(pump()), asyncio.create_task(watch())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 — never let a socket error escape the handler
        logger.debug("ws closed", exc_info=True)
    finally:
        hub.unregister(queue)
