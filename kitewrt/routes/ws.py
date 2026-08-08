"""WebSocket push channel — GET /ws.

The browser opens one socket; kitewrt pushes `state` frames (the full snapshot,
on every change — so toggle / server-switch feedback is instant without
polling) and `metrics` frames (pumped ~1/s regardless of the VPN — with it off
the frame is `available: false` carrying the router's own system numbers).
The metrics pump and the state listener both live in the lifespan
(`kitewrt.api`); this endpoint just drains the per-connection queue to the wire.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from kitewrt.schemas import state_payload
from kitewrt.security import is_local_host

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
        # Prime with the current snapshot so the UI renders immediately.
        # Secret-redacted via `state_payload`, because this socket never passes
        # through the `/api` redaction middleware — the redaction has to be in
        # the payload builder, not the HTTP layer.
        await websocket.send_json({"type": "state", "data": state_payload(state.snapshot())})
        # Prime with the latest metrics frame too (server-cached). This is
        # what makes the dashboard render with rates immediately on page
        # reload instead of waiting up to a second for the next pump tick —
        # and the frame carries the 30 s history, so the "peak · 30s" figures
        # are populated at once rather than after 30 seconds of warm-up.
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
            # Retrieve the exception of whichever task already finished on its
            # own (e.g. watch() raising WebSocketDisconnect) so asyncio doesn't
            # log "Task exception was never retrieved" when it's GC'd. Done
            # synchronously (no await): adding an await point here would let a
            # shutdown-time cancellation propagate out of the handler. The
            # just-cancelled task isn't `done()` yet and finishes as a
            # CancelledError, which never triggers that warning.
            for t in tasks:
                if t.done() and not t.cancelled():
                    t.exception()
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.debug("ws closed", exc_info=True)
    finally:
        hub.unregister(queue)
