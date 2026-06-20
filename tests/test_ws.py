"""Tests for the WebSocket push channel: the Broadcaster hub, the State
change-listener hook, and the /ws endpoint (initial snapshot + pushed frames).
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from kitewrt.api import create_app
from kitewrt.hub import Broadcaster
from kitewrt.state import Data, State
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


class FakePipeline:
    def signal(self) -> None:
        pass


# --- Broadcaster ------------------------------------------------------------


async def test_hub_fans_out_to_all_clients():
    hub = Broadcaster()
    a, b = hub.register(), hub.register()
    hub.publish({"x": 1})
    assert a.get_nowait() == {"x": 1}
    assert b.get_nowait() == {"x": 1}


async def test_hub_unregister_stops_delivery():
    hub = Broadcaster()
    q = hub.register()
    hub.unregister(q)
    assert hub.has_clients is False
    hub.publish({"x": 1})
    assert q.empty()


async def test_hub_full_queue_drops_oldest():
    hub = Broadcaster()
    q = hub.register()
    for i in range(40):  # maxsize is 32
        hub.publish({"n": i})
    # Never raised; queue capped; latest frame retained (oldest dropped).
    drained = []
    while not q.empty():
        drained.append(q.get_nowait()["n"])
    assert len(drained) == 32
    assert drained[-1] == 39  # most recent kept


# --- State listener ---------------------------------------------------------


async def test_state_update_notifies_listeners(tmp_path):
    state = State(tmp_path / "state.json")
    seen: list[bool] = []
    state.add_listener(lambda snap: seen.append(snap.vpn_on))
    await state.update(lambda d: setattr(d, "vpn_on", True))
    assert seen == [True]


async def test_state_listener_exception_does_not_break_update(tmp_path):
    state = State(tmp_path / "state.json")

    def boom(_snap: Data) -> None:
        raise RuntimeError("listener boom")

    state.add_listener(boom)
    # The write still succeeds despite the bad listener.
    snap = await state.update(lambda d: setattr(d, "vpn_on", True))
    assert snap.vpn_on is True
    assert state.snapshot().vpn_on is True


# --- /ws endpoint -----------------------------------------------------------


@pytest.fixture
def fresh_loop():
    """A current event loop for the sync TestClient tests. On py3.9 State()'s
    `asyncio.Lock` binds to the current loop at construction, and a prior test's
    `asyncio.run()` leaves the current loop set to None (so `get_event_loop()`
    raises instead of auto-creating) — so each sync test needs its own loop set
    up front. Also used to close the async fetcher without a throwaway loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


def test_ws_initial_state_and_pushed_frames(tmp_path, fresh_loop):
    state = State(tmp_path / "state.json")
    fetcher = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    app = create_app(state, FakePipeline(), fetcher)
    hub = Broadcaster()
    app.state.kitewrt_hub = hub

    try:
        with TestClient(app) as client, client.websocket_connect("/ws") as sock:
            first = sock.receive_json()
            assert first["type"] == "state"
            assert first["data"]["vpn_on"] is False
            # Anything published to the hub reaches the socket.
            hub.publish({"type": "metrics", "data": {"available": True, "connections": 3}})
            frame = sock.receive_json()
            assert frame["type"] == "metrics"
            assert frame["data"]["connections"] == 3
    finally:
        fresh_loop.run_until_complete(fetcher.aclose())


def _ws_app(tmp_path):
    state = State(tmp_path / "state.json")
    fetcher = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    app = create_app(state, FakePipeline(), fetcher)
    app.state.kitewrt_hub = Broadcaster()
    return app, fetcher


def test_ws_rejects_cross_origin(tmp_path, fresh_loop):
    # A cross-origin page (Origin != Host) must be closed before accept — the WS
    # bypasses CORS, so this Origin check is the only thing stopping it reading
    # the broadcast.
    app, fetcher = _ws_app(tmp_path)
    try:
        with TestClient(app) as client, pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws", headers={"origin": "http://evil.example"}):
                pass
    finally:
        fresh_loop.run_until_complete(fetcher.aclose())


def test_ws_allows_same_origin(tmp_path, fresh_loop):
    app, fetcher = _ws_app(tmp_path)
    try:
        # Origin host == Host (TestClient's "testserver") → same-origin → allowed.
        with (
            TestClient(app) as client,
            client.websocket_connect("/ws", headers={"origin": "http://testserver"}) as sock,
        ):
            assert sock.receive_json()["type"] == "state"
    finally:
        fresh_loop.run_until_complete(fetcher.aclose())
