"""Tests for auto-select-fastest — the proxy delay-test ranking (kitewrt
.autoselect) and the POST /api/subscriptions/{id}/auto-select route.

The module tests drive rank_by_delay/pick_fastest against a fake Clash client
(no sing-box). The route tests build the app in test mode and override get_clash
with that fake, mirroring how test_api wires a fake controller for /metrics.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import httpx
import pytest
from kitewrt.api import create_app
from kitewrt.autoselect import pick_fastest, rank_by_delay
from kitewrt.deps import get_clash, get_dataplane
from kitewrt.state import State
from kitewrt.vless import Server


class FakePipeline:
    def __init__(self):
        self.signals = 0

    def signal(self) -> None:
        self.signals += 1


class FakeClash:
    """delay() looks up a canned ms (or None) by the server_id half of the
    composite outbound tag, and records every tag it was asked about."""

    def __init__(self, by_server_id: dict[str, int | None]):
        self._delays = by_server_id
        self.calls: list[str] = []

    async def delay(self, name: str, *, url: str | None = None, timeout_ms: int = 5000):
        self.calls.append(name)
        server_id = name.split("/", 1)[1]  # tag = "<sub_id>/<host:port>"
        return self._delays.get(server_id)


def _servers(n: int) -> list[Server]:
    return [
        Server(id=f"h{i}.example:443", name=f"S{i}", country="DE", host=f"h{i}.example", port=443)
        for i in range(n)
    ]


# --- rank_by_delay / pick_fastest -------------------------------------------


async def test_rank_by_delay_keys_by_server_id_and_tags_outbound():
    servers = _servers(3)
    clash = FakeClash({"h0.example:443": 300, "h1.example:443": 120, "h2.example:443": None})
    out = await rank_by_delay(clash, "sub-xyz", servers)
    # Keyed by server_id (ready for merge_pings), values pass through.
    assert out == {"h0.example:443": 300, "h1.example:443": 120, "h2.example:443": None}
    # Each was probed by its composite tag "<sub_id>/<server_id>".
    assert set(clash.calls) == {f"sub-xyz/{s.id}" for s in servers}


async def test_rank_by_delay_passes_timeout():
    seen = {}

    class Probe:
        async def delay(self, name, *, url=None, timeout_ms=5000):
            seen["timeout_ms"] = timeout_ms
            return 10

    await rank_by_delay(Probe(), "sub-1", _servers(1), timeout_ms=1500)
    assert seen["timeout_ms"] == 1500


async def test_rank_by_delay_respects_concurrency():
    inflight = 0
    peak = 0

    class Counting:
        async def delay(self, name, *, url=None, timeout_ms=5000):
            nonlocal inflight, peak
            inflight += 1
            peak = max(peak, inflight)
            await asyncio.sleep(0.01)  # hold the slot so overlap is observable
            inflight -= 1
            return 100

    await rank_by_delay(Counting(), "sub-1", _servers(20), concurrency=4)
    assert peak <= 4


def test_pick_fastest_returns_lowest():
    assert pick_fastest({"a": 300, "b": 120, "c": 900}) == "b"


def test_pick_fastest_ignores_failed_nodes():
    assert pick_fastest({"a": None, "b": 250, "c": None}) == "b"


def test_pick_fastest_none_when_all_failed():
    assert pick_fastest({"a": None, "b": None}) is None


def test_pick_fastest_none_on_empty():
    assert pick_fastest({}) is None


# --- POST /auto-select route ------------------------------------------------


class FakeDataPlane:
    """Records ensure_materialized calls; scriptable success/failure."""

    def __init__(self, result: tuple[bool, str] = (True, "")):
        self.result = result
        self.ensured = 0

    async def ensure_materialized(self, snap):
        self.ensured += 1
        return self.result


@asynccontextmanager
async def _client(
    state: State, pipeline: FakePipeline, clash: object | None, dataplane: object | None = None
):
    fetcher = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    app = create_app(state, pipeline, fetcher)
    if clash is not None:
        app.dependency_overrides[get_clash] = lambda: clash
    if dataplane is not None:
        app.dependency_overrides[get_dataplane] = lambda: dataplane
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        await fetcher.aclose()


async def _seed(state: State, n: int = 3) -> tuple[str, list[str]]:
    servers = _servers(n)
    snap = await state.add_subscription("L", "https://sub.example/x", servers)
    return snap.subscriptions[0].id, [s.id for s in servers]


async def test_auto_select_switches_to_fastest_and_signals(tmp_path):
    state = State(tmp_path / "s.json")
    sub_id, ids = await _seed(state, 3)
    pipeline = FakePipeline()
    # ids[1] is fastest (120); ids[2] is down.
    clash = FakeClash({ids[0]: 300, ids[1]: 120, ids[2]: None})
    async with _client(state, pipeline, clash) as c:
        r = await c.post(f"/api/subscriptions/{sub_id}/auto-select")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["active_server"] == {"subscription_id": sub_id, "server_id": ids[1]}
    assert body["applying"] is True
    # Badges persisted for every server, including the down one.
    assert body["pings"][ids[0]]["ms"] == 300
    assert body["pings"][ids[2]]["ms"] is None
    assert pipeline.signals == 1  # the live selector switch


async def test_auto_select_materializes_before_testing(tmp_path):
    # With a data plane wired, the route must materialize (ensure outbounds are
    # live) before delay-testing, so a just-added sub still works.
    state = State(tmp_path / "s.json")
    sub_id, ids = await _seed(state, 2)
    pipeline = FakePipeline()
    clash = FakeClash({ids[0]: 200, ids[1]: 90})
    dp = FakeDataPlane()
    async with _client(state, pipeline, clash, dp) as c:
        r = await c.post(f"/api/subscriptions/{sub_id}/auto-select")
    assert r.status_code == 200, r.text
    assert dp.ensured == 1  # materialized first
    assert r.json()["active_server"]["server_id"] == ids[1]


async def test_auto_select_materialize_failure_returns_503(tmp_path):
    state = State(tmp_path / "s.json")
    sub_id, _ = await _seed(state, 1)
    pipeline = FakePipeline()
    dp = FakeDataPlane((False, "sing-box: config error"))
    async with _client(state, pipeline, FakeClash({}), dp) as c:
        r = await c.post(f"/api/subscriptions/{sub_id}/auto-select")
        assert r.status_code == 503
        st = (await c.get("/api/state")).json()
    # Materialize failed before any ranking → nothing changed, nothing signaled.
    assert st["active_server"] is None
    assert pipeline.signals == 0


async def test_auto_select_unknown_sub_404(tmp_path):
    state = State(tmp_path / "s.json")
    async with _client(state, FakePipeline(), FakeClash({})) as c:
        r = await c.post("/api/subscriptions/ghost/auto-select")
    assert r.status_code == 404


async def test_auto_select_all_down_returns_502_and_keeps_selection(tmp_path):
    state = State(tmp_path / "s.json")
    sub_id, ids = await _seed(state, 2)
    pipeline = FakePipeline()
    clash = FakeClash({ids[0]: None, ids[1]: None})
    async with _client(state, pipeline, clash) as c:
        r = await c.post(f"/api/subscriptions/{sub_id}/auto-select")
        assert r.status_code == 502
        # No active server set, no apply nudged — but the badges were recorded.
        st = (await c.get("/api/state")).json()
    assert st["active_server"] is None
    assert pipeline.signals == 0
    assert st["pings"][ids[0]]["ms"] is None


async def test_auto_select_no_clash_returns_503(tmp_path):
    # Test mode without a clash override → get_clash returns None → 503.
    state = State(tmp_path / "s.json")
    sub_id, _ = await _seed(state, 1)
    async with _client(state, FakePipeline(), None) as c:
        r = await c.post(f"/api/subscriptions/{sub_id}/auto-select")
    assert r.status_code == 503


async def test_auto_select_empty_subscription_400(tmp_path):
    state = State(tmp_path / "s.json")
    snap = await state.add_subscription("empty", "https://sub.example/x", [])
    sub_id = snap.subscriptions[0].id
    async with _client(state, FakePipeline(), FakeClash({})) as c:
        r = await c.post(f"/api/subscriptions/{sub_id}/auto-select")
    assert r.status_code == 400
