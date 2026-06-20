"""Tests for the subscription service (kitewrt.subscriptions) — fetch/parse +
the best-effort auto-refresh used by the background pump.

State is real (a tmp file); fetches go through an httpx MockTransport, and the
apply pipeline is a fake that just counts signals.
"""

from __future__ import annotations

import base64

import httpx
import pytest
from kitewrt.state import ActiveServerRef, State
from kitewrt.subscriptions import fetch_and_parse, refresh_all

_VLESS = (
    "vless://11111111-1111-1111-1111-111111111111@de.example.com:443"
    "?security=reality&pbk=k&sid=ab&sni=s&fp=chrome&flow=xtls-rprx-vision&type=tcp#DE"
)
_VLESS2 = (
    "vless://22222222-2222-2222-2222-222222222222@fi.example.com:443"
    "?security=reality&pbk=k&sid=cd&sni=s&fp=chrome&flow=xtls-rprx-vision&type=tcp#FI"
)


class FakePipeline:
    def __init__(self):
        self.signals = 0

    def signal(self) -> None:
        self.signals += 1


def _b64_sub(*uris: str) -> bytes:
    return base64.b64encode("\n".join(uris).encode())


def _fetcher(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# --- fetch_and_parse --------------------------------------------------------


async def test_fetch_and_parse_http_source():
    body = _b64_sub(_VLESS, _VLESS2)
    async with _fetcher(lambda r: httpx.Response(200, content=body)) as f:
        servers = await fetch_and_parse(f, "https://sub.example.com/x")
    assert {s.host for s in servers} == {"de.example.com", "fi.example.com"}


async def test_fetch_and_parse_inline_node_skips_fetch():
    called = False

    def handler(request):
        nonlocal called
        called = True
        return httpx.Response(200)

    async with _fetcher(handler) as f:
        servers = await fetch_and_parse(f, _VLESS)
    assert not called  # an inline node IS the source — no HTTP fetch
    assert len(servers) == 1 and servers[0].host == "de.example.com"


# --- refresh_all ------------------------------------------------------------


async def _seed_sub(state: State, source="https://sub.example.com/x"):
    """Add a subscription with one server, returning its id."""
    async with _fetcher(lambda r: httpx.Response(200, content=_b64_sub(_VLESS))) as f:
        servers = await fetch_and_parse(f, source)
    await state.add_subscription("L", source, servers)
    return state.snapshot().subscriptions[0].id


async def test_refresh_all_updates_servers(tmp_path):
    state = State(tmp_path / "s.json")
    await _seed_sub(state)
    pipeline = FakePipeline()
    # Source now returns TWO servers (the provider rotated/added one).
    async with _fetcher(lambda r: httpx.Response(200, content=_b64_sub(_VLESS, _VLESS2))) as f:
        n = await refresh_all(state, f, pipeline)
    assert n == 1
    servers = state.snapshot().subscriptions[0].servers
    assert {s.host for s in servers} == {"de.example.com", "fi.example.com"}


async def test_refresh_all_signals_only_when_active_sub_changes(tmp_path):
    state = State(tmp_path / "s.json")
    sub_id = await _seed_sub(state)
    # Make the de server active.
    srv_id = state.snapshot().subscriptions[0].servers[0].id
    await state.update(
        lambda d: setattr(
            d, "active_server", ActiveServerRef(subscription_id=sub_id, server_id=srv_id)
        )
    )
    pipeline = FakePipeline()
    async with _fetcher(lambda r: httpx.Response(200, content=_b64_sub(_VLESS, _VLESS2))) as f:
        await refresh_all(state, f, pipeline)
    assert pipeline.signals == 1  # active sub touched → apply nudged


async def test_refresh_all_no_signal_when_no_active(tmp_path):
    state = State(tmp_path / "s.json")
    await _seed_sub(state)  # no active server selected
    pipeline = FakePipeline()
    async with _fetcher(lambda r: httpx.Response(200, content=_b64_sub(_VLESS, _VLESS2))) as f:
        await refresh_all(state, f, pipeline)
    assert pipeline.signals == 0


async def test_refresh_all_keeps_old_list_on_fetch_failure(tmp_path):
    state = State(tmp_path / "s.json")
    await _seed_sub(state)
    pipeline = FakePipeline()
    async with _fetcher(lambda r: httpx.Response(502)) as f:
        n = await refresh_all(state, f, pipeline)
    assert n == 0
    # Old server list preserved — better stale than empty.
    assert len(state.snapshot().subscriptions[0].servers) == 1


async def test_refresh_all_keeps_old_list_on_empty_body(tmp_path):
    state = State(tmp_path / "s.json")
    await _seed_sub(state)
    pipeline = FakePipeline()
    # 200 but unparseable / no servers → keep the old list, don't wipe.
    async with _fetcher(lambda r: httpx.Response(200, content=b"garbage")) as f:
        n = await refresh_all(state, f, pipeline)
    assert n == 0
    assert len(state.snapshot().subscriptions[0].servers) == 1


async def test_refresh_all_skips_inline_node_subs(tmp_path):
    state = State(tmp_path / "s.json")
    # An inline-node subscription can't be re-fetched.
    async with _fetcher(lambda r: httpx.Response(200, content=_b64_sub(_VLESS))) as f:
        servers = await fetch_and_parse(f, _VLESS)
    await state.add_subscription("inline", _VLESS, servers)
    pipeline = FakePipeline()
    hit = False

    def handler(request):
        nonlocal hit
        hit = True
        return httpx.Response(200)

    async with _fetcher(handler) as f:
        n = await refresh_all(state, f, pipeline)
    assert n == 0 and not hit  # inline node never re-fetched
