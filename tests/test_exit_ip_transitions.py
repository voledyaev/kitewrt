"""Exit observations must describe a completed, unchanged routing state."""

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest
from kitewrt.proxied import ProxiedFetcher
from kitewrt.routes.exit_ip import exit_ip
from kitewrt.state import ActiveServerRef, ApplyResult, State


def request():
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))


def select(d, node):
    d.active_server = ActiveServerRef(subscription_id="s", server_id=node)


async def test_startup_does_not_fetch_or_cache_direct_exit(tmp_path):
    state = State(tmp_path / "state.json")
    await state.update(lambda d: (setattr(d, "vpn_on", True), setattr(d, "applying", True)))
    calls = []

    def trace(req):
        calls.append(req)
        return httpx.Response(200, text="ip=198.51.100.20\nloc=NL\n")

    req = request()
    async with httpx.AsyncClient(transport=httpx.MockTransport(trace)) as client:
        assert not (await exit_ip(req, state, client)).available
        assert not calls
        await state.update(lambda d: setattr(d, "applying", False))
        observed = await exit_ip(req, state, client)
    assert observed.ip == "198.51.100.20"
    assert len(calls) == 1


@pytest.mark.parametrize("change", ["selection", "apply"])
async def test_completed_switch_or_reload_invalidates_cached_exit(tmp_path, change):
    state = State(tmp_path / "state.json")
    await state.update(lambda d: (setattr(d, "vpn_on", True), select(d, "a")))
    calls = []

    def trace(req):
        calls.append(req)
        return httpx.Response(200, text=f"ip=198.51.100.{len(calls)}\nloc=NL\n")

    req = request()
    async with httpx.AsyncClient(transport=httpx.MockTransport(trace)) as client:
        first = await exit_ip(req, state, client)
        if change == "selection":
            await state.update(lambda d: select(d, "b"))
        else:
            await state.update(
                lambda d: setattr(d, "last_apply", ApplyResult(at="same-second", ok=True, msg=""))
            )
        second = await exit_ip(req, state, client)
    assert first.ip != second.ip
    assert len(calls) == 2


@pytest.mark.parametrize("change", ["selection", "toggle", "applying"])
async def test_inflight_observation_is_discarded_after_aba_transition(tmp_path, change):
    """The final state equals the initial one, including last_apply timestamp."""
    state = State(tmp_path / "state.json")
    await state.update(lambda d: (setattr(d, "vpn_on", True), select(d, "a")))
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def trace(req):
        calls.append(req)
        if len(calls) == 1:
            entered.set()
            await release.wait()
        return httpx.Response(200, text=f"ip=198.51.100.{len(calls)}\nloc=NL\n")

    req = request()
    async with httpx.AsyncClient(transport=httpx.MockTransport(trace)) as client:
        pending = asyncio.create_task(exit_ip(req, state, client))
        await entered.wait()
        if change == "selection":
            await state.update(lambda d: select(d, "b"))
            await state.update(lambda d: select(d, "a"))
        elif change == "toggle":
            await state.update(lambda d: setattr(d, "vpn_on", False))
            await state.update(lambda d: setattr(d, "vpn_on", True))
        else:
            await state.update(lambda d: setattr(d, "applying", True))
            await state.update(lambda d: setattr(d, "applying", False))
        release.set()
        stale = await pending
        assert not stale.available
        assert stale.vpn_on
        fresh = await exit_ip(req, state, client)
    assert fresh.ip == "198.51.100.2"
    assert len(calls) == 2


async def test_vpn_exit_never_falls_back_direct_when_proxy_is_dead(tmp_path):
    state = State(tmp_path / "state.json")
    direct_calls = []

    def dead(req):
        raise httpx.ConnectError("local proxy disappeared", request=req)

    def direct(req):
        direct_calls.append(req)
        return httpx.Response(200, text="ip=192.0.2.10\nloc=US\n")

    proxy = httpx.AsyncClient(transport=httpx.MockTransport(dead))
    direct_client = httpx.AsyncClient(transport=httpx.MockTransport(direct))
    fetcher = ProxiedFetcher(proxy, direct_client)
    try:
        await state.update(lambda d: setattr(d, "vpn_on", True))
        assert not (await exit_ip(request(), state, fetcher)).available
        assert not direct_calls
        # VPN-off retains the established bootstrap/direct behavior.
        await state.update(lambda d: setattr(d, "vpn_on", False))
        assert (await exit_ip(request(), state, fetcher)).ip == "192.0.2.10"
        assert len(direct_calls) == 1
    finally:
        await fetcher.aclose()


async def test_nonrouting_updates_do_not_invalidate_exit_cache_or_persist_revision(tmp_path):
    state = State(tmp_path / "state.json")
    revision = state.egress_revision
    await state.merge_pings({"node": 20})
    assert state.egress_revision == revision
    assert "egress_revision" not in json.loads((tmp_path / "state.json").read_text())


async def test_failed_state_write_does_not_advance_egress_revision(tmp_path, monkeypatch):
    state = State(tmp_path / "state.json")
    revision = state.egress_revision

    def no_space(_):
        raise OSError("full overlay")

    monkeypatch.setattr(state, "_save_locked", no_space)
    with pytest.raises(OSError, match="full overlay"):
        await state.update(lambda d: setattr(d, "vpn_on", True))
    assert state.egress_revision == revision
    assert not state.snapshot().vpn_on
