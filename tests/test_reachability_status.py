"""A controller error is not evidence that a proxy node failed its URL test."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from kitewrt.dataplane import SingBoxWatchdogDeps
from kitewrt.singbox.clash import ClashClient
from kitewrt.state import ActiveServerRef, ApplyResult, Data, State, Subscription
from kitewrt.vless import Server


def _snapshot():
    node = Server(id="node", name="Test", country="ZZ", host="example.test", port=443)
    return Data(
        subscriptions=[
            Subscription(id="sub", label="Test", source="", fetched_at="", servers=[node])
        ],
        active_server=ActiveServerRef(subscription_id="sub", server_id="node"),
        vpn_on=True,
    )


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (200, {"delay": 123}, True),
        (200, {"delay": 0}, True),
        # Exact responses from sing-box 1.14.4 getProxyDelay/errors.go.
        (503, {"message": "An error occurred in the delay test"}, False),
        (504, {"message": "Timeout"}, False),
        (404, {"message": "Resource not found"}, None),
        (400, {"message": "Body invalid"}, None),
        (500, {"message": "internal error"}, None),
        (503, {"message": "controller unavailable"}, None),
        (504, {"message": "gateway unavailable"}, None),
        (200, {}, None),
        (200, [], None),
        (200, {"delay": True}, None),
        (200, {"delay": -1}, None),
        (200, {"delay": "123"}, None),
        (200, {"delay": 1.5}, None),
    ],
)
async def test_watchdog_preserves_unknown_vs_failed_tests(status, body, expected):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(status, json=body))
    ) as client:
        state = SimpleNamespace(snapshot=_snapshot)
        deps = SingBoxWatchdogDeps(state, None, ClashClient(client))
        assert await deps.active_reachable() is expected


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout, httpx.PoolTimeout])
async def test_controller_transport_failure_is_unknown(error):
    def unavailable(req):
        raise error("controller unavailable", request=req)

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:
        clash = ClashClient(client)
        deps = SingBoxWatchdogDeps(SimpleNamespace(snapshot=_snapshot), None, clash)
        assert await deps.active_reachable() is None
        assert await clash.delay("node") is None  # legacy preflight/ranking facade


@pytest.mark.parametrize("status", [200, 503, 504])
async def test_malformed_controller_json_is_unknown(status):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(status, text="not JSON"))
    ) as client:
        clash = ClashClient(client)
        assert (await clash.probe_delay("node")).reachable is None
        assert await clash.delay("node") is None


@pytest.mark.parametrize("change", ["off", "switch", "applying", "applied"])
async def test_in_flight_result_is_discarded_when_intent_changes(change):
    before = _snapshot()
    current = before.model_copy(deep=True)

    def answer(req):
        if change == "off":
            current.vpn_on = False
        elif change == "switch":
            current.active_server = ActiveServerRef(subscription_id="sub", server_id="other")
        elif change == "applying":
            current.applying = True
        else:
            current.last_apply = ApplyResult(at="later", ok=True, msg="reload complete")
        return httpx.Response(504, json={"message": "Timeout"})

    calls = 0

    def snapshot():
        nonlocal calls
        calls += 1
        return before if calls == 1 else current

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as client:
        deps = SingBoxWatchdogDeps(SimpleNamespace(snapshot=snapshot), None, ClashClient(client))
        assert await deps.active_reachable() is None


async def test_applying_state_does_not_probe_or_publish_a_failure():
    snap = _snapshot()
    snap.applying = True

    def unexpected(req):
        pytest.fail("must not probe a data plane being applied")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as client:
        deps = SingBoxWatchdogDeps(
            SimpleNamespace(snapshot=lambda: snap), None, ClashClient(client)
        )
        assert await deps.active_reachable() is None


async def test_same_node_apply_aba_does_not_publish_old_probe_result(tmp_path):
    state = State(tmp_path / "state.json")
    desired = _snapshot()

    def select(d):
        d.subscriptions = desired.subscriptions
        d.active_server = desired.active_server
        d.vpn_on = True

    await state.update(select)

    async def answer(req):
        # The state is identical after these transitions, including last_apply;
        # an egress revision must still invalidate the in-flight old result.
        await state.update(lambda d: setattr(d, "applying", True))
        await state.update(lambda d: setattr(d, "applying", False))
        return httpx.Response(504, json={"message": "Timeout"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as client:
        deps = SingBoxWatchdogDeps(state, None, ClashClient(client))
        assert await deps.active_reachable() is None
