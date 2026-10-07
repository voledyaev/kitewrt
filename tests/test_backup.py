"""GET/POST /api/backup — the user's own copy of the subscriptions.

`/etc/kitewrt` survives a firmware upgrade, but not a reset or a new router.
"""

from __future__ import annotations

import json

import httpx
import pytest
from kitewrt.api import create_app
from kitewrt.state import ActiveServerRef, ResolvedEndpoint, State
from kitewrt.vless import Server


class FakePipeline:
    def __init__(self):
        self.signals = 0

    def signal(self) -> None:
        self.signals += 1


@pytest.fixture
async def env(tmp_path):
    state = State(tmp_path / "s.json")
    pipeline = FakePipeline()
    fetcher = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    app = create_app(state, pipeline, fetcher)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, state, pipeline
    await fetcher.aclose()


SECRET = "00000000-0000-4000-8000-00000000abcd"


async def _seed(state: State) -> None:
    srv = Server(
        id="ams.example.net:443",
        name="AMS",
        country="NL",
        host="ams.example.net",
        port=443,
        uuid=SECRET,
    )
    snap = await state.add_subscription("Mine", "https://sub.example/token123", [srv])
    sub_id = snap.subscriptions[0].id

    def more(d):
        d.active_server = ActiveServerRef(subscription_id=sub_id, server_id=srv.id)
        d.vpn_on = True
        d.rules_url = "https://rules.example/r.json"
        d.dns.direct_dns = "77.88.8.8"
        d.endpoints = {"ams.example.net": ResolvedEndpoint(ip="87.199.195.89", at="t")}

    await state.update(more)


async def test_backup_carries_the_credentials_it_needs_to_restore(env):
    c, state, _ = env
    await _seed(state)
    r = await c.get("/api/backup")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    body = r.json()
    assert body["format"] == "kitewrt-backup"
    assert body["state"]["subscriptions"][0]["servers"][0]["uuid"] == SECRET
    assert body["state"]["subscriptions"][0]["source"] == "https://sub.example/token123"
    assert "vpn_on" not in body["state"]  # restoring must not flip the tunnel


async def test_other_responses_still_redact(env):
    c, state, _ = env
    await _seed(state)
    assert SECRET not in (await c.get("/api/state")).text


async def test_round_trip_restores_onto_an_empty_router(env, tmp_path):
    c, state, pipeline = env
    await _seed(state)
    dump = (await c.get("/api/backup")).content

    def wipe(d):
        d.subscriptions = []
        d.active_server = None
        d.rules_url = ""
        d.dns.direct_dns = ""
        d.endpoints = {}
        d.vpn_on = False

    await state.update(wipe)
    r = await c.post("/api/backup", content=dump, headers={"content-type": "application/json"})
    assert r.status_code == 200, r.text
    snap = state.snapshot()
    assert snap.subscriptions[0].servers[0].uuid == SECRET
    assert snap.active_server is not None
    assert snap.rules_url == "https://rules.example/r.json"
    assert snap.dns.direct_dns == "77.88.8.8"
    assert snap.vpn_on is False  # untouched
    assert pipeline.signals == 1
    assert SECRET not in r.text  # the response is an ordinary, redacted state


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        json.dumps({"format": "something-else", "version": 1, "state": {}}).encode(),
        json.dumps({"subscriptions": []}).encode(),
    ],
)
async def test_garbage_is_refused_and_changes_nothing(env, payload):
    c, state, _ = env
    await _seed(state)
    before = state.snapshot()
    r = await c.post("/api/backup", content=payload, headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert state.snapshot().subscriptions == before.subscriptions


async def test_a_newer_format_is_refused(env):
    c, *_ = env
    payload = json.dumps({"format": "kitewrt-backup", "version": 99, "state": {}}).encode()
    r = await c.post("/api/backup", content=payload, headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert "newer" in r.json()["error"]


async def test_a_dangling_active_server_is_dropped(env):
    c, state, _ = env
    payload = {
        "format": "kitewrt-backup",
        "version": 1,
        "state": {"active_server": {"subscription_id": "gone", "server_id": "x:1"}},
    }
    r = await c.post("/api/backup", json=payload)
    assert r.status_code == 200
    assert state.snapshot().active_server is None


async def test_cross_origin_restore_is_blocked(env):
    c, *_ = env
    r = await c.post(
        "/api/backup",
        json={"format": "kitewrt-backup", "version": 1, "state": {}},
        headers={"origin": "https://evil.example"},
    )
    assert r.status_code == 403
