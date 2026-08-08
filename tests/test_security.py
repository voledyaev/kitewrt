"""Tests for the API security middleware: secret redaction + the rebinding /
cross-origin guards.

Drives the app in-process (ASGITransport) like test_api, plus unit tests for the
Host-locality helper.
"""

from __future__ import annotations

import httpx
import pytest
from kitewrt.api import create_app
from kitewrt.security import host_only, is_local_host
from kitewrt.state import State, redacted_state_dict
from kitewrt.vless import Server

_VLESS_BODY = (
    "vless://11111111-1111-1111-1111-111111111111@de.example.com:443"
    "?security=reality&pbk=PUBKEY&sid=SHORTID&type=tcp#DE\n"
)


class FakePipeline:
    def signal(self) -> None: ...


@pytest.fixture
async def client(tmp_path):
    state = State(tmp_path / "s.json")
    routes = {}

    def handler(request):
        return routes.get(str(request.url)) or httpx.Response(404)

    fetcher = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(state, FakePipeline(), fetcher)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c, routes
    await fetcher.aclose()


# --- _is_local_host / _host_only -------------------------------------------


def test_host_only_strips_port_and_brackets():
    assert host_only("192.168.8.1:8088") == "192.168.8.1"
    assert host_only("openwrt") == "openwrt"
    assert host_only("[::1]:8088") == "::1"


def test_is_local_host_allows_lan_rejects_public():
    for ok in (
        "192.168.8.1:8088",
        "127.0.0.1",
        "localhost:8088",
        "openwrt",
        "router.lan",
        "[::1]:8088",
        "",
    ):
        assert is_local_host(ok), ok
    for bad in ("evil.example.com", "attacker.com:8088", "kitewrt.evil.io"):
        assert not is_local_host(bad), bad


# --- secret redaction -------------------------------------------------------


async def test_state_response_strips_server_secrets(client):
    c, routes = client
    routes["http://p.test/x"] = httpx.Response(200, text=_VLESS_BODY)
    add = await c.post("/api/subscriptions", json={"label": "X", "source": "http://p.test/x"})
    assert add.status_code == 200, add.text
    # The add (mutation) response is redacted...
    assert "1111-1111" not in add.text
    # ...and so is GET /api/state.
    r = await c.get("/api/state")
    assert "1111-1111" not in r.text and "PUBKEY" not in r.text
    srv = r.json()["subscriptions"][0]["servers"][0]
    assert set(srv) == {"id", "name", "country", "type", "host", "port"}
    assert srv["host"] == "de.example.com"  # display fields survive


def test_redacted_state_dict_drops_secrets_keeps_display():
    from kitewrt.state import Data, Subscription

    server = Server(
        id="h:443",
        name="N",
        country="DE",
        host="h",
        port=443,
        uuid="secret-uuid",
        password="secret-pw",
        method="aes",
        params={"pbk": "k", "obfs-password": "o"},
    )
    d = Data(
        subscriptions=[
            Subscription(id="s", label="L", source="x", fetched_at="t", servers=[server])
        ]
    )
    s = redacted_state_dict(d)["subscriptions"][0]["servers"][0]
    assert "uuid" not in s and "password" not in s and "method" not in s and "params" not in s
    assert s["host"] == "h" and s["port"] == 443


# --- rebinding + cross-origin guards ---------------------------------------


async def test_non_local_host_blocked(client):
    c, _ = client
    r = await c.get("/api/state", headers={"host": "evil.example.com"})
    assert r.status_code == 403


async def test_cross_origin_mutation_blocked(client):
    c, _ = client
    r = await c.post("/api/toggle", json={"on": False}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403


async def test_same_origin_mutation_allowed(client):
    c, _ = client
    # Origin host == Host ("test") → same-origin → allowed.
    r = await c.post("/api/toggle", json={"on": False}, headers={"origin": "http://test"})
    assert r.status_code == 200


async def test_cross_origin_get_is_allowed(client):
    # Only mutations are origin-gated; a GET with a foreign Origin still works
    # (its response is redacted + CORS keeps a cross-origin script from reading
    # it anyway). Keeps the guard from breaking benign reads.
    c, _ = client
    r = await c.get("/api/state", headers={"origin": "http://evil.example"})
    assert r.status_code == 200
