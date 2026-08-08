"""Tests for the FastAPI surface.

Uses httpx.AsyncClient + ASGITransport to drive the app in-process — no
sockets, no network. Subscription/rules fetches go through a MockTransport
that maps fake source URLs to canned responses.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import pkgutil
from pathlib import Path

import httpx
import kitewrt.routes
import pytest
from kitewrt.api import create_app
from kitewrt.routes.exit_ip import parse_trace
from kitewrt.state import DEFAULT_DOH_URL, Data, State

SAMPLE_VLESS_BODY = (
    "vless://uuid1@host1.com:443?security=reality&type=tcp"
    "#%F0%9F%87%B5%F0%9F%87%B1Poland\n"
    "vless://uuid2@host2.com:443?security=reality&type=tcp"
    "#%F0%9F%87%A9%F0%9F%87%AAGermany\n"
)


class FakePipeline:
    def __init__(self):
        self.signals = 0

    def signal(self) -> None:
        self.signals += 1


class FakeRouteMap:
    """Maps (method, url) → httpx.Response, used by httpx.MockTransport.

    Each entry can be a single response (returned every time) or a callable
    that produces a response per request — handy for "first call returns X,
    second call returns Y" tests.
    """

    def __init__(self):
        self.routes: dict[str, object] = {}
        self.requests: list[httpx.Request] = []

    def add(self, url: str, response_or_factory) -> None:
        self.routes[url] = response_or_factory

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        entry = self.routes.get(str(request.url))
        if entry is None:
            return httpx.Response(404, text=f"no route for {request.url}")
        if callable(entry):
            return entry(request)
        return entry


@pytest.fixture
async def setup(tmp_path):
    state = State(tmp_path / "state.json")
    pipeline = FakePipeline()
    routes = FakeRouteMap()
    fetcher = httpx.AsyncClient(transport=httpx.MockTransport(routes.handle))
    app = create_app(state, pipeline, fetcher)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, state, pipeline, routes
    await fetcher.aclose()


# --- Meta -------------------------------------------------------------------


async def test_get_state_returns_defaults(setup):
    client, *_ = setup
    r = await client.get("/api/state")
    assert r.status_code == 200
    body = r.json()
    assert body["subscriptions"] == []
    assert body["vpn_on"] is False
    assert body["active_server"] is None
    assert body["dns"]["doh_url"] == DEFAULT_DOH_URL


async def test_health(setup):
    client, *_ = setup
    r = await client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


# The three fields whose size follows the user's rules document. The UI has
# only ever rendered `.length` of each, so the wire carries the counts.
_BULK_RULE_FIELDS = ("rules", "rule_sets", "rules_bypass_address")


def _assert_counts_not_lists(body: dict, where: str) -> None:
    for field in _BULK_RULE_FIELDS:
        assert field not in body, f"{where} still ships the whole {field} list"
    assert body["rules_count"] == 1
    assert body["rule_sets_count"] == 1
    assert body["rules_bypass_count"] == 8640


async def _load_a_country_sized_rules_document(state) -> None:
    """The shape that made this expensive: one country's CIDR list plus its
    domain rules. Measured on /api/state before the counts: 147,363 bytes for
    the bypass list alone and 489,448 for 20000 inline domains, against 45
    bytes for /api/health — and the dashboard polls this."""

    def mutate(d: Data) -> None:
        d.rules_url = "http://rules.test/rules.json"
        d.rules = [{"domain_suffix": [f"s{i}.example" for i in range(20000)], "outbound": "proxy"}]
        d.rule_sets = [{"tag": "geosite-ads", "type": "remote", "url": "http://x.test/a.srs"}]
        d.rules_bypass_address = [f"10.{i // 256}.{i % 256}.0/24" for i in range(8640)]

    await state.update(mutate)


async def test_state_reports_rule_counts_not_the_lists(setup):
    client, state, *_ = setup
    await _load_a_country_sized_rules_document(state)
    r = await client.get("/api/state")
    assert r.status_code == 200
    _assert_counts_not_lists(r.json(), "GET /api/state")
    # 400-odd bytes rather than the ~640 KB those three lists serialize to.
    assert len(r.content) < 2048


async def test_every_state_returning_endpoint_reports_counts(setup):
    """Not just /api/state: every mutating endpoint answers with the same
    snapshot, so each one is its own copy of the payload."""
    client, state, _, routes = setup
    routes.add("http://p.test/x", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    routes.add("http://rules.test/rules.json", httpx.Response(200, json={"rules": []}))
    await _load_a_country_sized_rules_document(state)

    add = await client.post("/api/subscriptions", json={"label": "X", "source": "http://p.test/x"})
    sub_id = add.json()["subscriptions"][0]["id"]
    server_id = add.json()["subscriptions"][0]["servers"][0]["id"]
    seen = [("POST /api/subscriptions", add)]

    async def record(where, coro):
        seen.append((where, await coro))

    await record(
        "PATCH /api/subscriptions/{id}",
        client.patch(f"/api/subscriptions/{sub_id}", json={"label": "Y"}),
    )
    await record(
        "POST /api/subscriptions/{id}/refresh", client.post(f"/api/subscriptions/{sub_id}/refresh")
    )
    await record(
        "POST /api/server",
        client.post("/api/server", json={"subscription_id": sub_id, "server_id": server_id}),
    )
    await record("POST /api/toggle", client.post("/api/toggle", json={"on": True}))
    await record(
        "POST /api/dns/config", client.post("/api/dns/config", json={"direct_dns": "9.9.9.9"})
    )
    await record("DELETE /api/subscriptions/{id}", client.delete(f"/api/subscriptions/{sub_id}"))

    for where, response in seen:
        assert response.status_code == 200, (where, response.text)
        _assert_counts_not_lists(response.json(), where)


def test_no_route_answers_with_the_raw_state_model():
    """Guard for the next state-returning route: annotate it `-> Data` and
    FastAPI serializes all three lists straight back onto the wire. Walks the
    package rather than a hand-listed set of modules, so a new route module is
    covered the day it is added."""
    offenders = []
    for found in pkgutil.iter_modules(kitewrt.routes.__path__):
        module = importlib.import_module(f"kitewrt.routes.{found.name}")
        for route in getattr(getattr(module, "router", None), "routes", ()):
            if getattr(route, "response_model", None) is Data:
                offenders.append(f"{found.name}:{route.path}")
    assert offenders == [], "return state_payload(...) instead"


async def test_metrics_unavailable_when_vpn_off(setup):
    client, *_ = setup
    r = await client.get("/api/metrics")
    assert r.status_code == 200
    assert r.json()["available"] is False  # no clash wired + vpn off


async def test_metrics_summary_when_vpn_on(tmp_path):
    from kitewrt.deps import get_clash

    state = State(tmp_path / "state.json")
    await state.update(lambda d: setattr(d, "vpn_on", True))
    fetcher = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    app = create_app(state, FakePipeline(), fetcher)

    class FakeClash:
        async def connections(self):
            return {
                "downloadTotal": 1000,
                "uploadTotal": 200,
                "memory": 5000,
                "connections": [
                    {
                        "chains": ["sub/de:443", "select"],
                        "download": 10,
                        "upload": 5,
                        "metadata": {
                            "host": "small.example",
                            "sourceIP": "192.168.8.10",
                            "network": "tcp",
                        },
                    },  # proxied, light, phone
                    {
                        "chains": ["direct"],
                        "download": 9000,
                        "upload": 100,
                        "metadata": {
                            "host": "heavy.example",
                            "sourceIP": "192.168.8.20",
                            "network": "udp",
                        },
                    },  # direct, heavy, TV
                ],
            }

        async def current(self, selector):
            return "sub/de:443"

    app.dependency_overrides[get_clash] = lambda: FakeClash()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/metrics")
    await fetcher.aclose()

    assert r.status_code == 200
    b = r.json()
    assert b["available"] is True
    assert b["now"] == "sub/de:443"
    assert b["download_total"] == 1000
    assert b["upload_total"] == 200
    assert b["connections"] == 2
    assert b["proxied"] == 1
    assert b["direct"] == 1
    assert b["memory"] == 5000
    # top sorted by total bytes desc: heavy.example (direct) first
    assert [c["host"] for c in b["top"]] == ["heavy.example", "small.example"]
    assert b["top"][0] == {
        "host": "heavy.example",
        "down": 9000,
        "up": 100,
        "proxied": False,
        "net": "udp",
    }
    # Per-device rollup: heavy device (9100 B) before the light one (15 B).
    assert [c["ip"] for c in b["clients"]] == ["192.168.8.20", "192.168.8.10"]
    assert b["clients"][0] == {"ip": "192.168.8.20", "down": 9000, "up": 100, "conns": 1}


def test_client_rollup_aggregates_per_source_ip():
    from kitewrt.routes.metrics import build_metrics_summary

    conns = {
        "connections": [
            {"download": 100, "upload": 10, "metadata": {"sourceIP": "192.168.8.5"}},
            {"download": 200, "upload": 20, "metadata": {"sourceIP": "192.168.8.5"}},
            {"download": 50, "upload": 5, "metadata": {"sourceIP": "192.168.8.9"}},
        ]
    }
    clients = build_metrics_summary(conns, "select")["clients"]
    # The two flows from .5 are summed into one device row; .5 (330 B) > .9 (55 B).
    assert clients == [
        {"ip": "192.168.8.5", "down": 300, "up": 30, "conns": 2},
        {"ip": "192.168.8.9", "down": 50, "up": 5, "conns": 1},
    ]


async def test_boot_reconcile_brackets_when_vpn_on(tmp_path, monkeypatch):
    # A2: the first reconcile is kill-switch-bracketed when vpn_on persisted, and
    # the guard lifts only once the selector is confirmed on target.
    from kitewrt import api as api_mod
    from kitewrt import killswitch

    events: list[str] = []

    async def detect():
        return "eth0"

    async def engage(wan):
        events.append("engage")
        return True

    async def disengage(wan):
        events.append("disengage")

    monkeypatch.setattr(killswitch, "detect_wan", detect)
    monkeypatch.setattr(killswitch, "engage", engage)
    monkeypatch.setattr(killswitch, "disengage", disengage)

    state = State(tmp_path / "s.json")
    await state.update(lambda d: setattr(d, "vpn_on", True))  # no active server → target=direct

    class Clash:
        async def current(self, selector):
            return "direct"  # matches selector_default(vpn_on, no active)

    class Pipe:
        def __init__(self):
            self.signals = 0

        def signal(self):
            self.signals += 1

    pipe = Pipe()
    await api_mod._boot_reconcile(state, Clash(), pipe)
    assert pipe.signals == 1
    assert events == ["engage", "disengage"]  # bracketed, lifted after confirm


async def test_boot_reconcile_no_bracket_when_vpn_off(tmp_path, monkeypatch):
    from kitewrt import api as api_mod
    from kitewrt import killswitch

    engaged = False

    async def engage(wan):
        nonlocal engaged
        engaged = True
        return True

    monkeypatch.setattr(killswitch, "detect_wan", lambda: _aret("eth0")())
    monkeypatch.setattr(killswitch, "engage", engage)

    state = State(tmp_path / "s.json")  # vpn_on defaults False

    class Pipe:
        signals = 0

        def signal(self):
            type(self).signals += 1

    pipe = Pipe()
    await api_mod._boot_reconcile(state, object(), pipe)
    assert pipe.signals == 1
    assert engaged is False  # vpn off → no kill-switch bracket


async def test_await_clock_sane_true_when_clock_set():
    from kitewrt import api as api_mod

    # Real clock (year >> 2000) → sane on the first check, no wait.
    assert await api_mod._await_clock_sane(min_year=2000, attempts=1, delay=0) is True


async def test_await_clock_sane_gives_up_when_unset():
    from kitewrt import api as api_mod

    # min_year in the future → never sane → bounded give-up returns False (the
    # daemon proceeds rather than blocking the boot forever).
    assert await api_mod._await_clock_sane(min_year=9999, attempts=2, delay=0) is False


def _aret(value):
    async def f():
        return value

    return f


async def test_unknown_api_returns_404(setup):
    client, *_ = setup
    r = await client.get("/api/nope")
    assert r.status_code == 404


# --- Static -----------------------------------------------------------------


async def test_index_served_at_root(setup):
    client, *_ = setup
    r = await client.get("/")
    assert r.status_code == 200
    assert "<!DOCTYPE html>" in r.text or "<html" in r.text
    # Must revalidate so a stale index.html can't point at deleted asset hashes
    # after an upgrade.
    assert "no-cache" in r.headers.get("cache-control", "")


async def test_index_answers_head(setup):
    """`curl -I` / uptime monitors probe with HEAD. FastAPI's router does not
    add it automatically, so this used to fall through to the StaticFiles mount
    and 404 while GET on the same URL returned the page."""
    client, *_ = setup
    r = await client.head("/")
    assert r.status_code == 200


async def test_favicon_returns_204(setup):
    client, *_ = setup
    r = await client.get("/favicon.ico")
    assert r.status_code == 204


# --- Subscriptions ----------------------------------------------------------


async def test_add_subscription_happy_path(setup):
    client, state, pipeline, routes = setup
    routes.add("http://provider.test/sub", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    r = await client.post(
        "/api/subscriptions", json={"label": "Test", "source": "http://provider.test/sub"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["subscriptions"]) == 1
    sub = body["subscriptions"][0]
    assert sub["label"] == "Test"
    assert len(sub["servers"]) == 2
    # No apply triggered — new sub doesn't change runtime.
    assert pipeline.signals == 0


async def test_add_subscription_inline_vless_skips_fetch(setup):
    client, state, pipeline, routes = setup
    inline = "vless://abc@host.example:8443?security=reality&type=tcp#test"
    r = await client.post("/api/subscriptions", json={"label": "Inline", "source": inline})
    assert r.status_code == 200, r.text
    sub = r.json()["subscriptions"][0]
    assert sub["source"] == inline
    assert sub["servers"][0]["host"] == "host.example"
    assert routes.requests == []  # no fetch was made


async def test_add_subscription_sub_wrapper_fetches_decoded_url(setup):
    """A Shadowrocket `sub://` source fetches the URL it wraps, stores the
    source verbatim (so auto-refresh keeps working) and takes its label from
    the fragment."""
    import base64

    client, state, pipeline, routes = setup
    url = "http://provider.test/sub"
    routes.add(url, httpx.Response(200, text=SAMPLE_VLESS_BODY))
    blob = base64.b64encode(url.encode()).decode().rstrip("=")
    source = f"sub://{blob}#%F0%9F%87%AA%F0%9F%87%BA%20Auto"

    r = await client.post("/api/subscriptions", json={"source": source})
    assert r.status_code == 200, r.text
    sub = r.json()["subscriptions"][0]
    assert sub["source"] == source
    assert sub["label"] == "\U0001f1ea\U0001f1fa Auto"
    assert len(sub["servers"]) == 2


async def test_add_subscription_sub_wrapper_rejects_smuggled_scheme(setup):
    """The guard checks what the blob DECODES to, so a non-http scheme can't
    ride in inside the base64."""
    import base64

    client, *_ = setup
    blob = base64.b64encode(b"file:///etc/shadow").decode().rstrip("=")
    r = await client.post("/api/subscriptions", json={"source": f"sub://{blob}"})
    assert r.status_code == 400, r.text
    assert "must start with" in r.text


async def test_add_subscription_label_derived_from_url(setup):
    client, state, _, routes = setup
    routes.add("http://provider.test/sub", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    r = await client.post("/api/subscriptions", json={"source": "http://provider.test/sub"})
    assert r.status_code == 200
    assert r.json()["subscriptions"][0]["label"] == "provider.test"


async def test_add_subscription_label_derived_from_vless_host(setup):
    client, *_ = setup
    inline = "vless://abc@host.example:8443?security=reality&type=tcp#x"
    r = await client.post("/api/subscriptions", json={"source": inline})
    assert r.status_code == 200
    assert r.json()["subscriptions"][0]["label"] == "host.example"


async def test_add_subscription_rejects_bad_scheme(setup):
    client, *_ = setup
    r = await client.post(
        "/api/subscriptions", json={"label": "X", "source": "ftp://example.com/x"}
    )
    assert r.status_code == 400


async def test_add_subscription_fetch_failure_returns_502(setup):
    client, state, _, routes = setup
    # No route registered → 404 from MockTransport → FetchError → 502.
    r = await client.post(
        "/api/subscriptions", json={"label": "X", "source": "http://nowhere.test/x"}
    )
    assert r.status_code == 502


async def test_add_subscription_unparseable_body_returns_400(setup):
    client, state, _, routes = setup
    routes.add("http://provider.test/sub", httpx.Response(200, text="not a vless list"))
    r = await client.post(
        "/api/subscriptions", json={"label": "X", "source": "http://provider.test/sub"}
    )
    assert r.status_code == 400


async def test_delete_subscription_clears_active_when_affected(setup):
    client, state, pipeline, routes = setup
    routes.add("http://p.test/x", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    add = await client.post("/api/subscriptions", json={"label": "X", "source": "http://p.test/x"})
    sub = add.json()["subscriptions"][0]
    sub_id = sub["id"]
    srv_id = sub["servers"][0]["id"]
    await client.post("/api/server", json={"subscription_id": sub_id, "server_id": srv_id})
    await client.post("/api/toggle", json={"on": True})
    pipeline.signals = 0

    r = await client.delete(f"/api/subscriptions/{sub_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["subscriptions"] == []
    assert body["active_server"] is None
    assert body["vpn_on"] is False
    assert pipeline.signals == 1  # apply triggered (affected active server)


async def test_delete_unknown_subscription_returns_404(setup):
    client, *_ = setup
    r = await client.delete("/api/subscriptions/ghost-id")
    assert r.status_code == 404


async def test_refresh_subscription_replaces_servers(setup):
    client, state, _, routes = setup
    calls = 0
    body1 = "vless://u1@host1.com:443?security=reality#%F0%9F%87%B5%F0%9F%87%B1Poland\n"
    body2 = body1 + ("vless://u2@host2.com:443?security=reality#%F0%9F%87%A9%F0%9F%87%AAGermany\n")

    def respond(req):
        nonlocal calls
        i = calls
        calls += 1
        return httpx.Response(200, text=(body1, body2)[min(i, 1)])

    routes.add("http://p.test/x", respond)
    add = await client.post("/api/subscriptions", json={"label": "X", "source": "http://p.test/x"})
    sub_id = add.json()["subscriptions"][0]["id"]
    assert len(add.json()["subscriptions"][0]["servers"]) == 1

    r = await client.post(f"/api/subscriptions/{sub_id}/refresh")
    assert r.status_code == 200
    assert len(r.json()["subscriptions"][0]["servers"]) == 2


async def test_patch_subscription_renames(setup):
    client, *_, routes = setup
    routes.add("http://p.test/x", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    add = await client.post(
        "/api/subscriptions", json={"label": "Old", "source": "http://p.test/x"}
    )
    sub_id = add.json()["subscriptions"][0]["id"]
    r = await client.patch(f"/api/subscriptions/{sub_id}", json={"label": "New"})
    assert r.status_code == 200
    assert r.json()["subscriptions"][0]["label"] == "New"


async def test_subscription_test_endpoint_returns_pings(setup, monkeypatch):
    """POST /test delay-tests every server through the proxy and merges the
    results into state as ping badges.

    We monkey-patch the delay-test helper so the test stays network-free (no
    sing-box / Clash API); the routing/state plumbing is what we verify here.
    """
    client, _state, _pipeline, routes_map = setup
    routes_map.add("http://p.test/x", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    add = await client.post("/api/subscriptions", json={"label": "X", "source": "http://p.test/x"})
    sub = add.json()["subscriptions"][0]
    server_ids = [s["id"] for s in sub["servers"]]

    from kitewrt.routes import subscriptions as subs_module

    async def fake_delay_test(sub_id, state, clash, dataplane):
        # Live first, down second — exercises both display paths.
        return {server_ids[0]: 42, server_ids[1]: None}

    monkeypatch.setattr(subs_module, "_delay_test_all", fake_delay_test)

    r = await client.post(f"/api/subscriptions/{sub['id']}/test")
    assert r.status_code == 200, r.text
    pings = r.json()["pings"]
    assert pings[server_ids[0]]["ms"] == 42
    assert pings[server_ids[1]]["ms"] is None
    # `at` must be a non-empty ISO timestamp for the UI to format.
    assert pings[server_ids[0]]["at"]


async def test_subscription_test_unknown_returns_404(setup):
    client, *_ = setup
    r = await client.post("/api/subscriptions/ghost-id/test")
    assert r.status_code == 404


# --- /api/server -----------------------------------------------------------


async def test_server_select_invalid_rejected(setup):
    client, *_ = setup
    r = await client.post("/api/server", json={"subscription_id": "ghost", "server_id": "h:443"})
    assert r.status_code == 400


async def test_server_select_valid_sets_active(setup):
    client, *_, routes = setup
    routes.add("http://p.test/x", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    add = await client.post("/api/subscriptions", json={"label": "X", "source": "http://p.test/x"})
    sub = add.json()["subscriptions"][0]
    r = await client.post(
        "/api/server", json={"subscription_id": sub["id"], "server_id": sub["servers"][0]["id"]}
    )
    assert r.status_code == 200
    a = r.json()["active_server"]
    assert a["subscription_id"] == sub["id"]
    assert a["server_id"] == sub["servers"][0]["id"]


async def test_server_select_nulls_deselect(setup):
    client, state, _, routes = setup
    routes.add("http://p.test/x", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    add = await client.post("/api/subscriptions", json={"label": "X", "source": "http://p.test/x"})
    sub = add.json()["subscriptions"][0]
    await client.post(
        "/api/server", json={"subscription_id": sub["id"], "server_id": sub["servers"][0]["id"]}
    )
    r = await client.post("/api/server", json={"subscription_id": None, "server_id": None})
    assert r.status_code == 200
    assert r.json()["active_server"] is None


# --- /api/toggle -----------------------------------------------------------


async def test_toggle_on_without_active_rejected(setup):
    client, *_ = setup
    r = await client.post("/api/toggle", json={"on": True})
    assert r.status_code == 400
    assert "no active server" in r.json()["error"]


async def test_toggle_off_without_active_succeeds(setup):
    client, *_ = setup
    r = await client.post("/api/toggle", json={"on": False})
    assert r.status_code == 200
    assert r.json()["vpn_on"] is False


async def test_toggle_on_with_active_succeeds(setup):
    client, state, pipeline, routes = setup
    routes.add("http://p.test/x", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    add = await client.post("/api/subscriptions", json={"label": "X", "source": "http://p.test/x"})
    sub = add.json()["subscriptions"][0]
    await client.post(
        "/api/server", json={"subscription_id": sub["id"], "server_id": sub["servers"][0]["id"]}
    )
    pipeline.signals = 0
    r = await client.post("/api/toggle", json={"on": True})
    assert r.status_code == 200
    assert r.json()["vpn_on"] is True
    assert pipeline.signals == 1


# --- /api/dns/config (new) -------------------------------------------------


async def test_dns_config_updates_doh_url_and_signals(setup):
    client, state, pipeline, _ = setup
    new_url = "https://9.9.9.9/dns-query"
    r = await client.post("/api/dns/config", json={"doh_url": new_url})
    assert r.status_code == 200
    body = r.json()
    assert body["dns"]["doh_url"] == new_url
    assert pipeline.signals == 1


async def test_dns_config_rejects_a_hostname_doh_url(setup):
    """A hostname here is accepted by every layer and rejected by sing-box.

    It becomes `route.default_domain_resolver`, which resolves the proxy
    servers' own domains — so a name there would need resolving to be
    resolved. sing-box refuses the config outright, the bad value persists in
    state.json so every later apply fails too, and after a reboot `apply()`
    returns before `ensure_capture()` — so following `sweep()` nothing
    reinstalls the capture and the whole LAN goes direct while the UI reads
    "on". The test that used to live here asserted `https://dns.google/...`
    was accepted.
    """
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"doh_url": "https://dns.google/dns-query"})
    assert r.status_code == 400
    assert "hostname" in r.json()["error"]


async def test_dns_config_rejects_non_https(setup):
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"doh_url": "http://insecure.example/dns-query"})
    assert r.status_code == 400
    assert "https" in r.json()["error"].lower()


async def test_dns_config_rejects_empty(setup):
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"doh_url": ""})
    assert r.status_code == 400


async def test_dns_config_updates_direct_dns(setup):
    # direct_dns is independently settable (e.g. a regional resolver for GeoDNS).
    client, state, pipeline, _ = setup
    r = await client.post("/api/dns/config", json={"direct_dns": "9.9.9.9"})
    assert r.status_code == 200
    assert r.json()["dns"]["direct_dns"] == "9.9.9.9"
    # doh_url left unchanged (only direct_dns was sent).
    assert r.json()["dns"]["doh_url"] == DEFAULT_DOH_URL


async def test_dns_config_direct_dns_empty_means_system_default(setup):
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"direct_dns": ""})
    assert r.status_code == 200
    assert r.json()["dns"]["direct_dns"] == ""


async def test_dns_config_rejects_direct_dns_with_scheme(setup):
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"direct_dns": "https://dns.example/x"})
    assert r.status_code == 400


async def test_dns_config_rejects_router_loopback_resolver(setup):
    # Pointing direct DNS at the router's own resolver is rejected. The reason
    # written here was the tun era's `hijack-dns` loop, and that mechanism is
    # gone — the capture hooks PREROUTING only, and router-origin traffic takes
    # OUTPUT. Whether a loop still forms under tproxy is **unverified**; what
    # holds regardless is that the router's resolver is dnsmasq, which forwards
    # to whatever kitewrt configured, so pointing "direct" back at it is
    # circular by construction.
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"direct_dns": "127.0.0.1"})
    assert r.status_code == 400
    assert "router" in r.json()["error"].lower()


async def test_dns_config_rejects_unspecified_resolver(setup):
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"direct_dns": "0.0.0.0"})
    assert r.status_code == 400


async def test_dns_config_rejects_ipv6_resolver(setup):
    # The data plane is IPv4-only; an IPv6 literal is rejected with a clear msg.
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"direct_dns": "2001:4860:4860::8888"})
    assert r.status_code == 400
    assert "ipv4" in r.json()["error"].lower()


async def test_dns_config_allows_private_lan_resolver(setup):
    # A LAN resolver (e.g. Pi-hole) that ISN'T the router itself is fine.
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"direct_dns": "192.168.8.5"})
    assert r.status_code == 200
    assert r.json()["dns"]["direct_dns"] == "192.168.8.5"


async def test_dns_config_rejects_hostname_resolver(setup):
    # direct_dns bootstraps name resolution, so a hostname is circular → IP only.
    client, *_ = setup
    r = await client.post("/api/dns/config", json={"direct_dns": "dns.example.com"})
    assert r.status_code == 400
    assert "hostname" in r.json()["error"].lower()


async def test_dns_config_default_preserved_on_startup(setup):
    client, *_ = setup
    r = await client.get("/api/state")
    assert r.json()["dns"]["doh_url"] == DEFAULT_DOH_URL


# --- /api/rules-url --------------------------------------------------------


async def test_rules_url_set_and_clear(setup):
    client, state, pipeline, routes = setup
    routes.add(
        "http://rules.test/rules.json",
        httpx.Response(
            200,
            json={
                "rules": [
                    {"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"},
                ]
            },
        ),
    )
    r = await client.post("/api/rules-url", json={"url": "http://rules.test/rules.json"})
    assert r.status_code == 200
    body = r.json()
    assert body["rules_url"] == "http://rules.test/rules.json"
    assert body["rules_count"] == 1

    # Clear with empty URL.
    r = await client.post("/api/rules-url", json={"url": ""})
    assert r.status_code == 200
    assert r.json()["rules_url"] == ""
    assert r.json()["rules_count"] == 0


async def test_rules_url_rejects_non_http_scheme(setup):
    # A non-http(s) scheme is rejected at the schema layer (don't rely solely on
    # httpx to refuse file:// / ftp:// etc.). The app maps validation errors → 400.
    client, *_ = setup
    r = await client.post("/api/rules-url", json={"url": "file:///etc/passwd"})
    assert r.status_code == 400


async def test_rules_refresh_requires_existing_url(setup):
    client, *_ = setup
    r = await client.post("/api/rules/refresh")
    assert r.status_code == 400


# --- applying flag --------------------------------------------------------


async def test_applying_flag_set_synchronously_on_toggle(setup):
    client, state, _, routes = setup
    routes.add("http://p.test/x", httpx.Response(200, text=SAMPLE_VLESS_BODY))
    add = await client.post("/api/subscriptions", json={"label": "X", "source": "http://p.test/x"})
    sub = add.json()["subscriptions"][0]
    await client.post(
        "/api/server", json={"subscription_id": sub["id"], "server_id": sub["servers"][0]["id"]}
    )
    r = await client.post("/api/toggle", json={"on": True})
    # The handler sets applying=True before responding; the UI's next /state
    # poll thus shows it true. No real apply pipeline running here, so it
    # stays true.
    assert r.json()["applying"] is True


# --- exit IP --------------------------------------------------------------


def test_parse_trace():
    kv = parse_trace("fl=1f23\nip=203.0.113.7\nts=1\nloc=NL\ncolo=AMS\n")
    assert kv["ip"] == "203.0.113.7"
    assert kv["loc"] == "NL"


async def test_exit_ip_returns_parsed_ip(setup):
    client, _, _, routes = setup
    routes.add(
        "https://cloudflare.com/cdn-cgi/trace",
        httpx.Response(200, text="ip=203.0.113.7\nloc=NL\n"),
    )
    r = await client.get("/api/exit-ip")
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True
    assert body["ip"] == "203.0.113.7"
    assert body["country"] == "NL"


async def test_routes_work_against_the_production_fetcher(tmp_path):
    """Every other test injects a bare `httpx.AsyncClient`, so the routes were
    only ever exercised against a type production doesn't use. `ProxiedFetcher`
    shipped without `get()` and both of these endpoints raised AttributeError —
    not caught by their `except (httpx.HTTPError, OSError)` — so they were hard
    500s on a real router while the suite stayed green.
    """
    from kitewrt.proxied import ProxiedFetcher

    routes = FakeRouteMap()
    routes.add(
        "https://cloudflare.com/cdn-cgi/trace",
        httpx.Response(200, text="ip=203.0.113.7\nloc=NL\n"),
    )
    inner = httpx.AsyncClient(transport=httpx.MockTransport(routes.handle))
    fetcher = ProxiedFetcher(inner, httpx.AsyncClient())
    app = create_app(State(tmp_path / "state.json"), FakePipeline(), fetcher)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r = await client.get("/api/exit-ip")
        assert r.status_code == 200, r.text
        assert r.json()["ip"] == "203.0.113.7"

        r = await client.get("/api/connectivity")
        assert r.status_code == 200, r.text
    await fetcher.aclose()


async def test_exit_ip_cache_busts_on_vpn_toggle(setup):
    client, state, _, routes = setup
    routes.add(
        "https://cloudflare.com/cdn-cgi/trace",
        httpx.Response(200, text="ip=1.2.3.4\nloc=US\n"),
    )
    await client.get("/api/exit-ip")  # vpn off → fetch #1
    await client.get("/api/exit-ip")  # same vpn_on → served from cache
    await state.update(lambda d: setattr(d, "vpn_on", True))
    await client.get("/api/exit-ip")  # vpn flipped → cache busted → fetch #2
    trace_hits = sum(1 for r in routes.requests if "cdn-cgi/trace" in str(r.url))
    assert trace_hits == 2


# --- connectivity ---------------------------------------------------------


async def test_connectivity_probes_targets(setup):
    from kitewrt.routes.connectivity import TARGETS

    client, _, _, routes = setup
    for _name, url in TARGETS:
        routes.add(url, httpx.Response(204))
    r = await client.get("/api/connectivity")
    body = r.json()
    assert {t["name"] for t in body["targets"]} == {n for n, _ in TARGETS}
    assert all(t["ok"] for t in body["targets"])


async def test_connectivity_marks_unreachable_on_error(setup):
    client, _, _, routes = setup

    def boom(_request):
        raise httpx.ConnectError("unreachable")

    from kitewrt.routes.connectivity import TARGETS

    routes.add(TARGETS[0][1], boom)  # Google fails
    for _name, url in TARGETS[1:]:
        routes.add(url, httpx.Response(200))
    body = (await client.get("/api/connectivity")).json()
    by_name = {t["name"]: t for t in body["targets"]}
    assert by_name["Google"]["ok"] is False
    assert by_name["Cloudflare"]["ok"] is True


def test_frontend_dns_defaults_match_the_backend():
    """The UI's "Reset to defaults" writes these, so a mismatch silently
    degrades the config the user just asked to restore.

    It did: the frontend said `cloudflare-dns.com` while the backend default is
    the IP literal `1.1.1.1` — chosen deliberately, because `dns-bootstrap`
    dials it to resolve the proxy servers' own domains, so a hostname there
    would need resolving to be resolved. The mismatch also meant the button
    never read as already-default on a fresh install.
    """
    import re

    from kitewrt.state import DEFAULT_DIRECT_DNS

    src = (Path(__file__).resolve().parent.parent / "web" / "src" / "api.ts").read_text()
    found = dict(re.findall(r"export const (DEFAULT_\w+) = '([^']+)'", src))
    assert found.get("DEFAULT_DOH_URL") == DEFAULT_DOH_URL
    assert found.get("DEFAULT_DIRECT_DNS") == DEFAULT_DIRECT_DNS


def test_frontend_capture_messages_match_the_backend():
    """The watchdog reports three different capture events down one channel.

    `report_capture_gap` writes `last_apply` with **ok=True**, so a self-healed
    gap — a measured 4-21 s window of forwarded plaintext and cleartext DNS —
    renders as a tick and the grey line "last applied 2m ago" unless the UI
    picks it back out. `report_capture_lost` writes ok=False, which the dash
    would otherwise show as a generic "Apply failed" box.

    The only thing distinguishing them on the wire is the message string, so
    web/src/health.ts matches on it verbatim. Pin it: a reworded banner here
    would silently turn a standing alarm into a grey apply error, and nothing
    else in the test suite would notice.
    """
    import re

    from kitewrt.dataplane import _CAPTURE_GAP_MSG, _CAPTURE_LOST_MSG

    src = (Path(__file__).resolve().parent.parent / "web" / "src" / "health.ts").read_text()
    found = dict(re.findall(r'export const (CAPTURE_\w+) =\s*"([^"]+)"', src))
    assert found.get("CAPTURE_GAP_MSG") == _CAPTURE_GAP_MSG
    assert found.get("CAPTURE_LOST_MSG") == _CAPTURE_LOST_MSG


# --- metrics pump -----------------------------------------------------------


async def test_metrics_pump_publishes_a_frame_when_clash_is_down():
    """A Clash outage must still push, and must not resample the router.

    Publishing only on the happy path left an already-connected client with no
    frame at all, so the dashboard kept rendering the last live throughput and
    connection counts as though the tunnel were healthy — only a reload, which
    primes from `latest_frame()`, revealed `available: false`. Measured: 3 s of
    Clash errors with the VPN on delivered zero frames.

    The second `system.sample()` on this path was its own bug: it deltas over a
    sub-millisecond window and reported `cpu_percent 50.0` on an idle router
    against an honest 1.99, and that frame is what `/api/metrics` serves.
    """
    import asyncio as _asyncio

    from kitewrt.api import _metrics_pump
    from kitewrt.metrics_store import MetricsStore
    from kitewrt.singbox.clash import ClashError

    class FakeHub:
        has_clients = True

        def __init__(self):
            self.frames = []

        def publish(self, msg):
            self.frames.append(msg)

    class FakeState:
        def snapshot(self):
            return type("S", (), {"vpn_on": True})()

    class DownClash:
        async def connections(self):
            raise ClashError("controller unreachable")

        async def current(self, _tag):
            raise ClashError("controller unreachable")

    class CountingSystem:
        def __init__(self):
            self.calls = 0

        def sample(self, mono_now=None):
            self.calls += 1
            return {"cpu_percent": 1.0, "wan_device": "eth1"}

    hub, system = FakeHub(), CountingSystem()
    task = _asyncio.ensure_future(
        _metrics_pump(hub, FakeState(), DownClash(), MetricsStore(), system=system)
    )
    await _asyncio.sleep(1.3)  # one tick (the pump sleeps 1 s first)
    task.cancel()
    with contextlib.suppress(_asyncio.CancelledError):
        await task

    assert hub.frames, "a Clash outage delivered no frame at all"
    data = hub.frames[-1]["data"]
    assert data["available"] is False
    assert data["cpu_percent"] == 1.0  # router health still flows
    assert system.calls == 1, "the router was sampled twice in one tick"


async def test_compression_wraps_redaction_not_the_other_way_round(setup):
    """Ordering, not just presence. `GZipMiddleware` must be added LAST so it is
    outermost and compresses *after* `_redact_secrets` has read and rewritten
    the JSON. Added first it is innermost, and redaction gets an already-gzipped
    body to `json.loads` — which fails silently and ships the response through
    with the per-server secrets still in it."""
    client, *_ = setup
    r = await client.get("/api/state", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200
    body = r.json()  # would raise if redaction had mangled a compressed body
    for sub in body.get("subscriptions", []):
        for srv in sub.get("servers", []):
            assert not {"uuid", "password", "method", "params"} & set(srv)


async def test_the_swagger_page_is_not_served(setup):
    """`/docs` was the one page here that pulled third-party JavaScript — a
    CDN's `swagger-ui-dist@5`, floating major tag, no SRI — into the daemon's
    own origin, which every guard in this app trusts absolutely."""
    client, *_ = setup
    assert (await client.get("/docs")).status_code == 404
    assert (await client.get("/openapi.json")).status_code == 404


async def test_hashed_assets_are_cacheable_and_index_is_not(setup):
    """`index()` claimed "the hashed assets themselves stay cacheable" and they
    were not: measured on the wire, `/assets/*` returned etag + last-modified
    and **no** `Cache-Control`, so every reload revalidated. Vite hashes those
    filenames and the build deletes the old ones, so the bytes behind a URL can
    never change — while index.html must keep revalidating, or an upgrade leaves
    the browser asking for asset names that no longer exist."""
    import glob

    client, *_ = setup
    assets = glob.glob("kitewrt/static/assets/*.js")
    assert assets, "no built bundle to check"
    name = assets[0].rsplit("/", 1)[-1]

    r = await client.get(f"/assets/{name}")
    assert r.status_code == 200
    assert "immutable" in r.headers.get("cache-control", "")

    assert (await client.get("/")).headers.get("cache-control") == "no-cache"


def test_the_shutdown_teardown_outlasts_one_contended_iptables_call():
    """3 s bounded the whole teardown while a single `iptables -w 5` inside it
    blocks 5.02 s, so under any contention past 3 s it timed out having done
    nothing — deterministically. Measured: `stop` returned rc=0 in under a
    second, the log said "teardown did not finish within 3.0s", and the capture
    was left complete. procd then stops sing-box at STOP=10 and the LAN goes
    fully dark — TCP and DNS time out and ping is 100% lost, because the chain's
    terminal DROP eats ICMP too. Nothing self-heals; recovery needs SSH."""
    from kitewrt import api, divert

    wait_s = float(divert._IPT[divert._IPT.index("-w") + 1])
    assert wait_s * 2 < api._TEARDOWN_BUDGET_S, (
        "the teardown must outlast more than one contended call, not fewer"
    )
