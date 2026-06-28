"""Tests for the FastAPI surface.

Uses httpx.AsyncClient + ASGITransport to drive the app in-process — no
sockets, no network. Subscription/rules fetches go through a MockTransport
that maps fake source URLs to canned responses.
"""

from __future__ import annotations

import asyncio

import httpx
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
    new_url = "https://dns.google/dns-query"
    r = await client.post("/api/dns/config", json={"doh_url": new_url})
    assert r.status_code == 200
    body = r.json()
    assert body["dns"]["doh_url"] == new_url
    assert pipeline.signals == 1


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
    # Pointing direct DNS at the router's own resolver loops through the tun's
    # DNS hijack and deadlocks every lookup — must be rejected.
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
    assert len(body["rules"]) == 1

    # Clear with empty URL.
    r = await client.post("/api/rules-url", json={"url": ""})
    assert r.status_code == 200
    assert r.json()["rules_url"] == ""
    assert r.json()["rules"] == []


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
