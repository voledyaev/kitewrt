"""kitewrt.endpoints — remembered addresses for named VPN servers.

What it protects: a DoH block used to take down every domain-addressed node
(measured on the live router: `lookup ams…: dial tcp <doh-ip>:443` on every
connection, because sing-box re-resolved per dial through one DoH endpoint).
"""

from __future__ import annotations

import socket
import struct

import httpx
import pytest
from kitewrt import endpoints
from kitewrt.endpoints import (
    acceptable,
    build_query,
    doh_sources,
    parse_a_records,
    refresh,
    resolve,
    server_hostnames,
)
from kitewrt.singbox.config import build_config
from kitewrt.state import ActiveServerRef, Data, ResolvedEndpoint, State, Subscription
from kitewrt.vless import Server


def _answer(host: str, ips: list[str], *, rcode: int = 0) -> bytes:
    """A DNS response to `build_query(host)`, answers as compression pointers."""
    q = build_query(host)
    header = struct.pack(">HHHHHH", 0, 0x8180 | rcode, 1, len(ips), 0, 0)
    body = q[12:]
    for ip in ips:
        body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
    return header + body


def test_wire_format_round_trip():
    msg = _answer("ams.example.net", ["87.199.195.89", "87.199.195.90"])
    assert parse_a_records(msg) == ["87.199.195.89", "87.199.195.90"]


def test_nxdomain_has_no_answers():
    assert parse_a_records(_answer("nope.example", [], rcode=3)) == []


def test_malformed_response_raises():
    with pytest.raises(ValueError):
        parse_a_records(b"\x00\x01garbage")


@pytest.mark.parametrize(
    ("ip", "ok"),
    [
        ("87.199.195.89", True),
        ("0.0.0.0", False),  # a sinkhole answer
        ("127.0.0.1", False),
        ("10.10.34.35", False),  # an ISP block page on a private address
        ("198.18.0.5", False),  # our own fake-IP range
        ("2a03:2880::1", False),  # the data plane is IPv4-only
    ],
)
def test_only_public_unicast_ipv4_is_accepted(ip, ok):
    assert acceptable(ip) is ok


def test_custom_doh_goes_first_without_duplicates():
    assert doh_sources("") == list(endpoints.BUILTIN_DOH)
    custom = endpoints.BUILTIN_DOH[2]
    assert doh_sources(custom)[0] == custom
    assert doh_sources(custom).count(custom) == 1


def _client(by_url: dict[str, list[str] | int]) -> httpx.AsyncClient:
    """DoH endpoints answering per URL host: a list of IPs, or an HTTP status."""

    def handler(req: httpx.Request) -> httpx.Response:
        r = by_url.get(f"https://{req.url.host}/dns-query", 599)
        if isinstance(r, int):
            return httpx.Response(r)
        return httpx.Response(200, content=_answer("x", r))

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_resolve_falls_through_dead_doh_to_the_next(monkeypatch):
    async def no_system(host):
        raise AssertionError("must not reach the router's resolver")

    monkeypatch.setattr(endpoints, "via_system", no_system)
    client = _client({"https://8.8.8.8/dns-query": ["87.199.195.89"]})
    res = await resolve("ams.example.net", client, doh_sources(""))
    assert res == (["87.199.195.89"], "https://8.8.8.8/dns-query")


async def test_resolve_uses_the_routers_resolver_when_all_doh_is_blocked(monkeypatch):
    async def system(host):
        return ["87.199.195.89"]

    monkeypatch.setattr(endpoints, "via_system", system)
    res = await resolve("ams.example.net", _client({}), doh_sources(""))
    assert res == (["87.199.195.89"], "system")


async def test_a_sinkhole_answer_is_not_a_result(monkeypatch):
    async def system(host):
        return ["0.0.0.0"]

    monkeypatch.setattr(endpoints, "via_system", system)
    client = _client({"https://1.1.1.1/dns-query": ["127.0.0.1"]})
    assert await resolve("ams.example.net", client, doh_sources("")) is None


def _state(tmp_path, hosts: list[str], known: dict[str, str] | None = None) -> State:
    st = State(tmp_path / "s.json")
    servers = [Server(id=f"{h}:443", name=h, country="NL", host=h, port=443) for h in hosts]
    sub = Subscription(id="s1", label="L", source="x", fetched_at="t", servers=servers)
    # Seeded directly: refresh() only reads the snapshot, and State.update is
    # async (these helpers are shared by sync and async tests alike).
    st._data.subscriptions = [sub]
    st._data.endpoints = {h: ResolvedEndpoint(ip=ip, at="t") for h, ip in (known or {}).items()}
    return st


async def test_refresh_only_reports_real_moves(tmp_path, monkeypatch):
    """Round-robin DNS reordering its answers must not cost a sing-box restart."""
    st = _state(
        tmp_path,
        ["a.example.net", "b.example.net", "1.2.3.4"],
        known={"a.example.net": "5.5.5.5", "gone.example.net": "6.6.6.6"},
    )
    answers = {"a.example.net": ["7.7.7.7", "5.5.5.5"], "b.example.net": ["8.8.4.4"]}

    async def fake_resolve(host, client, sources):
        return answers[host], "https://1.1.1.1/dns-query"

    monkeypatch.setattr(endpoints, "resolve", fake_resolve)
    changed, forget = await refresh(st, _client({}))
    assert set(changed) == {"b.example.net"}  # a: current 5.5.5.5 still answered
    assert changed["b.example.net"].ip == "8.8.4.4"
    assert forget == {"gone.example.net"}  # no longer in any subscription


async def test_refresh_keeps_the_last_good_address_when_nothing_answers(tmp_path, monkeypatch):
    st = _state(tmp_path, ["a.example.net"], known={"a.example.net": "5.5.5.5"})

    async def nothing(host, client, sources):
        return None

    monkeypatch.setattr(endpoints, "resolve", nothing)
    changed, forget = await refresh(st, _client({}))
    assert changed == {} and forget == set()


def test_server_hostnames_skips_ip_literals():
    servers = [
        Server(id="a:443", name="a", country="NL", host="ams.example.net", port=443),
        Server(id="b:443", name="b", country="NL", host="95.135.48.10", port=443),
    ]
    d = Data(
        subscriptions=[Subscription(id="s", label="L", source="x", fetched_at="t", servers=servers)]
    )
    assert server_hostnames(d) == {"ams.example.net"}


def test_config_dials_the_remembered_address_but_checks_the_name():
    srv = Server(
        id="ams.example.net:443",
        name="AMS",
        country="NL",
        type="vless",
        host="ams.example.net",
        port=443,
        uuid="00000000-0000-4000-8000-000000000000",
        params={"security": "tls", "type": "tcp"},
    )
    sub = Subscription(id="s1", label="L", source="x", fetched_at="t", servers=[srv])
    d = Data(
        subscriptions=[sub],
        active_server=ActiveServerRef(subscription_id="s1", server_id=srv.id),
        vpn_on=True,
    )
    plain = next(o for o in build_config(d)["outbounds"] if o["tag"].startswith("s1/"))
    assert plain["server"] == "ams.example.net"

    d.endpoints = {"ams.example.net": ResolvedEndpoint(ip="87.199.195.89", at="t")}
    pinned = next(o for o in build_config(d)["outbounds"] if o["tag"].startswith("s1/"))
    assert pinned["server"] == "87.199.195.89"
    assert pinned["tls"]["server_name"] == "ams.example.net"
