"""Hermetic tests for the sing-box config generator (kitewrt.singbox.*).

No router, no sing-box binary — pure dict-shape assertions. The shapes here
were validated against `sing-box check` v1.13 on the actual device; these
tests lock them so refactors don't silently break the generated config.
"""

from __future__ import annotations

from kitewrt.singbox.config import (
    SELECTOR_TAG,
    active_tag,
    build_config,
    selector_default,
)
from kitewrt.singbox.dns import DNS_DIRECT, DNS_FAKE, DNS_LOCAL, DNS_PROXY, build_dns
from kitewrt.singbox.outbound import (
    build_hysteria2_outbound,
    build_hysteria_outbound,
    build_outbound,
    build_shadowsocks_outbound,
    build_trojan_outbound,
    build_tuic_outbound,
    build_vless_outbound,
    build_vmess_outbound,
    outbound_tag,
)
from kitewrt.singbox.route import build_route, default_route_rules
from kitewrt.state import ActiveServerRef, Data, DnsState, Subscription
from kitewrt.vless import Server


def _reality_server(host="de-dp-01.com", port=8443, uuid="u-1") -> Server:
    return Server(
        id=f"{host}:{port}",
        name="DE",
        country="DE",
        host=host,
        port=port,
        uuid=uuid,
        params={
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": "storage.example.com",
            "fp": "firefox",
            "pbk": "publickeybase64",
            "sid": "abcd1234",
            "type": "tcp",
        },
    )


def _hysteria2_server(host="fi-gaming.com", port=443) -> Server:
    return Server(
        id=f"{host}:{port}",
        name="FI GAMING",
        country="FI",
        type="hysteria2",
        host=host,
        port=port,
        password="s3cr3t",
        params={"sni": "fi-gaming.com", "insecure": "1"},
    )


def _data(*, vpn_on=True, active=True, rules=None) -> Data:
    srv = _reality_server()
    sub = Subscription(
        id="sub-1", label="example", source="https://x", fetched_at="t", servers=[srv]
    )
    ref = ActiveServerRef(subscription_id="sub-1", server_id=srv.id) if active else None
    return Data(
        subscriptions=[sub],
        active_server=ref,
        vpn_on=vpn_on,
        rules=rules or [],
        dns=DnsState(),
    )


# --- outbound ---------------------------------------------------------------


def test_reality_outbound_shape():
    srv = _reality_server()
    ob = build_vless_outbound(srv, "tagX")
    assert ob["type"] == "vless"
    assert ob["tag"] == "tagX"
    assert ob["server"] == "de-dp-01.com"
    assert ob["server_port"] == 8443
    assert ob["uuid"] == "u-1"
    assert ob["flow"] == "xtls-rprx-vision"
    assert ob["tls"]["enabled"] is True
    assert ob["tls"]["server_name"] == "storage.example.com"
    assert ob["tls"]["utls"] == {"enabled": True, "fingerprint": "firefox"}
    assert ob["tls"]["reality"] == {
        "enabled": True,
        "public_key": "publickeybase64",
        "short_id": "abcd1234",
    }
    # tcp network → no transport block
    assert "transport" not in ob


def test_flow_omitted_when_absent():
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        host="h",
        port=443,
        uuid="u",
        params={"security": "reality", "pbk": "k", "sni": "s"},
    )
    assert "flow" not in build_vless_outbound(srv, "t")


def test_reality_server_name_falls_back_to_host():
    # Reality needs a real SNI; a link missing `sni` must fall back to the host
    # rather than emit server_name="" (which dooms the handshake).
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        host="real-host.example",
        port=443,
        uuid="u",
        params={"security": "reality", "pbk": "k", "sid": "ab"},  # no sni
    )
    ob = build_vless_outbound(srv, "t")
    assert ob["tls"]["server_name"] == "real-host.example"


def test_flow_dropped_when_transport_present():
    # xtls-rprx-vision is TCP-only; a malformed link carrying both flow and a
    # ws/grpc transport must drop the flow (sing-box rejects the combination).
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        host="h",
        port=443,
        uuid="u",
        params={"flow": "xtls-rprx-vision", "security": "tls", "type": "ws", "path": "/r"},
    )
    ob = build_vless_outbound(srv, "t")
    assert "flow" not in ob
    assert ob["transport"]["type"] == "ws"


def test_plain_tls_outbound():
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        host="h",
        port=443,
        uuid="u",
        params={"security": "tls", "sni": "s", "fp": "chrome"},
    )
    ob = build_vless_outbound(srv, "t")
    assert ob["tls"]["enabled"] is True
    assert "reality" not in ob["tls"]
    assert ob["tls"]["alpn"] == ["h2", "http/1.1"]


def test_ws_transport():
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        host="h",
        port=443,
        uuid="u",
        params={"security": "tls", "type": "ws", "path": "/ray", "host": "cdn.example.com"},
    )
    ob = build_vless_outbound(srv, "t")
    assert ob["transport"] == {
        "type": "ws",
        "path": "/ray",
        "headers": {"Host": "cdn.example.com"},
    }


def test_grpc_transport():
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        host="h",
        port=443,
        uuid="u",
        params={"security": "reality", "type": "grpc", "path": "/GunService", "pbk": "k"},
    )
    ob = build_vless_outbound(srv, "t")
    assert ob["transport"] == {"type": "grpc", "service_name": "GunService"}


def test_hysteria2_outbound_shape():
    ob = build_hysteria2_outbound(_hysteria2_server(), "tagH")
    assert ob["type"] == "hysteria2"
    assert ob["tag"] == "tagH"
    assert ob["server"] == "fi-gaming.com"
    assert ob["server_port"] == 443
    assert ob["password"] == "s3cr3t"
    assert "uuid" not in ob
    assert ob["tls"]["enabled"] is True
    assert ob["tls"]["server_name"] == "fi-gaming.com"
    assert ob["tls"]["insecure"] is True
    # no obfs param → no obfs block
    assert "obfs" not in ob


def test_hysteria2_obfs_block():
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        type="hysteria2",
        host="h",
        port=443,
        password="pw",
        params={"obfs": "salamander", "obfs-password": "xyz"},
    )
    ob = build_hysteria2_outbound(srv, "t")
    assert ob["obfs"] == {"type": "salamander", "password": "xyz"}
    # sni absent → server_name falls back to host
    assert ob["tls"]["server_name"] == "h"
    assert ob["tls"]["insecure"] is False


def test_build_outbound_dispatches_by_type():
    assert build_outbound(_reality_server(), "t")["type"] == "vless"
    assert build_outbound(_hysteria2_server(), "t")["type"] == "hysteria2"
    for t in ("hysteria", "shadowsocks", "vmess", "trojan", "tuic"):
        srv = Server(id="h:443", name="x", country="??", type=t, host="h", port=443)
        assert build_outbound(srv, "tag")["type"] == t
    # Unknown / legacy type falls back to the vless builder.
    legacy = Server(id="h:443", name="x", country="??", type="weird", host="h", port=443, uuid="u")
    assert build_outbound(legacy, "tag")["type"] == "vless"


def test_trojan_outbound_shape():
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        type="trojan",
        host="h",
        port=443,
        password="pw",
        params={"sni": "a.com", "type": "ws", "path": "/p", "alpn": "h2,http/1.1"},
    )
    ob = build_trojan_outbound(srv, "tagT")
    assert ob["type"] == "trojan"
    assert ob["password"] == "pw"
    assert ob["tls"]["server_name"] == "a.com"
    assert ob["tls"]["alpn"] == ["h2", "http/1.1"]
    assert ob["transport"] == {"type": "ws", "path": "/p"}


def test_tuic_outbound_shape():
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        type="tuic",
        host="h",
        port=443,
        uuid="uu",
        password="pw",
        params={"alpn": "h3"},
    )
    ob = build_tuic_outbound(srv, "t")
    assert ob["type"] == "tuic"
    assert ob["uuid"] == "uu"
    assert ob["password"] == "pw"
    assert ob["congestion_control"] == "bbr"  # defaulted
    assert ob["tls"]["alpn"] == ["h3"]


def test_hysteria_v1_outbound_shape():
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        type="hysteria",
        host="h",
        port=443,
        password="tok",
        params={"upmbps": "100", "downmbps": "200", "obfs": "xplus", "insecure": "1"},
    )
    ob = build_hysteria_outbound(srv, "t")
    assert ob["type"] == "hysteria"
    assert ob["auth_str"] == "tok"
    assert ob["up_mbps"] == 100
    assert ob["down_mbps"] == 200
    assert ob["obfs"] == "xplus"
    assert ob["tls"]["insecure"] is True


def test_shadowsocks_outbound_shape():
    srv = Server(
        id="h:8388",
        name="x",
        country="??",
        type="shadowsocks",
        host="h",
        port=8388,
        password="secret",
        method="aes-256-gcm",
        params={"plugin": "obfs-local;obfs=tls"},
    )
    ob = build_shadowsocks_outbound(srv, "t")
    assert ob["type"] == "shadowsocks"
    assert ob["method"] == "aes-256-gcm"
    assert ob["password"] == "secret"
    assert ob["plugin"] == "obfs-local"
    assert ob["plugin_opts"] == "obfs=tls"


def test_vmess_outbound_shape():
    srv = Server(
        id="h:443",
        name="x",
        country="??",
        type="vmess",
        host="h",
        port=443,
        uuid="uuid-x",
        params={"net": "grpc", "path": "svc", "tls": "tls", "aid": "0"},
    )
    ob = build_vmess_outbound(srv, "t")
    assert ob["type"] == "vmess"
    assert ob["uuid"] == "uuid-x"
    assert ob["security"] == "auto"
    assert ob["alter_id"] == 0
    assert ob["tls"]["enabled"] is True
    assert ob["transport"] == {"type": "grpc", "service_name": "svc"}


def test_config_includes_hysteria2_outbound_in_selector():
    srv_v = _reality_server()
    srv_h = _hysteria2_server()
    sub = Subscription(
        id="sub-1", label="mix", source="https://x", fetched_at="t", servers=[srv_v, srv_h]
    )
    snap = Data(subscriptions=[sub], vpn_on=True, dns=DnsState())
    cfg = build_config(snap)
    types = [o["type"] for o in cfg["outbounds"]]
    assert types == ["vless", "hysteria2", "selector", "direct"]
    selector = next(o for o in cfg["outbounds"] if o["type"] == "selector")
    assert outbound_tag("sub-1", srv_h.id) in selector["outbounds"]


def test_outbound_tag_is_composite_and_unique():
    assert outbound_tag("sub-1", "h:443") == "sub-1/h:443"
    assert outbound_tag("sub-1", "h:443") != outbound_tag("sub-2", "h:443")


# --- route ------------------------------------------------------------------


def test_route_default_is_plain_full_tunnel():
    r = build_route(None, None, SELECTOR_TAG)
    # baseline only — no geo, no country assumptions
    assert r["rules"] == [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    assert {"action": "resolve"} not in r["rules"]
    assert r["final"] == SELECTOR_TAG
    assert r["auto_detect_interface"] is True
    # No bundled geo → no rule_set defs unless the user supplies them.
    assert "rule_set" not in r


def test_route_passes_user_rules_and_remote_rule_sets():
    user = [{"rule_set": ["geoip-x"], "outbound": "direct"}]
    rsets = [
        {
            "type": "remote",
            "tag": "geoip-x",
            "format": "binary",
            "url": "https://example.test/geoip-x.srs",
            "download_detour": "proxy",
        }
    ]
    r = build_route(user, rsets, SELECTOR_TAG)
    assert r["rules"][0] == {"action": "sniff"}
    assert user[0] in r["rules"]
    # rule-set defs passed through; download_detour "proxy" → selector
    assert r["rule_set"][0]["tag"] == "geoip-x"
    assert r["rule_set"][0]["download_detour"] == SELECTOR_TAG


def test_block_outbound_rewritten_to_reject_action():
    # `block` is accepted as user sugar but emitted as the modern reject action
    # (the legacy block special outbound is deprecated / going away in sing-box).
    user = [{"domain_suffix": ["ads.example"], "outbound": "block"}]
    r = build_route(user, None, SELECTOR_TAG)
    blocked = next(rule for rule in r["rules"] if rule.get("domain_suffix") == ["ads.example"])
    assert blocked == {"domain_suffix": ["ads.example"], "action": "reject"}
    assert "outbound" not in blocked


def test_no_block_outbound_in_config():
    # The legacy block special outbound must not be emitted at all.
    cfg = build_config(_data())
    assert all(o["type"] != "block" for o in cfg["outbounds"])


def test_default_route_rules_empty():
    assert default_route_rules() == []


def test_proxy_alias_rewritten_to_selector():
    user = [
        {"domain_suffix": ["example.test"], "outbound": "proxy"},
        {"domain_suffix": [".example"], "outbound": "direct"},
    ]
    r = build_route(user, None, SELECTOR_TAG)
    rewritten = next(rule for rule in r["rules"] if rule.get("domain_suffix") == ["example.test"])
    assert rewritten["outbound"] == SELECTOR_TAG  # "proxy" → selector
    passthrough = next(rule for rule in r["rules"] if rule.get("domain_suffix") == [".example"])
    assert passthrough["outbound"] == "direct"  # untouched


# --- dns --------------------------------------------------------------------


def test_dns_resolvers_direct_fake_doh_and_local():
    dns = build_dns("https://cloudflare-dns.com/dns-query", SELECTOR_TAG)
    by_tag = {s["tag"]: s for s in dns["servers"]}
    assert by_tag[DNS_PROXY]["type"] == "https"
    assert by_tag[DNS_PROXY]["server"] == "cloudflare-dns.com"
    assert by_tag[DNS_PROXY]["path"] == "/dns-query"
    assert by_tag[DNS_PROXY]["detour"] == SELECTOR_TAG  # foreign DNS over proxy
    # dns-direct uses the router's own resolver — no hardcoded IP.
    assert by_tag[DNS_DIRECT]["type"] == "local"
    assert "server" not in by_tag[DNS_DIRECT]
    # fake-IP resolver: v4-only range, no v6 (the data plane is v4-only).
    assert by_tag[DNS_FAKE]["type"] == "fakeip"
    assert by_tag[DNS_FAKE]["inet4_range"] == "198.18.0.0/15"
    assert "inet6_range" not in by_tag[DNS_FAKE]
    # router-local resolver for *.lan / localhost (so LAN-by-name keeps working).
    assert by_tag[DNS_LOCAL]["type"] == "local"
    # DoH is the final (non-A/AAAA foreign queries); v4-only strategy.
    assert dns["final"] == DNS_PROXY
    assert dns["strategy"] == "ipv4_only"
    assert dns["independent_cache"] is True
    # No user rules → LAN-names rule first, then the catch-all (all A/AAAA → fake).
    assert dns["rules"] == [
        {"domain_suffix": ["lan", "localhost"], "server": DNS_LOCAL},
        {"query_type": ["A", "AAAA"], "server": DNS_FAKE},
    ]


def test_dns_mirrors_user_routing_rules():
    # A proxy override before a broad direct rule: DNS must keep the order so the
    # overridden name gets a fake IP (→ proxy), not a real direct-path answer.
    user_rules = [
        {"domain_suffix": ["example.net"], "outbound": "proxy"},
        {"domain_suffix": [".example"], "outbound": "direct"},
        {"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"},  # IP-only: dropped
    ]
    dns = build_dns("https://cloudflare-dns.com/dns-query", SELECTOR_TAG, user_rules)
    assert dns["rules"] == [
        # LAN-names rule always comes first.
        {"domain_suffix": ["lan", "localhost"], "server": DNS_LOCAL},
        {"domain_suffix": ["example.net"], "server": DNS_FAKE},
        {"domain_suffix": [".example"], "server": DNS_DIRECT},
        # catch-all appended last: remaining foreign A/AAAA → fake IP
        {"query_type": ["A", "AAAA"], "server": DNS_FAKE},
    ]


def test_dns_doh_without_path():
    dns = build_dns("https://dns.example", SELECTOR_TAG)
    proxy = next(s for s in dns["servers"] if s["tag"] == DNS_PROXY)
    assert proxy["server"] == "dns.example"
    assert "path" not in proxy


def test_direct_dns_plain_ip_no_port():
    dns = build_dns("https://dns.example", SELECTOR_TAG, direct_dns="1.1.1.1")
    direct = next(s for s in dns["servers"] if s["tag"] == DNS_DIRECT)
    assert direct["type"] == "udp"
    assert direct["server"] == "1.1.1.1"
    assert "server_port" not in direct


def test_direct_dns_host_port_split():
    # A `host:port` value splits into server + server_port (a typed server
    # rejects "host:port" crammed into `server`).
    dns = build_dns("https://dns.example", SELECTOR_TAG, direct_dns="9.9.9.9:5353")
    direct = next(s for s in dns["servers"] if s["tag"] == DNS_DIRECT)
    assert direct["server"] == "9.9.9.9"
    assert direct["server_port"] == 5353


# --- config assembly --------------------------------------------------------


def test_inbound_is_single_tun():
    # One tun inbound; auto_route + strict_route make sing-box own the LAN
    # capture (no iptables redirect/tproxy chains). IPv4-only /30.
    from kitewrt.singbox.config import TUN_ADDRESS, TUN_NAME, TUN_STACK

    inbounds = build_config(_data())["inbounds"]
    assert len(inbounds) == 1
    tun = inbounds[0]
    assert tun["type"] == "tun"
    assert tun["tag"] == "tun-in"
    assert tun["interface_name"] == TUN_NAME
    assert tun["address"] == [TUN_ADDRESS]
    assert tun["auto_route"] is True
    assert tun["strict_route"] is True
    assert tun["stack"] == TUN_STACK


def test_config_full_shape_and_selector_membership():
    cfg = build_config(_data())
    assert [i["type"] for i in cfg["inbounds"]] == ["tun"]
    types = [o["type"] for o in cfg["outbounds"]]
    assert types == ["vless", "selector", "direct"]
    selector = next(o for o in cfg["outbounds"] if o["type"] == "selector")
    # every selector member resolves to a real outbound tag (+ direct)
    real_tags = {o["tag"] for o in cfg["outbounds"]}
    for member in selector["outbounds"]:
        assert member in real_tags
    assert "direct" in selector["outbounds"]
    assert cfg["experimental"]["clash_api"]["external_controller"]
    assert cfg["route"]["default_domain_resolver"] == DNS_DIRECT
    # auto_route handles outbound loop-avoidance internally — no manual
    # default_mark / OUTPUT-skip plumbing (that was the TPROXY-era technique).
    assert "default_mark" not in cfg["route"]


def test_selector_default_on_points_at_active():
    snap = _data(vpn_on=True, active=True)
    assert active_tag(snap) == "sub-1/de-dp-01.com:8443"
    assert selector_default(snap) == "sub-1/de-dp-01.com:8443"
    assert build_config(snap)["outbounds"][1]["default"] == "sub-1/de-dp-01.com:8443"


def test_selector_default_off_points_at_direct():
    assert selector_default(_data(vpn_on=False, active=True)) == "direct"


def test_selector_default_direct_when_no_active():
    assert selector_default(_data(vpn_on=True, active=False)) == "direct"


def test_active_tag_none_for_dangling_selection():
    snap = _data(active=False)
    snap.active_server = ActiveServerRef(subscription_id="sub-1", server_id="ghost:1")
    assert active_tag(snap) is None
    assert selector_default(snap) == "direct"


def test_empty_state_selector_only_direct():
    cfg = build_config(Data())
    selector = next(o for o in cfg["outbounds"] if o["type"] == "selector")
    assert selector["outbounds"] == ["direct"]
    assert selector["default"] == "direct"
