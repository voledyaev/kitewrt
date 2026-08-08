import base64
import json

import pytest
from kitewrt.vless import (
    MAX_SERVERS_PER_SUBSCRIPTION,
    VlessParseError,
    detect_country,
    parse_hysteria2_link,
    parse_link,
    parse_node,
    parse_subscription,
    unwrap_subscription_uri,
)


@pytest.mark.parametrize(
    "fragment,expected",
    [
        # Flag emoji — the primary, language-agnostic path
        ("\U0001f1f5\U0001f1f1 Poland", "PL"),
        ("\U0001f1e9\U0001f1ea", "DE"),
        ("\U0001f1fa\U0001f1f8 USA", "US"),
        # Flag wins even when the label text after it is decorated / non-English
        ("\U0001f1ed\U0001f1fa⚡Hungary", "HU"),
        # English-name fallback (no flag), decoration stripped
        ("Germany", "DE"),
        ("united states", "US"),
        ("⚡ Poland", "PL"),
        ("(Germany)", "DE"),
        # Unknown
        ("Atlantis", "??"),
        ("", "??"),
    ],
)
def test_detect_country(fragment, expected):
    assert detect_country(fragment) == expected


def test_parse_link_basic_reality():
    uri = (
        "vless://33333333-3333-3333-3333-333333333333@example.com:8443"
        "?security=reality&type=tcp&flow=xtls-rprx-vision&sni=test.example"
        "&fp=chrome&pbk=KEY&sid=SID#%F0%9F%87%B5%F0%9F%87%B1Poland"
    )
    srv = parse_link(uri)
    assert srv.host == "example.com"
    assert srv.port == 8443
    assert srv.uuid == "33333333-3333-3333-3333-333333333333"
    assert srv.id == "example.com:8443"
    assert srv.country == "PL"
    assert srv.params["security"] == "reality"
    assert srv.params["pbk"] == "KEY"


@pytest.mark.parametrize(
    "uri",
    [
        "vless://@example.com:8443",  # missing uuid
        "vless://uuid@:8443",  # missing host
        "vmess://uuid@example.com:8443",  # wrong scheme
    ],
)
def test_parse_link_errors(uri):
    with pytest.raises(VlessParseError):
        parse_link(uri)


def test_parse_link_default_port():
    srv = parse_link("vless://uuid-x@example.com")
    assert srv.port == 443


def test_parse_link_no_fragment_uses_id_as_name():
    srv = parse_link("vless://uuid-x@example.com:1234")
    assert srv.name == "example.com:1234"


def test_parse_vless_sets_type():
    assert parse_link("vless://uuid-x@example.com:1234").type == "vless"


# --- Shadowrocket export dialect --------------------------------------------


def _shadowrocket_uri(authority_plain: str, query: str) -> str:
    blob = base64.b64encode(authority_plain.encode()).decode().rstrip("=")
    return f"vless://{blob}?{query}"


def test_parse_link_shadowrocket_reality():
    """A real Shadowrocket export: base64 authority, remarks label, peer/xtls/
    fingerprint param names, and `tls=1` standing in for security=reality."""
    uri = _shadowrocket_uri(
        "none:44444444-4444-4444-4444-444444444444@node-a.example.net:443",
        "remarks=Node-A-Reality&tls=1&peer=gateway.icloud.com&udp=1&xtls=2"
        "&pbk=PUBKEY&sid=SHORTID&fingerprint=chrome",
    )
    srv = parse_link(uri)
    assert srv.uuid == "44444444-4444-4444-4444-444444444444"
    assert srv.host == "node-a.example.net"
    assert srv.port == 443
    assert srv.id == "node-a.example.net:443"
    # Label comes from `remarks=`, not a #fragment.
    assert srv.name == "Node-A-Reality"
    # The translated params are what the outbound builder reads.
    assert srv.params["security"] == "reality"
    assert srv.params["sni"] == "gateway.icloud.com"
    assert srv.params["fp"] == "chrome"
    assert srv.params["flow"] == "xtls-rprx-vision"
    assert srv.params["pbk"] == "PUBKEY"
    assert srv.params["sid"] == "SHORTID"


def test_shadowrocket_reality_builds_tls_block():
    """Regression guard: without the `security` translation the builder falls
    through to the no-TLS branch and emits a Reality node with no tls block."""
    from kitewrt.singbox.outbound import build_vless_outbound

    uri = _shadowrocket_uri(
        "none:uuid-x@node-a.example.net:443",
        "remarks=N&tls=1&peer=gateway.icloud.com&xtls=2&pbk=PUBKEY&sid=SID&fingerprint=chrome",
    )
    out = build_vless_outbound(parse_link(uri), "sub/ams")
    assert out["flow"] == "xtls-rprx-vision"
    assert out["tls"]["enabled"] is True
    assert out["tls"]["server_name"] == "gateway.icloud.com"
    assert out["tls"]["reality"] == {
        "enabled": True,
        "public_key": "PUBKEY",
        "short_id": "SID",
    }
    assert out["tls"]["utls"]["fingerprint"] == "chrome"


def test_shadowrocket_plain_tls_without_reality_key():
    """`tls=1` with no `pbk` is ordinary TLS, not Reality."""
    uri = _shadowrocket_uri("none:uuid-x@example.com:8443", "remarks=N&tls=1&peer=sni.example")
    assert parse_link(uri).params["security"] == "tls"


def test_shadowrocket_no_tls_stays_plain():
    uri = _shadowrocket_uri("none:uuid-x@example.com:8443", "remarks=N&udp=1")
    assert "security" not in parse_link(uri).params


def test_shadowrocket_obfs_maps_to_transport_type():
    uri = _shadowrocket_uri(
        "none:uuid-x@example.com:8443", "remarks=N&tls=1&obfs=websocket&path=%2Fws"
    )
    srv = parse_link(uri)
    assert srv.params["type"] == "ws"
    assert srv.params["path"] == "/ws"


def test_shadowrocket_blob_keeps_base64_padding():
    """Shadowrocket leaves the '=' padding on; it must not confuse the split."""
    blob = base64.b64encode(b"none:uuid-x@example.com:8443").decode()
    assert blob.endswith("="), "fixture no longer exercises the padded case"
    srv = parse_link(f"vless://{blob}?remarks=N&tls=1")
    assert srv.id == "example.com:8443"
    assert srv.uuid == "uuid-x"


def test_shadowrocket_blob_with_query_and_fragment():
    """The authority ends at whichever of '?' / '#' comes first."""
    blob = base64.b64encode(b"none:uuid-x@example.com:8443").decode().rstrip("=")
    srv = parse_link(f"vless://{blob}#Frag")
    assert srv.id == "example.com:8443"
    assert srv.name == "Frag"


def test_standard_link_params_not_clobbered():
    """A standard link carrying both spellings keeps the standard values."""
    uri = (
        "vless://uuid-x@example.com:8443?security=reality&type=tcp&sni=real.example"
        "&peer=ignored.example&fp=firefox&fingerprint=chrome&flow=xtls-rprx-vision&xtls=1"
    )
    srv = parse_link(uri)
    assert srv.params["sni"] == "real.example"
    assert srv.params["fp"] == "firefox"
    assert srv.params["flow"] == "xtls-rprx-vision"


def test_fragment_wins_over_remarks():
    uri = _shadowrocket_uri("none:uuid-x@example.com:8443", "remarks=FromParam") + "#FromFragment"
    assert parse_link(uri).name == "FromFragment"


def test_shadowrocket_link_parses_via_parse_node_and_subscription():
    """The dialect must work on the paths the app actually uses: inline links go
    through parse_node, subscription bodies through parse_subscription."""
    uri = _shadowrocket_uri("none:uuid-x@example.com:8443", "remarks=N&tls=1&pbk=K")
    assert parse_node(uri).host == "example.com"
    servers = parse_subscription(base64.b64encode(uri.encode()).decode())
    assert [s.id for s in servers] == ["example.com:8443"]


@pytest.mark.parametrize(
    "uri",
    [
        "vless://bm90LWJhc2U2NC1hdC1hbGw?remarks=N",  # decodes, but has no '@'
        "vless://!!!not-base64!!!?remarks=N",  # not base64 at all
    ],
)
def test_shadowrocket_undecodable_still_rejected(uri):
    with pytest.raises(VlessParseError):
        parse_link(uri)


def test_shadowrocket_websocket_node_builds_transport():
    """Shadowrocket's ws export: `obfs`/`obfsParam` carry the carrier and the
    Host header, and `allowInsecure` the cert-verification escape hatch."""
    from kitewrt.singbox.outbound import build_vless_outbound

    uri = _shadowrocket_uri(
        "none:uuid-x@node-a.example.net:8443",
        "path=%2Fws-path-placeholder&remarks=Node-A-WS&obfsParam=www.bing.com"
        "&obfs=websocket&tls=1&peer=www.bing.com&allowInsecure=1&udp=1&fingerprint=chrome",
    )
    srv = parse_link(uri)
    assert srv.id == "node-a.example.net:8443"
    assert srv.name == "Node-A-WS"
    assert srv.params["security"] == "tls"  # tls=1 with no pbk
    assert srv.params["type"] == "ws"
    assert srv.params["host"] == "www.bing.com"  # from obfsParam
    assert srv.params["insecure"] == "1"  # from allowInsecure

    out = build_vless_outbound(srv, "sub/ws")
    assert out["transport"] == {
        "type": "ws",
        "path": "/ws-path-placeholder",
        "headers": {"Host": "www.bing.com"},
    }
    assert out["tls"]["server_name"] == "www.bing.com"
    assert out["tls"]["insecure"] is True
    # xtls-rprx-vision is TCP-only — a ws carrier must not also carry a flow.
    assert "flow" not in out


def test_vless_tls_insecure_defaults_false():
    from kitewrt.singbox.outbound import build_vless_outbound

    srv = parse_link("vless://uuid-x@example.com:8443?security=tls&sni=a.example")
    assert build_vless_outbound(srv, "t")["tls"]["insecure"] is False


def test_hysteria2_shadowrocket_params():
    """A Shadowrocket hysteria2 export is standard-shaped but uses `peer` for
    the SNI; `alpn` must reach the outbound too."""
    from kitewrt.singbox.outbound import build_hysteria2_outbound

    uri = (
        "hysteria2://hy2-password-placeholder@node-a.example.net:443"
        "?peer=www.bing.com&insecure=1&alpn=h3&obfs=salamander"
        "&obfs-password=obfs-password-placeholder#Node-A-HY2"
    )
    srv = parse_node(uri)
    assert srv.type == "hysteria2"
    assert srv.password == "hy2-password-placeholder"
    assert srv.params["sni"] == "www.bing.com"  # aliased from peer
    # `obfs=salamander` is hysteria2 obfuscation, NOT a ws/grpc carrier.
    assert "type" not in srv.params

    out = build_hysteria2_outbound(srv, "sub/hy2")
    assert out["tls"]["server_name"] == "www.bing.com"
    assert out["tls"]["insecure"] is True
    assert out["tls"]["alpn"] == ["h3"]
    assert out["obfs"] == {
        "type": "salamander",
        "password": "obfs-password-placeholder",
    }


# --- sub:// subscription wrapper --------------------------------------------


def test_unwrap_subscription_uri():
    url = "https://provider.example/connection/subs/257f7b6b-0c13"
    blob = base64.b64encode(url.encode()).decode().rstrip("=")
    got_url, label = unwrap_subscription_uri(f"sub://{blob}#%F0%9F%87%AA%F0%9F%87%BA%20Auto")
    assert got_url == url
    assert label == "\U0001f1ea\U0001f1fa Auto"


def test_unwrap_subscription_uri_without_label():
    url = "https://provider.example/sub/tok"
    blob = base64.b64encode(url.encode()).decode().rstrip("=")
    assert unwrap_subscription_uri(f"sub://{blob}") == (url, "")


@pytest.mark.parametrize(
    "source",
    [
        "https://provider.example/sub/tok",
        "vless://uuid-x@example.com:8443",
        "",
    ],
)
def test_unwrap_subscription_uri_passes_through_non_sub(source):
    assert unwrap_subscription_uri(source) == (source, "")


def test_unwrap_subscription_uri_keeps_undecodable_blob():
    """An unparseable blob is left alone so the fetch error names what the user
    actually pasted."""
    src = "sub://!!!not-base64!!!#Label"
    assert unwrap_subscription_uri(src) == (src, "Label")


# --- hysteria2 --------------------------------------------------------------


def test_parse_hysteria2_basic():
    uri = (
        "hysteria2://s3cr3tpass@fi-gaming.example:443"
        "?sni=fi-gaming.example&insecure=1#%F0%9F%87%AB%F0%9F%87%AE Finland GAMING"
    )
    srv = parse_hysteria2_link(uri)
    assert srv.type == "hysteria2"
    assert srv.host == "fi-gaming.example"
    assert srv.port == 443
    assert srv.id == "fi-gaming.example:443"
    assert srv.password == "s3cr3tpass"
    assert srv.uuid == ""
    assert srv.country == "FI"
    assert srv.params["insecure"] == "1"


def test_parse_hy2_shorthand_scheme():
    srv = parse_hysteria2_link("hy2://pw@de.example:8443#Germany")
    assert srv.type == "hysteria2"
    assert srv.host == "de.example"
    assert srv.port == 8443


def test_parse_hysteria2_default_port():
    assert parse_hysteria2_link("hy2://pw@de.example").port == 443


def test_parse_hysteria2_password_with_colon_preserved():
    # urlsplit splits userinfo on ':'; we must rejoin so a user:pass auth
    # string survives verbatim.
    srv = parse_hysteria2_link("hysteria2://user:p%40ss@de.example:443")
    assert srv.password == "user:p@ss"


def test_parse_hysteria2_obfs_params():
    srv = parse_hysteria2_link("hysteria2://pw@nl.example:443?obfs=salamander&obfs-password=xyz#NL")
    assert srv.params["obfs"] == "salamander"
    assert srv.params["obfs-password"] == "xyz"


@pytest.mark.parametrize(
    "uri",
    [
        "hysteria2://pw@:443",  # missing host
        "vless://uuid@example.com:443",  # wrong scheme
    ],
)
def test_parse_hysteria2_errors(uri):
    with pytest.raises(VlessParseError):
        parse_hysteria2_link(uri)


def test_parse_node_dispatches_by_scheme():
    assert parse_node("vless://uuid@example.com:443").type == "vless"
    assert parse_node("hysteria2://pw@example.com:443").type == "hysteria2"
    assert parse_node("hy2://pw@example.com:443").type == "hysteria2"
    assert parse_node("hysteria://example.com:443?auth=t").type == "hysteria"
    assert parse_node("trojan://pw@example.com:443").type == "trojan"
    assert parse_node("tuic://uuid:pw@example.com:443").type == "tuic"
    assert parse_node("ss://aes-256-gcm:pw@example.com:8388").type == "shadowsocks"
    with pytest.raises(VlessParseError):
        parse_node("ssr://pw@example.com:443")  # ShadowsocksR — not supported


SUBSCRIPTION_URIS = [
    "vless://aaa@host1.com:443?security=reality#%F0%9F%87%B5%F0%9F%87%B1Poland",
    "vless://bbb@host2.com:8443?security=reality#%F0%9F%87%A9%F0%9F%87%AAGermany",
]


def test_parse_subscription_plaintext():
    body = "\n".join(SUBSCRIPTION_URIS).encode()
    servers = parse_subscription(body)
    assert len(servers) == 2
    assert servers[0].country == "PL"
    assert servers[1].country == "DE"


def test_parse_subscription_base64():
    encoded = base64.b64encode("\n".join(SUBSCRIPTION_URIS).encode())
    servers = parse_subscription(encoded)
    assert len(servers) == 2


def test_parse_subscription_base64_no_padding():
    encoded = base64.b64encode("\n".join(SUBSCRIPTION_URIS).encode()).rstrip(b"=")
    servers = parse_subscription(encoded)
    assert len(servers) == 2


def test_parse_subscription_dedup_by_host_port():
    body = (SUBSCRIPTION_URIS[0] + "\n" + SUBSCRIPTION_URIS[0]).encode()
    servers = parse_subscription(body)
    assert len(servers) == 1


def test_parse_subscription_skips_malformed_lines():
    body = (
        SUBSCRIPTION_URIS[0] + "\nvless://broken\nplain comment line\n" + SUBSCRIPTION_URIS[1]
    ).encode()
    servers = parse_subscription(body)
    assert len(servers) == 2


def test_parse_subscription_caps_server_count():
    # A malicious/misconfigured provider could stream thousands of nodes; each
    # becomes an outbound on a low-RAM router, so the count is capped.
    n = MAX_SERVERS_PER_SUBSCRIPTION + 50
    body = "\n".join(f"vless://u@h{i}.example:443#n{i}" for i in range(n)).encode()
    servers = parse_subscription(body)
    assert len(servers) == MAX_SERVERS_PER_SUBSCRIPTION


def test_parse_subscription_keeps_mixed_protocols():
    # The original bug: a real provider mixes vless and hysteria2 ("GAMING")
    # nodes; everything that wasn't vless:// was silently dropped.
    body = "\n".join(
        [
            "vless://aaa@host1.com:443?security=reality#%F0%9F%87%B5%F0%9F%87%B1Poland",
            "hysteria2://pw@fi-gaming.com:443?sni=fi-gaming.com#Finland%20GAMING",
            "hy2://pw2@ch-gaming.com:8443#Switzerland%20GAMING",
        ]
    ).encode()
    servers = parse_subscription(body)
    assert len(servers) == 3
    by_type = sorted(s.type for s in servers)
    assert by_type == ["hysteria2", "hysteria2", "vless"]


def test_parse_subscription_only_hysteria2_base64():
    # A subscription with no vless:// at all must still be recognised as a
    # node list (the body-shape detector keyed on "vless://" before).
    body = base64.b64encode(b"hysteria2://pw@de.example:443#Germany")
    servers = parse_subscription(body)
    assert len(servers) == 1
    assert servers[0].type == "hysteria2"


def test_parse_subscription_invalid_body_raises():
    with pytest.raises(VlessParseError):
        parse_subscription(b"not base64 nor a node list")


def test_parse_subscription_empty_body_raises():
    with pytest.raises(VlessParseError):
        parse_subscription(b"")


# --- shadowsocks / vmess / trojan / tuic / hysteria v1 ----------------------


def test_parse_trojan():
    srv = parse_node("trojan://pw@ex.com:443?sni=a.com&type=ws&path=/x#TJ")
    assert srv.type == "trojan"
    assert srv.host == "ex.com" and srv.port == 443
    assert srv.password == "pw"
    assert srv.params["sni"] == "a.com"


def test_parse_trojan_missing_password_raises():
    with pytest.raises(VlessParseError):
        parse_node("trojan://@ex.com:443")


def test_parse_tuic():
    srv = parse_node("tuic://uuid-1:pw-2@ex.com:443?congestion_control=bbr&alpn=h3#TU")
    assert srv.type == "tuic"
    assert srv.uuid == "uuid-1"
    assert srv.password == "pw-2"


def test_parse_tuic_missing_uuid_raises():
    with pytest.raises(VlessParseError):
        parse_node("tuic://ex.com:443")


def test_parse_hysteria_v1():
    srv = parse_node("hysteria://ex.com:443?auth=tok&upmbps=100&downmbps=200#HY")
    assert srv.type == "hysteria"
    assert srv.password == "tok"  # auth carried via query, surfaced as password
    assert srv.params["upmbps"] == "100"


def test_parse_shadowsocks_sip002_base64():
    ui = base64.b64encode(b"aes-256-gcm:secret").decode()
    srv = parse_node(f"ss://{ui}@ex.com:8388#SS")
    assert srv.type == "shadowsocks"
    assert srv.method == "aes-256-gcm"
    assert srv.password == "secret"
    assert srv.host == "ex.com" and srv.port == 8388


def test_parse_shadowsocks_plaintext_userinfo():
    srv = parse_node("ss://chacha20-ietf-poly1305:pw@ex.com:8388")
    assert srv.method == "chacha20-ietf-poly1305"
    assert srv.password == "pw"


def test_parse_shadowsocks_legacy_whole_base64():
    blob = base64.urlsafe_b64encode(b"aes-128-gcm:pw@ex.com:8388").decode().rstrip("=")
    srv = parse_node(f"ss://{blob}#Legacy")
    assert srv.method == "aes-128-gcm"
    assert srv.host == "ex.com" and srv.port == 8388
    assert srv.name == "Legacy"


def test_parse_vmess_json():
    payload = base64.b64encode(
        json.dumps(
            {"add": "ex.com", "port": "443", "id": "uuid-x", "ps": "VM", "net": "ws", "tls": "tls"}
        ).encode()
    ).decode()
    srv = parse_node(f"vmess://{payload}")
    assert srv.type == "vmess"
    assert srv.host == "ex.com"
    assert srv.uuid == "uuid-x"
    assert srv.name == "VM"
    assert srv.params["net"] == "ws"


def test_parse_vmess_invalid_raises():
    with pytest.raises(VlessParseError):
        parse_node("vmess://not-base64-json!!!")


def test_parse_subscription_mixed_protocols():
    body = "\n".join(
        [
            "vless://uuid@v.example:443#V",
            "trojan://pw@t.example:443#T",
            "ss://" + base64.b64encode(b"aes-256-gcm:pw").decode() + "@s.example:8388#S",
            "tuic://u:p@q.example:443#Q",
        ]
    ).encode()
    servers = parse_subscription(body)
    assert sorted(s.type for s in servers) == ["shadowsocks", "trojan", "tuic", "vless"]
