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
        "vless://5ce044d1-6a0b-4dc5-b2c9-6eb296642a1c@example.com:8443"
        "?security=reality&type=tcp&flow=xtls-rprx-vision&sni=test.example"
        "&fp=chrome&pbk=KEY&sid=SID#%F0%9F%87%B5%F0%9F%87%B1Poland"
    )
    srv = parse_link(uri)
    assert srv.host == "example.com"
    assert srv.port == 8443
    assert srv.uuid == "5ce044d1-6a0b-4dc5-b2c9-6eb296642a1c"
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
