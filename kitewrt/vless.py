"""Parses proxy subscriptions into structured Server values.

Most providers serve subscriptions as a base64-encoded list of node URIs
separated by newlines; some serve plaintext. Both forms are accepted.

Seven node protocols are recognised: `vless://`, `hysteria2://` / `hy2://`,
`hysteria://` (v1), `ss://` (shadowsocks), `vmess://`, `trojan://` and
`tuic://`. A `Server.type` field discriminates them; everything downstream
(state, UI, the sing-box outbound builder) dispatches on it. The module is
still named `vless` because that was the first protocol supported.

Reference: docs/vless-format.md.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from urllib.parse import SplitResult, unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field


class VlessParseError(ValueError):
    """Raised when a vless:// URI or subscription body cannot be parsed."""


class Server(BaseModel):
    """A parsed proxy endpoint.

    `id` is "host:port" and is the stable key used by the rest of the app
    (state, UI, sing-box config). `type` selects the protocol; the auth fields are
    protocol-specific (`uuid` for vless/vmess/tuic, `password` for
    hysteria(2)/trojan/tuic/shadowsocks, `method` for the shadowsocks cipher) —
    only the relevant ones are set. All have empty defaults so older persisted
    state (which had no `type`/`password`/`method`) still deserialises as a
    plain VLESS server.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    country: str
    # vless | hysteria2 | hysteria | shadowsocks | vmess | trojan | tuic
    type: str = "vless"
    host: str
    port: int
    uuid: str = ""  # vless / vmess / tuic auth identifier
    password: str = ""  # hysteria(2) / trojan / tuic / shadowsocks secret
    method: str = ""  # shadowsocks cipher (e.g. aes-256-gcm); empty otherwise
    params: dict[str, str] = Field(default_factory=dict)


# Fallback country lookup for labels with NO leading flag emoji. detect_country
# tries the flag emoji first (language-agnostic — covers most real subscriptions);
# this English-name table is the fallback. Extend with other-language aliases if
# your provider labels servers that way.
_COUNTRY_ALIASES: dict[str, str] = {
    "poland": "PL",
    "spain": "ES",
    "germany": "DE",
    "hungary": "HU",
    "italy": "IT",
    "netherlands": "NL",
    "finland": "FI",
    "france": "FR",
    "uk": "GB",
    "united kingdom": "GB",
    "usa": "US",
    "united states": "US",
    "america": "US",
    "sweden": "SE",
    "norway": "NO",
    "denmark": "DK",
    "austria": "AT",
    "switzerland": "CH",
    "belgium": "BE",
    "czech": "CZ",
    "slovakia": "SK",
    "romania": "RO",
    "bulgaria": "BG",
    "moldova": "MD",
    "ukraine": "UA",
    "kazakhstan": "KZ",
    "armenia": "AM",
    "georgia": "GE",
    "turkey": "TR",
    "japan": "JP",
    "south korea": "KR",
    "singapore": "SG",
    "hong kong": "HK",
    "canada": "CA",
    "australia": "AU",
    "lithuania": "LT",
    "latvia": "LV",
    "estonia": "EE",
}

# Strips punctuation/decoration while preserving Unicode letters and digits.
_NON_WORD_RE = re.compile(r"[^\w\s-]+", re.UNICODE)
_WHITESPACE_RE = re.compile(r"\s+")

_FLAG_BASE = 0x1F1E6
_FLAG_UPPER = 0x1F1FF


def _flag_to_country(text: str) -> str:
    """Extract an ISO country code from a leading regional-indicator flag emoji.

    Flag emoji are pairs of code points in U+1F1E6..U+1F1FF; each pair maps to
    two ASCII letters via (cp - 0x1F1E6 + ord('A')).
    """
    if len(text) < 2:
        return ""
    a, b = ord(text[0]), ord(text[1])
    if _FLAG_BASE <= a <= _FLAG_UPPER and _FLAG_BASE <= b <= _FLAG_UPPER:
        return chr(a - _FLAG_BASE + ord("A")) + chr(b - _FLAG_BASE + ord("A"))
    return ""


def _name_to_country(text: str) -> str:
    s = _NON_WORD_RE.sub(" ", text.strip().lower())
    s = _WHITESPACE_RE.sub(" ", s).strip()
    if not s:
        return ""
    if s in _COUNTRY_ALIASES:
        return _COUNTRY_ALIASES[s]
    for word in s.split():
        if word in _COUNTRY_ALIASES:
            return _COUNTRY_ALIASES[word]
    return ""


def detect_country(fragment: str) -> str:
    """Return ISO-3166 alpha-2 from fragment text, or '??' if undetectable."""
    if not fragment:
        return "??"
    return _flag_to_country(fragment) or _name_to_country(fragment) or "??"


# Node URI schemes we understand. hysteria2 has two interchangeable scheme
# spellings in the wild (`hysteria2://` and the shorthand `hy2://`).
_HY2_SCHEMES = ("hysteria2://", "hy2://")
NODE_SCHEMES = (
    "vless://",
    *_HY2_SCHEMES,
    "hysteria://",
    "ss://",
    "vmess://",
    "trojan://",
    "tuic://",
)


def _b64_to_text(data: str) -> str | None:
    """Decode base64 (standard or URL-safe, padding-tolerant) to UTF-8 text, or
    None if `data` isn't cleanly decodable base64. `validate=True` makes a
    wrong-alphabet guess fail rather than silently dropping chars, so the two
    alphabets can be tried in turn without corrupting the payload."""
    compact = re.sub(r"\s", "", data)
    if not compact:
        return None
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    for altchars in (b"+/", b"-_"):
        try:
            return base64.b64decode(padded, altchars=altchars, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    return None


def _parse_query(query: str) -> dict[str, str]:
    """Collapse a URI query into a scalar dict; drop empty keys/values."""
    params: dict[str, str] = {}
    if not query:
        return params
    for pair in query.split("&"):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        if k and v:
            params[unquote(k)] = unquote(v)
    return params


def _resolve_port(parts: SplitResult, uri: str) -> int:
    try:
        port = parts.port if parts.port is not None else 443
    except ValueError as exc:
        raise VlessParseError(f"invalid port in: {uri[:80]}") from exc
    return port


def _finish_server(
    parts: SplitResult,
    uri: str,
    *,
    node_type: str,
    uuid: str = "",
    password: str = "",
    method: str = "",
) -> Server:
    """Assemble a Server from the host / port / query / fragment common to every
    URI-shaped node link. The caller extracts only the protocol-specific auth
    (uuid / password / method) and passes it in. Raises on a missing host.

    urlsplit handles these non-registered schemes the same as http — parsing
    userinfo / host / port / query / fragment uniformly."""
    host = parts.hostname or ""
    if not host:
        raise VlessParseError(f"missing host in: {uri[:80]}")
    port = _resolve_port(parts, uri)
    fragment = unquote(parts.fragment)
    server_id = f"{host}:{port}"
    return Server(
        id=server_id,
        name=fragment or server_id,
        country=detect_country(fragment),
        type=node_type,
        host=host,
        port=port,
        uuid=uuid,
        password=password,
        method=method,
        params=_parse_query(parts.query),
    )


def parse_link(uri: str) -> Server:
    """Parse a single vless://... URI into a Server.

    Raises VlessParseError on malformed input or missing uuid/host.
    """
    if not uri.startswith("vless://"):
        raise VlessParseError(f"not a vless URI: {uri[:80]}")
    parts = urlsplit(uri)
    uuid = unquote(parts.username) if parts.username else ""
    if not uuid:
        raise VlessParseError(f"missing uuid in: {uri[:80]}")
    return _finish_server(parts, uri, node_type="vless", uuid=uuid)


def parse_hysteria2_link(uri: str) -> Server:
    """Parse a single hysteria2://... (or hy2://...) URI into a Server.

    hysteria2 authenticates with a password carried in the URI userinfo (not a
    UUID) and always runs over QUIC/TLS. The userinfo may itself contain a ':'
    (some providers use a `user:pass` auth string) — urlsplit would split that
    into username/password, so we rejoin it verbatim into one secret.
    """
    if not uri.startswith(_HY2_SCHEMES):
        raise VlessParseError(f"not a hysteria2 URI: {uri[:80]}")
    parts = urlsplit(uri)
    if parts.password is not None:
        password = f"{unquote(parts.username or '')}:{unquote(parts.password)}"
    else:
        password = unquote(parts.username) if parts.username else ""
    return _finish_server(parts, uri, node_type="hysteria2", password=password)


def parse_hysteria_link(uri: str) -> Server:
    """Parse a hysteria://... (v1) URI into a Server.

    hysteria v1 differs from hysteria2: its auth string rides in the `auth`
    (or `auth_str`) query param rather than the userinfo, and bandwidth hints
    live in `upmbps` / `downmbps`. Still QUIC/TLS.
    """
    if not uri.startswith("hysteria://"):
        raise VlessParseError(f"not a hysteria URI: {uri[:80]}")
    parts = urlsplit(uri)
    q = _parse_query(parts.query)
    password = q.get("auth") or q.get("auth_str") or q.get("auth-str") or ""
    return _finish_server(parts, uri, node_type="hysteria", password=password)


def parse_trojan_link(uri: str) -> Server:
    """Parse a trojan://password@host:port?... URI into a Server.

    Trojan authenticates with a password in the userinfo and always runs over
    TLS (TCP carrier; optional ws/grpc transport from the query params).
    """
    if not uri.startswith("trojan://"):
        raise VlessParseError(f"not a trojan URI: {uri[:80]}")
    parts = urlsplit(uri)
    password = unquote(parts.username) if parts.username else ""
    if not password:
        raise VlessParseError(f"missing password in: {uri[:80]}")
    return _finish_server(parts, uri, node_type="trojan", password=password)


def parse_tuic_link(uri: str) -> Server:
    """Parse a tuic://uuid:password@host:port?... URI into a Server.

    TUIC (v5, QUIC) authenticates with BOTH a uuid and a password, carried in
    the userinfo as `uuid:password`.
    """
    if not uri.startswith("tuic://"):
        raise VlessParseError(f"not a tuic URI: {uri[:80]}")
    parts = urlsplit(uri)
    uuid = unquote(parts.username) if parts.username else ""
    password = unquote(parts.password) if parts.password else ""
    if not uuid:
        raise VlessParseError(f"missing uuid in: {uri[:80]}")
    return _finish_server(parts, uri, node_type="tuic", uuid=uuid, password=password)


def parse_shadowsocks_link(uri: str) -> Server:
    """Parse a shadowsocks ss://... URI into a Server.

    Two encodings appear in the wild: SIP002 `ss://<userinfo>@host:port#name`
    where userinfo is `method:password` (usually base64), and the legacy
    whole-base64 `ss://base64(method:password@host:port)#name`. Both handled.
    """
    if not uri.startswith("ss://"):
        raise VlessParseError(f"not a shadowsocks URI: {uri[:80]}")
    rest = uri[len("ss://") :]
    fragment = ""
    if "#" in rest:
        rest, fragment = rest.split("#", 1)
    if "@" not in rest:
        # Legacy: the whole blob is base64(method:password@host:port).
        decoded = _b64_to_text(rest)
        if decoded is None or "@" not in decoded:
            raise VlessParseError(f"malformed shadowsocks URI: {uri[:80]}")
        rest = decoded
    userinfo, _, hostport = rest.rpartition("@")
    if not userinfo or not hostport:
        raise VlessParseError(f"malformed shadowsocks URI: {uri[:80]}")
    # userinfo is "method:password" (plain) or base64 of it. base64 has no ':'
    # so a literal ':' means it's already plaintext.
    if ":" in userinfo:
        method, _, password = userinfo.partition(":")
        method, password = unquote(method), unquote(password)
    else:
        decoded = _b64_to_text(userinfo)
        if decoded is None or ":" not in decoded:
            raise VlessParseError(f"cannot decode shadowsocks userinfo in: {uri[:80]}")
        method, _, password = decoded.partition(":")
    # Reuse the URI machinery for host / port / query / fragment via a clean
    # re-parse (the placeholder userinfo is ignored by _finish_server).
    tail = "#" + fragment if fragment else ""
    parts = urlsplit("ss://_@" + hostport + tail)
    return _finish_server(parts, uri, node_type="shadowsocks", password=password, method=method)


def parse_vmess_link(uri: str) -> Server:
    """Parse a vmess://base64(json) URI into a Server.

    Unlike the other schemes vmess isn't URI-shaped — the payload is base64'd
    JSON (`add` / `port` / `id` / `net` / `tls` / ...). Transport + TLS hints
    are stashed into `params` (string-valued, like the URI query dict) for the
    outbound builder.
    """
    if not uri.startswith("vmess://"):
        raise VlessParseError(f"not a vmess URI: {uri[:80]}")
    decoded = _b64_to_text(uri[len("vmess://") :])
    if decoded is None:
        raise VlessParseError(f"vmess payload is not base64: {uri[:80]}")
    try:
        cfg = json.loads(decoded)
    except (ValueError, TypeError) as exc:
        raise VlessParseError(f"malformed vmess JSON in: {uri[:80]}") from exc
    if not isinstance(cfg, dict):
        raise VlessParseError(f"vmess JSON is not an object: {uri[:80]}")
    host = str(cfg.get("add") or "")
    uuid = str(cfg.get("id") or "")
    if not host or not uuid:
        raise VlessParseError(f"missing add/id in vmess: {uri[:80]}")
    try:
        port = int(cfg.get("port") or 443)
    except (ValueError, TypeError) as exc:
        raise VlessParseError(f"invalid vmess port in: {uri[:80]}") from exc
    name = str(cfg.get("ps") or f"{host}:{port}")
    params: dict[str, str] = {}
    for k in ("net", "type", "host", "path", "tls", "sni", "scy", "aid", "alpn", "fp"):
        v = cfg.get(k)
        if v not in (None, ""):
            params[k] = str(v)
    return Server(
        id=f"{host}:{port}",
        name=name,
        country=detect_country(name),
        type="vmess",
        host=host,
        port=port,
        uuid=uuid,
        params=params,
    )


def parse_node(uri: str) -> Server:
    """Parse any supported node URI into a Server (dispatches on the scheme).

    hysteria2 / hy2 are matched before hysteria (v1) so the longer scheme wins.
    """
    if uri.startswith("vless://"):
        return parse_link(uri)
    if uri.startswith(_HY2_SCHEMES):
        return parse_hysteria2_link(uri)
    if uri.startswith("hysteria://"):
        return parse_hysteria_link(uri)
    if uri.startswith("ss://"):
        return parse_shadowsocks_link(uri)
    if uri.startswith("vmess://"):
        return parse_vmess_link(uri)
    if uri.startswith("trojan://"):
        return parse_trojan_link(uri)
    if uri.startswith("tuic://"):
        return parse_tuic_link(uri)
    raise VlessParseError(f"unsupported scheme in: {uri[:80]}")


# Hard cap on servers taken from one subscription. fetch_url already bounds the
# body to 1 MiB, but at ~100-300 bytes per node URI that's still thousands of
# entries — and each becomes a sing-box outbound + selector member + an
# auto-select delay probe, which bloats config.json and strains a low-RAM
# router. A malicious provider is explicitly in the threat model. 512 is far
# above any real subscription (tens of servers) yet bounds the worst case.
MAX_SERVERS_PER_SUBSCRIPTION = 512

logger = logging.getLogger(__name__)


def parse_subscription(body: bytes | str) -> list[Server]:
    """Parse a subscription body (base64 or plaintext auto-detected).

    Returns a deduplicated list of Servers (first occurrence wins per host:port)
    spanning every supported protocol, capped at MAX_SERVERS_PER_SUBSCRIPTION.
    Malformed or unsupported individual lines are silently skipped — providers
    occasionally include comments or future-format entries.
    """
    text = _decode_subscription_body(body)

    servers: list[Server] = []
    seen: set[str] = set()
    truncated = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith(NODE_SCHEMES):
            continue
        try:
            srv = parse_node(line)
        except VlessParseError:
            continue
        if srv.id in seen:
            continue
        seen.add(srv.id)
        servers.append(srv)
        if len(servers) >= MAX_SERVERS_PER_SUBSCRIPTION:
            truncated = True
            break
    if truncated:
        logger.warning(
            "subscription exceeded %d servers; truncated to the cap "
            "(a config with thousands of outbounds would strain the router)",
            MAX_SERVERS_PER_SUBSCRIPTION,
        )
    return servers


def _contains_node_uri(text: str) -> bool:
    """True if `text` holds at least one URI of a supported node protocol."""
    return any(scheme in text for scheme in NODE_SCHEMES)


def _decode_subscription_body(body: bytes | str) -> str:
    if isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace").strip()
    else:
        text = body.strip()

    if _contains_node_uri(text):
        return text

    decoded = _b64_to_text(text)
    if decoded is not None and _contains_node_uri(decoded):
        return decoded

    raise VlessParseError("subscription body is neither a plain node list nor a base64-encoded one")
