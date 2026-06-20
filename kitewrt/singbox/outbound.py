"""Parsed server → sing-box outbound.

Maps a parsed `Server` to the matching sing-box outbound, dispatching on
`Server.type` via the `_BUILDERS` table. Supported: vless (Reality / plain TLS
over tcp/ws/grpc), hysteria2 and hysteria v1 (QUIC), shadowsocks, vmess
(tcp/ws/grpc, optional TLS), trojan (TLS + optional ws/grpc) and tuic (QUIC).

Shared shape: top-level `server` / `server_port` + protocol auth; TLS is a
`tls` block (with nested `utls` where the protocol uses a TCP carrier); ws/grpc
go in a `transport` block built by `_transport_block`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from kitewrt.vless import Server


def outbound_tag(subscription_id: str, server_id: str) -> str:
    """Stable, globally-unique tag for one server's outbound.

    Composite (subscription + server) because two subscriptions can hold the
    same host:port; the selector and the Clash API switch by this tag, so it
    must be unique across the whole config. This is also the value kitewrt
    PUTs to `/proxies/<selector>` to switch servers.
    """
    return f"{subscription_id}/{server_id}"


def build_vless_outbound(srv: Server, tag: str) -> dict[str, Any]:
    """Build a sing-box `vless` outbound for `srv` under `tag`."""
    p = srv.params

    out: dict[str, Any] = {
        "type": "vless",
        "tag": tag,
        "server": srv.host,
        "server_port": srv.port,
        "uuid": srv.uuid,
    }
    if flow := p.get("flow"):
        out["flow"] = flow

    security = p.get("security") or "none"
    if security == "reality":
        out["tls"] = {
            "enabled": True,
            "server_name": p.get("sni", ""),
            "utls": {"enabled": True, "fingerprint": p.get("fp") or "chrome"},
            "reality": {
                "enabled": True,
                "public_key": p.get("pbk", ""),
                "short_id": p.get("sid", ""),
            },
        }
    elif security == "tls":
        out["tls"] = {
            "enabled": True,
            "server_name": p.get("sni") or srv.host,
            "utls": {"enabled": True, "fingerprint": p.get("fp") or "chrome"},
            "alpn": ["h2", "http/1.1"],
        }

    if transport := _transport_block(p.get("type") or "tcp", p):
        out["transport"] = transport

    return out


# `insecure=1` (skip cert verification) shows up as several truthy spellings.
_TRUTHY = {"1", "true", "yes"}


def _is_truthy(value: str | None) -> bool:
    """True for the link spellings of a boolean flag (insecure / allowInsecure)."""
    return (value or "").lower() in _TRUTHY


def _maybe_int(value: str | None) -> int | None:
    """Parse `value` to int, or None if absent/non-numeric — for optional
    int-valued link params (alterId, up/down mbps)."""
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _transport_block(network: str, p: dict[str, str]) -> dict[str, Any] | None:
    """The ws / grpc `transport` block shared by vless, trojan and vmess.
    Returns None for a plain TCP carrier (no transport block)."""
    if network == "ws":
        t: dict[str, Any] = {"type": "ws", "path": p.get("path") or "/"}
        if host := p.get("host"):
            t["headers"] = {"Host": host}
        return t
    if network == "grpc":
        service = (p.get("serviceName") or p.get("path") or "").lstrip("/")
        return {"type": "grpc", "service_name": service}
    return None


def build_hysteria2_outbound(srv: Server, tag: str) -> dict[str, Any]:
    """Build a sing-box `hysteria2` outbound for `srv` under `tag`.

    hysteria2 runs over QUIC and is therefore always TLS — there's no plaintext
    variant and no transport block. Auth is the password (not a uuid). An
    optional `obfs=salamander` with `obfs-password` wraps the QUIC packets.
    """
    p = srv.params
    out: dict[str, Any] = {
        "type": "hysteria2",
        "tag": tag,
        "server": srv.host,
        "server_port": srv.port,
        "password": srv.password,
        "tls": {
            "enabled": True,
            "server_name": p.get("sni") or srv.host,
            # Gaming / self-hosted hysteria2 nodes often present a cert that
            # doesn't match the SNI; honour the link's `insecure` flag.
            "insecure": _is_truthy(p.get("insecure")),
        },
    }
    if obfs := p.get("obfs"):
        out["obfs"] = {"type": obfs, "password": p.get("obfs-password", "")}
    return out


def build_hysteria_outbound(srv: Server, tag: str) -> dict[str, Any]:
    """Build a sing-box `hysteria` (v1) outbound. Auth is `auth_str`; the
    up/down bandwidth hints map to `up_mbps` / `down_mbps`. Always QUIC/TLS."""
    p = srv.params
    out: dict[str, Any] = {
        "type": "hysteria",
        "tag": tag,
        "server": srv.host,
        "server_port": srv.port,
        "tls": {
            "enabled": True,
            "server_name": p.get("peer") or p.get("sni") or srv.host,
            "insecure": _is_truthy(p.get("insecure")),
        },
    }
    if srv.password:
        out["auth_str"] = srv.password
    if (up := _maybe_int(p.get("upmbps") or p.get("up"))) is not None:
        out["up_mbps"] = up
    if (down := _maybe_int(p.get("downmbps") or p.get("down"))) is not None:
        out["down_mbps"] = down
    if obfs := p.get("obfs"):
        out["obfs"] = obfs
    if alpn := p.get("alpn"):
        out["tls"]["alpn"] = alpn.split(",")
    return out


def build_shadowsocks_outbound(srv: Server, tag: str) -> dict[str, Any]:
    """Build a sing-box `shadowsocks` outbound. `method` is the cipher; an
    optional SIP003 `plugin` ("name;opts") splits into plugin + plugin_opts."""
    out: dict[str, Any] = {
        "type": "shadowsocks",
        "tag": tag,
        "server": srv.host,
        "server_port": srv.port,
        "method": srv.method,
        "password": srv.password,
    }
    if plugin := srv.params.get("plugin"):
        name, _, opts = plugin.partition(";")
        out["plugin"] = name
        if opts:
            out["plugin_opts"] = opts
    return out


def build_vmess_outbound(srv: Server, tag: str) -> dict[str, Any]:
    """Build a sing-box `vmess` outbound. Cipher (`security`) defaults to auto;
    `alter_id` defaults to 0 (AEAD). TLS + ws/grpc come from params."""
    p = srv.params
    out: dict[str, Any] = {
        "type": "vmess",
        "tag": tag,
        "server": srv.host,
        "server_port": srv.port,
        "uuid": srv.uuid,
        "security": p.get("scy") or "auto",
        "alter_id": _maybe_int(p.get("aid")) or 0,
    }
    if p.get("tls") == "tls":
        out["tls"] = {
            "enabled": True,
            "server_name": p.get("sni") or p.get("host") or srv.host,
            "utls": {"enabled": True, "fingerprint": p.get("fp") or "chrome"},
        }
        if alpn := p.get("alpn"):
            out["tls"]["alpn"] = alpn.split(",")
    if transport := _transport_block(p.get("net") or "tcp", p):
        out["transport"] = transport
    return out


def build_trojan_outbound(srv: Server, tag: str) -> dict[str, Any]:
    """Build a sing-box `trojan` outbound (password auth, always TLS, optional
    ws/grpc transport)."""
    p = srv.params
    out: dict[str, Any] = {
        "type": "trojan",
        "tag": tag,
        "server": srv.host,
        "server_port": srv.port,
        "password": srv.password,
        "tls": {
            "enabled": True,
            "server_name": p.get("sni") or p.get("peer") or srv.host,
            "insecure": _is_truthy(p.get("allowInsecure") or p.get("insecure")),
        },
    }
    if alpn := p.get("alpn"):
        out["tls"]["alpn"] = alpn.split(",")
    if transport := _transport_block(p.get("type") or "tcp", p):
        out["transport"] = transport
    return out


def build_tuic_outbound(srv: Server, tag: str) -> dict[str, Any]:
    """Build a sing-box `tuic` outbound (QUIC; uuid + password). Defaults the
    congestion control to bbr and alpn to h3."""
    p = srv.params
    out: dict[str, Any] = {
        "type": "tuic",
        "tag": tag,
        "server": srv.host,
        "server_port": srv.port,
        "uuid": srv.uuid,
        "password": srv.password,
        "congestion_control": p.get("congestion_control") or "bbr",
        "tls": {
            "enabled": True,
            "server_name": p.get("sni") or srv.host,
            "insecure": _is_truthy(p.get("allow_insecure") or p.get("insecure")),
            "alpn": (p.get("alpn") or "h3").split(","),
        },
    }
    if mode := p.get("udp_relay_mode"):
        out["udp_relay_mode"] = mode
    return out


# Protocol → builder. build_outbound dispatches on Server.type, defaulting to
# vless for forward-compatibility with older persisted servers.
_BUILDERS: dict[str, Callable[[Server, str], dict[str, Any]]] = {
    "vless": build_vless_outbound,
    "hysteria2": build_hysteria2_outbound,
    "hysteria": build_hysteria_outbound,
    "shadowsocks": build_shadowsocks_outbound,
    "vmess": build_vmess_outbound,
    "trojan": build_trojan_outbound,
    "tuic": build_tuic_outbound,
}


def build_outbound(srv: Server, tag: str) -> dict[str, Any]:
    """Build the sing-box outbound matching `srv.type` (defaults to vless)."""
    return _BUILDERS.get(srv.type, build_vless_outbound)(srv, tag)
