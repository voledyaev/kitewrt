"""Remembered IP addresses for the VPN servers' own hostnames.

A server addressed by name (`ams.example.net`) used to be resolved by sing-box
itself, through `dns-bootstrap`: DoH to one IP-literal endpoint, dialed off the
tunnel, with `disable_cache` so every new connection resolved again. That made
one DoH endpoint a single point of failure for the whole VPN. Measured on the
live router with the bootstrap endpoint unreachable: every connection through
a domain-addressed node failed with `lookup …: dial tcp …:443` — and DoH is
precisely what Russian ISPs have started blocking.

So the daemon resolves server hostnames itself, from several sources in turn —
the user's own DoH if they set one, a short built-in list of public DoH
endpoints, and finally the router's resolver — and writes the answer into the
generated config. The last good address is kept in `state.json`, so when every
source fails the server is still dialed at the address that worked last.

The order matters. Encrypted DNS first, because the reason `dns-bootstrap`
existed at all was a plain-UDP ISP resolver returning a stale answer for a
server whose address had just moved. The router's resolver is the fallback, not
the default; an answer from it is still only accepted if it is a public unicast
address. That catches a sinkhole (0.0.0.0, 127.x, a private block-page
address) — not an ISP block page served from a public IP, which looks like any
other answer; DoH coming first is what guards against that.

A changed address is a structural change (the config's `server` field moves),
so it costs one sing-box restart — which is why an address is only replaced
when the current one is no longer among the answers. Round-robin DNS that
merely reorders its answers changes nothing.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import socket
import struct
from collections.abc import Iterable
from typing import Any

import httpx

from kitewrt.state import Data, ResolvedEndpoint, now_iso

logger = logging.getLogger(__name__)

# RFC 8484 endpoints that answer a binary GET over HTTP/1.1, measured from the
# router's WAN (2026-10-07). Two providers, two addresses each. Quad9 needs
# HTTP/2 (505 over 1.1); AdGuard and Yandex did not answer at all.
BUILTIN_DOH = (
    "https://1.1.1.1/dns-query",
    "https://1.0.0.1/dns-query",
    "https://8.8.8.8/dns-query",
    "https://8.8.4.4/dns-query",
)

REFRESH_INTERVAL_S = 1800
_TIMEOUT_S = 5.0


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def server_hostnames(snap: Data) -> set[str]:
    """Every server host across all subscriptions that is a name, not an IP."""
    return {srv.host for sub in snap.subscriptions for srv in sub.servers if not _is_ip(srv.host)}


# Transports that are routinely fronted by a CDN: the address such a node dials
# is a shared edge (Cloudflare anycast), not the operator's machine.
_CDN_TRANSPORTS = frozenset({"ws", "grpc", "httpupgrade", "h2", "http", "xhttp", "splithttp"})


def server_addresses(snap: Data) -> list[str]:
    """The VPN servers' own IPv4 addresses as /32s: IP-literal hosts plus the
    remembered addresses of named ones.

    These go into the capture's bypass set. A LAN device that connects to one
    of them is (almost always) running its own client to that same server —
    Shadowrocket on a laptop, say. Captured, its tunnel rode inside ours: two
    layers of encryption for nothing, and every sing-box restart (a deploy, a
    rules change) cut the device's own long-lived connection. Measured on the
    live router: each kitewrt redeploy stalled a streaming session on a Mac
    running Shadowrocket to the same server. The router already talks to these
    addresses directly, so letting the device do the same reveals nothing new.

    **Not for CDN-fronted nodes** (ws / grpc / … transports). Their address is
    a shared edge that serves countless unrelated sites; bypassing it would send
    all LAN traffic to those sites around the tunnel, and the subscription's
    author would get to choose which (red-team finding). Those nodes are left
    captured — a device's own tunnel to them is merely double-wrapped.
    """
    ips: set[str] = set()
    for sub in snap.subscriptions:
        for srv in sub.servers:
            if (srv.params or {}).get("type", "") in _CDN_TRANSPORTS:
                continue
            if _is_ip(srv.host):
                ips.add(srv.host)
            elif (ep := snap.endpoints.get(srv.host)) is not None:
                ips.add(ep.ip)
    return [f"{ip}/32" for ip in sorted(ips) if acceptable(ip)]


def pin(outbound: dict[str, Any], host: str, endpoints: dict[str, ResolvedEndpoint]) -> None:
    """Point an outbound at the remembered address of its host, if there is one.

    The name must survive everywhere the server checks it:

    * TLS: every outbound builder writes `server_name` explicitly (the `sni`
      parameter, or the host), so the certificate is still checked against
      the name.
    * WebSocket: the Host header is only written when the link carries
      `host=`. Without it sing-box sends the dial address — after pinning, the
      IP — and a CDN-fronted node answers with its default vhost or an error
      (red-team finding). So the name is written into the header here.
    * gRPC: sing-box has no option for the `:authority` it sends, so a gRPC
      node is left dialing its name rather than risk it.
    """
    ep = endpoints.get(host)
    if ep is None or outbound.get("server") != host or not acceptable(ep.ip):
        # Not a public address (a crafted backup, a corrupted state file):
        # dial the name instead — never pin a node onto loopback or the LAN.
        return
    transport = outbound.get("transport") or {}
    if transport.get("type") == "grpc":
        return
    outbound["server"] = ep.ip
    if transport.get("type") == "ws":
        headers = transport.setdefault("headers", {})
        headers.setdefault("Host", host)


def acceptable(ip: str) -> bool:
    """A public unicast IPv4 address — not a sinkhole, block page or LAN."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_global and not addr.is_multicast


# --- DNS wire format (RFC 1035), just enough for one A query -----------------


def build_query(host: str) -> bytes:
    header = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)  # id 0 per RFC 8484, RD
    labels = b"".join(bytes([len(p)]) + p.encode("idna") for p in host.rstrip(".").split("."))
    return header + labels + b"\x00" + struct.pack(">HH", 1, 1)  # A, IN


def _skip_name(msg: bytes, i: int) -> int:
    while True:
        n = msg[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:  # compression pointer: two bytes, ends the name
            return i + 2
        i += 1 + n


def parse_a_records(msg: bytes) -> list[str]:
    """The A records in a DNS response. Raises ValueError on a malformed one."""
    try:
        _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
        if flags & 0x000F:  # RCODE != NOERROR
            return []
        i = 12
        for _ in range(qd):
            i = _skip_name(msg, i) + 4
        out: list[str] = []
        for _ in range(an):
            i = _skip_name(msg, i)
            rtype, _, _, rdlen = struct.unpack(">HHIH", msg[i : i + 10])
            i += 10
            if rtype == 1 and rdlen == 4:
                out.append(socket.inet_ntoa(msg[i : i + 4]))
            i += rdlen
        return out
    except (struct.error, IndexError) as exc:
        raise ValueError(f"malformed DNS response: {exc}") from exc


# --- sources -------------------------------------------------------------------


async def via_doh(client: httpx.AsyncClient, url: str, host: str) -> list[str]:
    q = base64.urlsafe_b64encode(build_query(host)).decode().rstrip("=")
    r = await client.get(
        url,
        params={"dns": q},
        headers={"accept": "application/dns-message"},
        timeout=_TIMEOUT_S,
    )
    if r.status_code != 200:
        raise ValueError(f"HTTP {r.status_code}")
    return parse_a_records(r.content)


async def via_system(host: str) -> list[str]:
    """The router's own resolver (dnsmasq → the ISP's servers)."""
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
        timeout=_TIMEOUT_S,
    )
    seen: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in seen:
            seen.append(ip)
    return seen


def doh_sources(custom: str) -> list[str]:
    custom = custom.strip()
    return ([custom] if custom else []) + [u for u in BUILTIN_DOH if u != custom]


async def resolve(
    host: str, client: httpx.AsyncClient, doh_urls: Iterable[str]
) -> tuple[list[str], str] | None:
    """(acceptable addresses, source) from the first source that has any."""
    for url in doh_urls:
        try:
            ips = [ip for ip in await via_doh(client, url, host) if acceptable(ip)]
        except Exception as exc:  # any failure → next source
            logger.debug("DoH %s for %s failed: %s", url, host, exc)
            continue
        if ips:
            return ips, url
    try:
        ips = [ip for ip in await via_system(host) if acceptable(ip)]
    except Exception as exc:
        logger.debug("system resolver for %s failed: %s", host, exc)
        return None
    return (ips, "system") if ips else None


async def refresh(
    state: Any, client: httpx.AsyncClient
) -> tuple[dict[str, ResolvedEndpoint], set[str]]:
    """Resolve every server hostname. Returns (changed addresses, hosts to forget).

    Never raises; a host no source can resolve keeps its last good address.
    The caller commits the result (and signals an apply when addresses moved).
    """
    snap = state.snapshot()
    hosts = server_hostnames(snap)
    sources = doh_sources(snap.dns.doh_url)
    changed: dict[str, ResolvedEndpoint] = {}
    for host in sorted(hosts):
        res = await resolve(host, client, sources)
        current = snap.endpoints.get(host)
        if res is None:
            if current is None:
                logger.warning("could not resolve server host %s from any source", host)
            else:
                logger.warning(
                    "could not resolve server host %s; keeping its last good address %s",
                    host,
                    current.ip,
                )
            continue
        ips, via = res
        if current is not None and current.ip in ips:
            continue
        changed[host] = ResolvedEndpoint(ip=ips[0], at=now_iso(), via=via)
        logger.info(
            "server host %s → %s (via %s)%s",
            host,
            ips[0],
            via,
            f", was {current.ip}" if current else "",
        )
    forget = set(snap.endpoints) - hosts
    return changed, forget
