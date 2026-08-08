"""Shared host-locality helpers for the API's DNS-rebinding guard.

In their own module so both the HTTP middleware (kitewrt.api) and the WebSocket
handler (kitewrt.routes.ws) can apply the same check without an import cycle
(routes import from kitewrt.*, and api imports routes).
"""

from __future__ import annotations

import ipaddress

_LOCAL_SUFFIXES = (".lan", ".local", ".home", ".internal", ".localdomain")


def host_only(host_header: str) -> str:
    """Strip the port (and IPv6 brackets) from a Host/Origin netloc."""
    h = host_header.strip()
    if h.startswith("["):  # [ipv6]:port
        return h[1 : h.index("]")] if "]" in h else h[1:]
    if h.count(":") == 1:  # host:port (ipv4 or name)
        return h.rsplit(":", 1)[0]
    return h  # bare host / bare ipv6


def is_local_host(host_header: str) -> bool:
    """True when the Host is a LAN-local name/IP. A DNS-rebinding defense: an
    attacker who rebinds a public domain to the router's IP still sends *their*
    domain in the Host header, so rejecting non-local Hosts blocks them driving
    the (unauthenticated) API. Allows IP literals, localhost, bare hostnames, and
    local suffixes; rejects public dotted domains."""
    host = host_only(host_header).lower()
    if not host:
        return True  # no Host (non-browser client) — allow
    try:
        ipaddress.ip_address(host)
        return True  # any IP literal — the documented way users reach the UI
    except ValueError:
        pass
    if host == "localhost" or "." not in host:
        return True  # bare hostname, e.g. "openwrt"
    return host.endswith(_LOCAL_SUFFIXES)
