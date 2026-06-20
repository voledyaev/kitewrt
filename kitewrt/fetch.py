"""HTTP fetch helper for subscription / rules URLs.

Bounded by size (1 MiB) and time (30s default). Streaming-read so an
oversize response is detected and dropped without buffering the whole body
in RAM — important on a router with constrained memory.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import httpx

# Some subscription providers vary the response body by User-Agent (serving
# base64 to one client, an HTML page to another). This value is known-good
# across the providers tested — re-verify against your provider before changing
# it; a careless bump can silently break "add subscription".
USER_AGENT = "kitewrt/0.3-py"

# Subscription bodies are short (a few KB typical). 1 MiB is a generous cap
# that still protects the daemon from a misconfigured source URL streaming
# megabytes at us. Reuse for rules fetches.
MAX_BODY_BYTES = 1 << 20

# Most subscription providers respond within a second. 30s tolerates slow
# upstreams without letting a hung connection block the apply pipeline.
DEFAULT_TIMEOUT_S = 30.0


class FetchError(Exception):
    """Raised for any fetch-time failure (network, HTTP non-2xx, oversize)."""


def blocks_ssrf(host: str) -> bool:
    """True when `host` is an IP literal pointing at a sensitive target: loopback
    (the local Clash controller on :9090), link-local (cloud metadata
    169.254.169.254), or reserved/multicast/unspecified. Hostnames are NOT
    resolved here — that keeps the fetch path hermetic and fast, and blocks the
    obvious direct-IP SSRF (the realistic case set via the API). Private LAN IPs
    are deliberately allowed so a user can self-host their subscription/rules on
    their own network."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # a hostname — not an IP-literal SSRF target
    return (
        ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


async def fetch_url(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int = MAX_BODY_BYTES,
) -> bytes:
    """GET url; return bytes; raise FetchError on any problem.

    Reads up to max_bytes+1 to detect overflow in a single pass without
    buffering the whole stream first. Refuses IP-literal non-public targets
    (SSRF guard).
    """
    host = urlparse(url).hostname
    if host and blocks_ssrf(host):
        raise FetchError(f"refusing to fetch a non-public address: {host}")
    try:
        async with client.stream("GET", url, headers={"User-Agent": USER_AGENT}) as resp:
            if not (200 <= resp.status_code < 300):
                raise FetchError(f"HTTP {resp.status_code}")
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"response too large (>{max_bytes // 1024} KB limit)")
            return b"".join(chunks)
    except FetchError:
        raise
    except httpx.HTTPError as exc:
        # Connect/read timeouts and connection resets (e.g. an upstream block)
        # often stringify to "" — fall back to the exception class name so the
        # API surfaces "ConnectTimeout" / "ConnectError" instead of a useless
        # generic "error" (the empty detail otherwise collapses to that).
        raise FetchError(str(exc).strip() or type(exc).__name__) from exc
