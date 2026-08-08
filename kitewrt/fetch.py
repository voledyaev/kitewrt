"""HTTP fetch helper for subscription / rules URLs.

Bounded by size: 1 MiB, enforced here. *Not* bounded by time here — `fetch_url`
takes no timeout; the 30 s comes from whichever `httpx.AsyncClient` the caller
passes (`api._lifespan` builds both with `DEFAULT_TIMEOUT_S`), so a caller that
hands over an unbounded client gets an unbounded fetch.

Streaming-read, which caps the damage rather than eliminating it: an oversize
body is abandoned as soon as the running total crosses the limit, so a source
streaming megabytes costs ~1 MiB of RAM instead of all of them. Up to the cap
*is* accumulated in memory, because the caller wants the bytes.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

import httpx

# Some subscription providers vary the response body by User-Agent (serving
# base64 to one client, an HTML page to another), so this is a compatibility
# token, not a version report. It deliberately does NOT track the package
# version (`pyproject.toml` says 2.0.0) and must not be "fixed" to match:
# bumping it changes what at least one provider serves, and a careless bump
# silently breaks "add subscription". Re-verify against your provider before
# touching it.
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
    resolved here, and not read either — `blocks_ssrf_name` rules on names that
    are non-public by definition, and `resolve_blocks_ssrf` covers the
    DNS-rebinding case (both are called alongside this in `fetch_url`); this
    handles the direct IP-literal one. Private LAN IPs are deliberately allowed
    so a user can self-host their subscription/rules on their own network."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # a hostname — not an IP-literal SSRF target
    return _is_sensitive(ip)


# Final labels whose meaning is fixed by standard rather than by whoever
# answers the query. `localhost` MUST resolve to loopback (RFC 6761 §6.3) and
# `.internal` is ICANN's reserved private-use TLD — the home of the cloud
# metadata service (`metadata.google.internal`), which the link-local literal
# guard can only catch after a lookup.
_LOCAL_BY_DEFINITION = frozenset({"localhost", "internal"})


def blocks_ssrf_name(host: str) -> bool:
    """True when the *name itself* says the target is non-public — no DNS.

    The companion to `blocks_ssrf` for callers that cannot resolve, or whose
    resolution would not be the one that matters: `_validate_rule_set` validates
    a URL that **sing-box**, not this process, will later fetch. Measured, the
    literal-only guard accepted `localhost` and `metadata.google.internal`
    outright.

    Two classes, both answering the same wherever they are resolved:

    * a reserved name (`localhost`, `*.localhost`, `*.internal`);
    * an IPv4 literal in a spelling `ipaddress` refuses and a C resolver
      accepts — `2130706433`, `127.1`, `0177.0.0.1` are all 127.0.0.1 to
      `inet_aton`, and were all accepted as "hostnames" before.

    Private LAN names/addresses stay allowed, exactly as in `blocks_ssrf`: the
    self-hosting case is deliberate, and this is not the place to change that
    policy.
    """
    name = host.rstrip(".").lower()  # `localhost.` is the same name
    if name.rsplit(".", 1)[-1] in _LOCAL_BY_DEFINITION:
        return True
    ip = _inet_aton_literal(name)
    return ip is not None and _is_sensitive(ip)


def _inet_aton_literal(host: str) -> ipaddress.IPv4Address | None:
    """The address a C resolver would read out of `host`, or None if it is a
    real name. `ipaddress` only takes dotted-quad, so every other legal IPv4
    spelling (integer, octal, hex, `127.1`) walked past `blocks_ssrf` as a
    hostname. No name survives this: `inet_aton` needs every component
    numeric."""
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):  # ValueError covers non-ASCII (UnicodeError)
        return None


def _is_sensitive(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """An address we refuse to fetch from: loopback, link-local (cloud metadata
    169.254.169.254), reserved, multicast or unspecified. Private LAN ranges are
    deliberately NOT here — users self-host subscriptions on their own network."""
    return (
        ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


async def resolve_blocks_ssrf(host: str) -> bool:
    """Resolve `host` and return True if it maps to any sensitive address.

    Complements `blocks_ssrf` (IP-literals only) by catching a *hostname* that
    resolves to loopback / link-local / reserved — the DNS-rebinding shape of
    SSRF (e.g. an attacker-controlled name pointing at 169.254.169.254). Blocks
    on *any* sensitive answer so a name that returns both a public and a
    metadata IP can't slip through.

    Best-effort and fail-open: on a resolution error we return False rather than
    block — httpx would then fail to connect anyway, and a router resolver
    hiccup shouldn't break a legitimate fetch. IP-literal hosts return False
    here (already covered by `blocks_ssrf`).
    """
    try:
        ipaddress.ip_address(host)
        return False  # IP literal — blocks_ssrf already ruled on it
    except ValueError:
        pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue  # scoped/odd literal — skip
        if _is_sensitive(ip):
            return True
    return False


async def fetch_url(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int = MAX_BODY_BYTES,
) -> bytes:
    """GET url; return bytes; raise FetchError on any problem.

    Overflow is detected in a single pass: the running total is checked after
    each chunk, so the read stops at up to `max_bytes` plus one chunk rather
    than draining the whole stream first. Refuses non-public targets — both IP
    literals and hostnames that resolve to loopback/link-local/reserved (SSRF
    guard).
    """
    # The literal check is free and always runs. The *resolving* one is not:
    # it is a plaintext DNS query from the router, which takes OUTPUT and is
    # therefore never captured — so on the proxied path it is the ONLY lookup
    # that happens (httpx sends `CONNECT host:port` and never resolves), i.e.
    # this guard would hand the subscription's hostname to the ISP's resolver
    # on every fetch and every 6-hourly refresh. That is precisely what
    # `kitewrt.proxied` exists to prevent, so a fetcher that is going through
    # the proxy opts out. sing-box still applies the user's routing to whatever
    # the name resolves to, and it is resolved at the exit rather than here.
    # `blocks_ssrf_name` is on the free side of that line — it reads the name
    # instead of resolving it — so it runs on both paths. Without it the
    # proxied path had no hostname guard at all, and a proxied
    # `CONNECT localhost:9090` is resolved by sing-box's own `dns-local`
    # (dnsmasq), i.e. straight back to the router.
    tunnels = getattr(client, "tunnels", None)
    resolving_fetcher = not (tunnels is not None and await tunnels())
    try:
        host = urlparse(url).hostname
    except ValueError as exc:
        # `urlparse` raises on some malformed inputs (e.g. an unbalanced IPv6
        # bracket) — before the try below, so this escaped the function
        # entirely, past `refresh_all`'s "never raises" contract and out of the
        # background refresh pump.
        raise FetchError(f"not a usable URL: {exc}") from exc
    if host and (
        blocks_ssrf(host)
        or blocks_ssrf_name(host)
        or (resolving_fetcher and await resolve_blocks_ssrf(host))
    ):
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
    except (httpx.HTTPError, httpx.InvalidURL, OSError) as exc:
        # `InvalidURL` is deliberately listed: it does NOT inherit `HTTPError`
        # (it derives straight from Exception), so a malformed subscription URL
        # escaped this function entirely — past `refresh_all`'s "never raises"
        # contract and out of the background refresh pump. Verified against
        # httpx 0.28.
        #
        # Connect/read timeouts and connection resets (e.g. an upstream block)
        # often stringify to "" — fall back to the exception class name so the
        # API surfaces "ConnectTimeout" / "ConnectError" instead of a useless
        # generic "error" (the empty detail otherwise collapses to that).
        raise FetchError(str(exc).strip() or type(exc).__name__) from exc
