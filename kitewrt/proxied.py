"""The daemon's own HTTP egress: through sing-box when it's up, direct when not.

Under the old `tun` inbound, `auto_route` captured *everything* the router
sent, including the daemon's own requests — subscription fetches, rules
fetches, the exit-IP check. That was implicit and, when the tunnel was up, it
meant those requests went through the proxy: the ISP never saw which
subscription URL we were pulling, and the exit-IP check reported the VPN's
address because it genuinely travelled through the VPN.

TPROXY hooks PREROUTING, which locally-generated traffic never enters, so none
of that happens by itself now. Capturing OUTPUT as well would restore it, but
that is exactly where routing loops with sing-box's own egress come from. So
the daemon asks explicitly, via sing-box's loopback HTTP-proxy inbound.

**Why there's a fallback.** sing-box only runs once there is something to
apply, so on a fresh install the sequence is: no subscription → no sing-box →
no local proxy. Routing the subscription fetch exclusively through the proxy
would deadlock the first-run experience — you could never add the first
subscription. `ProxiedFetcher` therefore tries the proxy and falls back to a
direct request when the proxy isn't there.

The fallback is deliberately narrow: only a failure to reach the *proxy
itself* falls through. An HTTP error from the far end, a timeout mid-body, a
TLS failure — those are answers, and retrying them direct would leak the
request to the ISP for no benefit.

Narrow enough is the hard part. `httpx.ConnectError` is *not* the signal it
looks like: httpcore maps a far-end `ssl.SSLError` to `ConnectError` from
inside `start_tls`, which runs **after** the CONNECT tunnel is up. So a
working proxy plus a failed handshake with the destination raises exactly the
same exception as a proxy that isn't listening — and retrying that in the
clear hands the subscription URL, token and all, straight to the ISP. A
router whose clock is wrong after a power cut (which `api._await_clock_sane`
exists for) produces it on *every* fetch. So on `ConnectError` we ask the one
question that actually distinguishes the two: is anything listening on the
proxy port?
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Callable
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT_S = 2.0


@runtime_checkable
class Fetcher(Protocol):
    """The slice of `httpx.AsyncClient` kitewrt's routes and fetchers use.

    Named so `FetcherDep` can be annotated with something both an
    `AsyncClient` (tests) and a `ProxiedFetcher` (production) satisfy. It was
    previously annotated as `AsyncClient` outright, which is how a
    `ProxiedFetcher` missing `get()` shipped and turned /api/exit-ip and
    /api/connectivity into hard 500s that no test could see.
    """

    def stream(self, method: str, url: str, **kwargs: Any) -> Any: ...

    async def get(self, url: str, **kwargs: Any) -> httpx.Response: ...

    async def aclose(self) -> None: ...


class ProxiedFetcher:
    """A small httpx facade that prefers the local proxy and falls back direct.

    Exposes the `httpx.AsyncClient` surface `kitewrt` actually uses — `get()`
    and `stream()` — so it can stand in for a client at those call sites.
    """

    def __init__(
        self,
        proxied: httpx.AsyncClient | Callable[[], httpx.AsyncClient],
        direct: httpx.AsyncClient,
        *,
        proxy_url: str = "",
    ) -> None:
        self._proxied = proxied
        self._direct = direct
        self._probe = _probe_target(proxy_url)

    @contextlib.asynccontextmanager
    async def _proxy_client(self) -> AsyncIterator[httpx.AsyncClient]:
        # httpcore 1.0.9 leaves CONNECT tunnels ACTIVE after a TLS failure
        # (encode/httpcore#921). A long-lived pool eventually fills with these
        # unusable entries and every later request raises PoolTimeout. Production
        # supplies a factory: each request owns and closes its pool, including on
        # cancellation. Do not rotate/close a shared pool under concurrent reads.
        if callable(self._proxied):
            async with self._proxied() as client:
                yield client
        else:
            yield self._proxied

    @contextlib.asynccontextmanager
    async def stream(self, method: str, url: str, **kwargs: Any) -> AsyncIterator[httpx.Response]:
        async with self._proxy_client() as client, contextlib.AsyncExitStack() as stack:
            try:
                resp = await stack.enter_async_context(client.stream(method, url, **kwargs))
            except httpx.ConnectError:
                if not await self._fall_back(url):
                    raise
                resp = await stack.enter_async_context(self._direct.stream(method, url, **kwargs))
            # Keep the yield outside the catch: errors while consuming a
            # response must never trigger a second request in the clear.
            yield resp

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Buffered GET. Used by the exit-IP and connectivity probes."""
        async with self._proxy_client() as client:
            try:
                return await client.get(url, **kwargs)
            except httpx.ConnectError:
                if not await self._fall_back(url):
                    raise
                return await self._direct.get(url, **kwargs)

    async def _fall_back(self, url: str) -> bool:
        """Should a failed proxied request be retried in the clear?

        Only when the proxy itself is not there. Logged by host, never by full
        URL — subscription URLs carry tokens and this runs at INFO.
        """
        if await _is_listening(self._probe):
            return False
        logger.info("local proxy unavailable; fetching %s directly", _host_of(url))
        return True

    async def tunnels(self) -> bool:
        """Will the next request actually go through the proxy?

        `kitewrt.fetch` asks this to decide whether its SSRF guard may resolve
        the hostname locally. Answered by probing, not by a flag: this class
        falls back to a direct request whenever the proxy port is dead — the
        fresh-install state, i.e. exactly when a user pastes a subscription
        link they were handed — and on that path the lookup is local anyway, so
        there is nothing to leak and every reason to keep the DNS-rebinding
        check. A cached answer would be wrong for precisely the first fetch.
        """
        return await _is_listening(self._probe)

    async def aclose(self) -> None:
        if not callable(self._proxied):
            await self._proxied.aclose()
        await self._direct.aclose()


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or "?"
    except ValueError:
        return "?"


def _probe_target(proxy_url: str) -> tuple[str, int] | None:
    """The (host, port) to test for liveness, or None to always fall back.

    None means we were given no proxy address, so there is nothing to
    distinguish — treat every connect failure as "no proxy", which is the
    pre-existing behaviour and what the tests inject.
    """
    if not proxy_url:
        return None
    parts = urlsplit(proxy_url)
    if not parts.hostname or not parts.port:
        # Silently reverting to "always fall back" is how the leak this guard
        # exists for would come back — so say so. Reachable only if
        # LOCAL_PROXY_URL ever loses its explicit port.
        logger.warning(
            "proxy url %r has no host:port to probe; every connect failure will "
            "fall back to a direct request",
            proxy_url,
        )
        return None
    return parts.hostname, parts.port


async def _is_listening(target: tuple[str, int] | None) -> bool:
    if target is None:
        return False
    try:
        fut = asyncio.open_connection(*target)
        _reader, writer = await asyncio.wait_for(fut, timeout=_PROBE_TIMEOUT_S)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    with contextlib.suppress(OSError, asyncio.TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), timeout=_PROBE_TIMEOUT_S)
    return True
