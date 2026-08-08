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
        proxied: httpx.AsyncClient,
        direct: httpx.AsyncClient,
        *,
        proxy_url: str = "",
    ) -> None:
        self._proxied = proxied
        self._direct = direct
        self._probe = _probe_target(proxy_url)

    def stream(self, method: str, url: str, **kwargs: object):
        return _StreamAttempt(self, method, url, kwargs)

    async def get(self, url: str, **kwargs: object) -> httpx.Response:
        """Buffered GET. Used by the exit-IP and connectivity probes."""
        try:
            return await self._proxied.get(url, **kwargs)  # type: ignore[arg-type]
        except httpx.ConnectError:
            if not await self._fall_back(url):
                raise
            return await self._direct.get(url, **kwargs)  # type: ignore[arg-type]

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


class _StreamAttempt:
    """Async context manager that opens on the proxy, retrying direct if the
    proxy is unreachable.

    httpx's `stream()` returns a context manager rather than a coroutine, so
    the retry has to live in `__aenter__` — by the time the caller has a
    response object it is too late to switch transports.
    """

    def __init__(
        self,
        fetcher: ProxiedFetcher,
        method: str,
        url: str,
        kwargs: dict[str, object],
    ) -> None:
        self._fetcher = fetcher
        self._method = method
        self._url = url
        self._kwargs = kwargs
        self._ctx: object | None = None

    async def __aenter__(self) -> httpx.Response:
        ctx = self._fetcher._proxied.stream(self._method, self._url, **self._kwargs)  # type: ignore[arg-type]
        try:
            resp = await ctx.__aenter__()
        except httpx.ConnectError:
            # sing-box may be down or still starting — fall back so a fresh
            # install can fetch its first subscription. But only if the proxy
            # port is genuinely dead: httpcore raises this same error for a
            # far-end TLS failure behind a live tunnel, and retrying *that* in
            # the clear leaks the URL. Anything else (timeout, HTTP status) is
            # a real answer and is never retried.
            if not await self._fetcher._fall_back(self._url):
                raise
            ctx = self._fetcher._direct.stream(self._method, self._url, **self._kwargs)  # type: ignore[arg-type]
            resp = await ctx.__aenter__()
        self._ctx = ctx
        return resp

    async def __aexit__(self, *exc_info: object) -> bool | None:
        if self._ctx is None:
            return None
        return await self._ctx.__aexit__(*exc_info)  # type: ignore[attr-defined,no-any-return]
