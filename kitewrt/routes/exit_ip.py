"""GET /api/exit-ip — best-effort public exit IP + country.

Shows what the internet sees as the router's source IP: the VPN exit when the
tunnel is up, or the ISP IP when it's off — a small confirmation that routing
is doing what the dashboard claims. Best-effort: returns `{"available": false}`
when the lookup fails (offline, blocked, …), so the UI can just hide the card.

The lookup is cached briefly (app-wide) so multiple browser clients don't each
trigger an outbound request.
"""

from __future__ import annotations

import asyncio
import time

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel

from kitewrt.deps import FetcherDep, StateDep
from kitewrt.http import request_bytes
from kitewrt.proxied import ProxiedFetcher
from kitewrt.state import Data

router = APIRouter(prefix="/api", tags=["meta"])

# Cloudflare's trace endpoint returns plain `key=value` lines including `ip=`
# and `loc=` (2-letter country). No API key, neutral, and Cloudflare is already
# the default resolver — no new third party introduced.
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
_CACHE_TTL_S = 30.0

# Bound the downloaded body, not just the parsed prefix.
_MAX_TRACE_BYTES = 4096


class ExitIpResp(BaseModel):
    """Public exit IP + country as the internet sees the router. `available`
    is False when the lookup failed (offline / blocked) and the UI hides the
    card; `vpn_on` is echoed so the client can label the IP VPN-exit vs ISP."""

    available: bool
    ip: str = ""
    country: str = ""
    vpn_on: bool = False


def parse_trace(text: str) -> dict[str, str]:
    """Parse Cloudflare's `cdn-cgi/trace` `key=value` lines into a dict."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key] = value
    return out


@router.get("/exit-ip")
async def exit_ip(request: Request, state: StateDep, fetcher: FetcherDep) -> ExitIpResp:
    lock = getattr(request.app.state, "kitewrt_exitip_lock", None)
    if lock is None:
        lock = request.app.state.kitewrt_exitip_lock = asyncio.Lock()
    async with lock:
        return await _lookup(request, state, fetcher)


def _egress_key(snap: Data, revision: int) -> tuple[object, ...]:
    """Invalidate observations when intent changes or an apply completes.

    An IP fetched before a selector switch must not describe the new node.
    last_apply also covers a structural reload that keeps the same selection.
    """
    ref = getattr(snap, "active_server", None)
    applied = getattr(snap, "last_apply", None)
    return (
        revision,
        snap.vpn_on,
        (ref.subscription_id, ref.server_id) if ref is not None else None,
        (applied.at, applied.ok, applied.msg) if applied is not None else None,
    )


async def _lookup(request: Request, state: StateDep, fetcher: FetcherDep) -> ExitIpResp:
    snap = state.snapshot()
    vpn_on = snap.vpn_on
    key = _egress_key(snap, getattr(state, "egress_revision", 0))
    if getattr(snap, "applying", False):
        # The selector/proxy may still be on the old route or not listening.
        # In particular ProxiedFetcher can fall back direct during startup;
        # never label that observation as the newly enabled VPN's exit.
        request.app.state.kitewrt_exitip_cache = None
        return ExitIpResp(available=False, vpn_on=vpn_on)

    now = time.monotonic()
    cache = getattr(request.app.state, "kitewrt_exitip_cache", None)
    if cache and cache["key"] == key and now - cache["at"] < _CACHE_TTL_S:
        return cache["data"].model_copy(update={"vpn_on": vpn_on})

    try:
        raw = await request_bytes(
            fetcher,
            "GET",
            TRACE_URL,
            max_bytes=_MAX_TRACE_BYTES,
            timeout_s=8.0,
            **({"allow_direct": False} if vpn_on and isinstance(fetcher, ProxiedFetcher) else {}),
        )
        kv = parse_trace(raw.decode("utf-8", errors="replace"))
        data = ExitIpResp(available=True, ip=kv.get("ip", ""), country=kv.get("loc", ""))
    except (httpx.HTTPError, httpx.InvalidURL, OSError):
        data = ExitIpResp(available=False)

    latest = state.snapshot()
    if (
        getattr(latest, "applying", False)
        or _egress_key(latest, getattr(state, "egress_revision", 0)) != key
    ):
        # State can change while the HTTP request is in flight. Discard the
        # old observation instead of publishing/caching it for the new state.
        request.app.state.kitewrt_exitip_cache = None
        return ExitIpResp(available=False, vpn_on=latest.vpn_on)
    request.app.state.kitewrt_exitip_cache = {"at": now, "data": data, "key": key}
    return data.model_copy(update={"vpn_on": vpn_on})
