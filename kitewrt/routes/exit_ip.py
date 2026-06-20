"""GET /api/exit-ip — best-effort public exit IP + country.

Shows what the internet sees as the router's source IP: the VPN exit when the
tunnel is up, or the ISP IP when it's off — a small confirmation that routing
is doing what the dashboard claims. Best-effort: returns `{"available": false}`
when the lookup fails (offline, blocked, …), so the UI can just hide the card.

The lookup is cached briefly (app-wide) so multiple browser clients don't each
trigger an outbound request.
"""

from __future__ import annotations

import time

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel

from kitewrt.deps import FetcherDep, StateDep

router = APIRouter(prefix="/api", tags=["meta"])

# Cloudflare's trace endpoint returns plain `key=value` lines including `ip=`
# and `loc=` (2-letter country). No API key, neutral, and Cloudflare is already
# the default resolver — no new third party introduced.
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
_CACHE_TTL_S = 30.0


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
    vpn_on = state.snapshot().vpn_on

    now = time.monotonic()
    cache = getattr(request.app.state, "kitewrt_exitip_cache", None)
    # Key the cache on vpn_on: toggling the VPN changes the exit, so a flip must
    # force a fresh lookup rather than serving the pre-toggle IP for up to 30s.
    if cache and cache["vpn_on"] == vpn_on and now - cache["at"] < _CACHE_TTL_S:
        return cache["data"].model_copy(update={"vpn_on": vpn_on})

    try:
        resp = await fetcher.get(TRACE_URL, timeout=8.0)
        kv = parse_trace(resp.text)
        data = ExitIpResp(available=True, ip=kv.get("ip", ""), country=kv.get("loc", ""))
    except (httpx.HTTPError, OSError):
        data = ExitIpResp(available=False)

    request.app.state.kitewrt_exitip_cache = {"at": now, "data": data, "vpn_on": vpn_on}
    return data.model_copy(update={"vpn_on": vpn_on})
