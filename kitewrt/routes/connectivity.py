"""GET /api/connectivity — quick reachability probe to a few well-known sites.

Confirms the data path actually reaches the internet (through the tunnel when
the VPN is on, direct when it's off). Each target is fetched concurrently with
a short timeout; a result is `{name, ok, ms}`. Best-effort and cached briefly so
multiple browser clients don't each fan out probes.
"""

from __future__ import annotations

import asyncio
import time

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel

from kitewrt.deps import FetcherDep

router = APIRouter(prefix="/api", tags=["meta"])

# Lightweight, widely-reachable endpoints (204 / tiny body). Purely a "can the
# data path reach the internet" check — no rate-limited API endpoints.
TARGETS = [
    ("Google", "https://www.google.com/generate_204"),
    ("Cloudflare", "https://cloudflare.com/cdn-cgi/trace"),
    ("GitHub", "https://github.com/robots.txt"),
]
_CACHE_TTL_S = 10.0
_TIMEOUT_S = 6.0


class ConnectivityTarget(BaseModel):
    """One reachability probe. `ms` is None when the host was unreachable
    (transport error / timeout) — the UI renders that as a failed target."""

    name: str
    ok: bool
    ms: int | None


class ConnectivityResp(BaseModel):
    targets: list[ConnectivityTarget]


async def _probe(fetcher: httpx.AsyncClient, name: str, url: str) -> ConnectivityTarget:
    start = time.monotonic()
    try:
        # Any response (even 4xx) means we reached the host — that's
        # "connectivity". Only a transport error counts as unreachable.
        await fetcher.get(url, timeout=_TIMEOUT_S)
        return ConnectivityTarget(name=name, ok=True, ms=round((time.monotonic() - start) * 1000))
    except (httpx.HTTPError, OSError):
        return ConnectivityTarget(name=name, ok=False, ms=None)


@router.get("/connectivity")
async def connectivity(request: Request, fetcher: FetcherDep) -> ConnectivityResp:
    now = time.monotonic()
    cache = getattr(request.app.state, "kitewrt_conn_cache", None)
    if cache and now - cache["at"] < _CACHE_TTL_S:
        return cache["data"]

    results = await asyncio.gather(*(_probe(fetcher, name, url) for name, url in TARGETS))
    data = ConnectivityResp(targets=list(results))
    request.app.state.kitewrt_conn_cache = {"at": now, "data": data}
    return data
