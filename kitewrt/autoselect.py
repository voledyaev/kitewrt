"""Proxy delay-test ranking — the data behind "auto-select fastest server".

Unlike probe.py's raw TCP-connect (which only times reachability to the server's
edge), this dials each server's *outbound* through sing-box and measures an HTTP
round-trip to a 204 endpoint — the full ISP → server → internet path the user's
traffic actually takes. A node that connects fast but proxies badly scores
honestly.

Requires sing-box up (the Clash controller answers); works whether the VPN is on
or off, because every server is always a live outbound in the config — only the
selector's `default` changes with on/off, never the set of dialable outbounds.
"""

from __future__ import annotations

import asyncio
import logging

from kitewrt.singbox.clash import ClashClient
from kitewrt.singbox.outbound import outbound_tag
from kitewrt.vless import Server

logger = logging.getLogger(__name__)

# Bound the concurrent delay-tests: each opens a real *cold* TLS handshake +
# HTTP-204 through a distinct server, so a 20-50 node subscription would
# otherwise fire that many simultaneous fresh outbound connections off the
# router at once — right after a materialize-reload, no less. On a constrained
# router (or its ISP NAT) a wide cold burst saturates the connection table and
# makes healthy nodes spuriously read "down" (504). 5 keeps the burst gentle
# enough to rank honestly while still draining a full subscription in a few
# rounds. Verified on the QEMU testbed: a burst of 8 storms the usermode NAT
# post-reload; 5 does not.
_MAX_CONCURRENCY = 5
# Per-server cap. Shorter than the Clash client's 5s default: a server that needs
# >3s to answer a 204 probe is already too slow to want as "fastest", and the
# tighter cap keeps the worst-case wall time (all nodes timing out) bounded so
# the UI spinner doesn't hang.
_DELAY_TIMEOUT_MS = 3000


async def rank_by_delay(
    clash: ClashClient,
    subscription_id: str,
    servers: list[Server],
    *,
    timeout_ms: int = _DELAY_TIMEOUT_MS,
    concurrency: int = _MAX_CONCURRENCY,
) -> dict[str, int | None]:
    """Delay-test every server (by its composite outbound tag) in bounded
    parallel. Returns {server_id: ms-or-None}; None means the node failed the
    test (timeout / handshake error / controller hiccup).

    Keyed by `server_id` (not the composite tag) so the result drops straight
    into State.merge_pings and the UI's latency badges, exactly like probe.py.
    """
    sem = asyncio.Semaphore(concurrency)

    async def one(srv: Server) -> tuple[str, int | None]:
        async with sem:
            ms = await clash.delay(outbound_tag(subscription_id, srv.id), timeout_ms=timeout_ms)
        return srv.id, ms

    pairs = await asyncio.gather(*(one(s) for s in servers))
    return dict(pairs)


def pick_fastest(results: dict[str, int | None]) -> str | None:
    """The server_id with the lowest delay, or None when every server failed."""
    alive = {sid: ms for sid, ms in results.items() if ms is not None}
    if not alive:
        return None
    return min(alive, key=alive.__getitem__)
