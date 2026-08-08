"""Proxy delay-test ranking — the data behind both "Test" and "⚡ Fastest".

This is the only latency measurement kitewrt makes. There is no router-side
TCP-connect probe any more: it timed reachability to the server's *edge* rather
than the path traffic takes, and it could not touch the UDP/QUIC protocols
(hysteria2 / hysteria v1 / tuic) at all, which therefore always read as down.
Instead, sing-box dials each server's *outbound* and times an HTTP round-trip to
a 204 endpoint — the full ISP → server → internet path. A node that connects
fast but proxies badly scores honestly.

Requires sing-box up (the Clash controller answers). It works with the VPN off
as well as on, because on/off only moves the selector's `default` and never
changes the set of dialable outbounds — but that is a property of the *generated*
config, not the *running* one. Adding a subscription deliberately skips the
reload, and with the VPN off sing-box may not be running at all, so callers must
go through `dataplane.ensure_materialized` first (`routes/subscriptions.py`
does).
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
    into State.merge_pings and the UI's latency badges.
    """
    sem = asyncio.Semaphore(concurrency)

    async def one(srv: Server) -> tuple[str, int | None]:
        async with sem:
            ms = await clash.delay(outbound_tag(subscription_id, srv.id), timeout_ms=timeout_ms)
        return srv.id, ms

    # `return_exceptions=True`: one server raising must not abort the whole
    # delay test. `clash.delay` maps its own failures to None, so reaching here
    # means something unforeseen — and without this the first one propagates
    # while its siblings keep running unawaited, so the user gets no ranking at
    # all instead of a ranking missing one node.
    pairs = await asyncio.gather(*(one(s) for s in servers), return_exceptions=True)
    out: dict[str, int | None] = {}
    for srv, result in zip(servers, pairs):
        if isinstance(result, BaseException):
            logger.warning("delay test for %s failed: %s", srv.name, result)
            out[srv.id] = None
        else:
            out[result[0]] = result[1]
    return out


def pick_fastest(results: dict[str, int | None]) -> str | None:
    """The server_id with the lowest delay, or None when every server failed."""
    alive = {sid: ms for sid, ms in results.items() if ms is not None}
    if not alive:
        return None
    return min(alive, key=alive.__getitem__)
