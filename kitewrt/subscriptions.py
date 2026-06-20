"""Subscription business logic — fetch/parse + periodic auto-refresh.

Lives outside the route module so the exact same fetch → parse → replace flow
runs whether a user clicks *Refresh* or the background pump fires. The route
layer (kitewrt.routes.subscriptions) translates the domain errors raised here
into HTTP; the pump (kitewrt.api._subscription_refresh_pump) logs and skips.
"""

from __future__ import annotations

import logging

import httpx

from kitewrt.deps import PipelineLike, commit_and_signal
from kitewrt.fetch import FetchError, fetch_url
from kitewrt.state import Data, State
from kitewrt.vless import NODE_SCHEMES, Server, VlessParseError, parse_subscription

logger = logging.getLogger(__name__)


async def fetch_and_parse(fetcher: httpx.AsyncClient, source: str) -> list[Server]:
    """Resolve a subscription source to a server list.

    An inline node URI (`vless://…`) IS the node, so it's parsed in place;
    HTTP(S) sources are fetched first. Raises `FetchError` (network) or
    `VlessParseError` (unparseable body) — the caller decides whether that's an
    HTTP 4xx/5xx or a logged skip.
    """
    if source.startswith(NODE_SCHEMES):
        raw: bytes = source.encode()
    else:
        raw = await fetch_url(fetcher, source)
    return parse_subscription(raw)


def _mark_applying(d: Data) -> None:
    d.applying = True


async def refresh_all(state: State, fetcher: httpx.AsyncClient, pipeline: PipelineLike) -> int:
    """Best-effort refresh of every fetchable subscription. Returns how many
    were refreshed. Never raises — a failed source is logged and its old server
    list kept (better a stale list than an empty one).

    Mirrors the route's apply policy: a refresh only nudges the data plane when
    it touched the *active* server's subscription, so refreshing a background
    subscription never disrupts the running VPN (its new servers become live on
    the next selection, which reloads anyway).
    """
    snap = state.snapshot()
    refreshed = 0
    active_sub_changed = False
    for sub in snap.subscriptions:
        if sub.source.startswith(NODE_SCHEMES):
            continue  # inline node — nothing to re-fetch
        try:
            servers = await fetch_and_parse(fetcher, sub.source)
        except (FetchError, VlessParseError) as exc:
            logger.warning("auto-refresh %r failed: %s", sub.label, exc)
            continue
        if not servers:
            logger.warning("auto-refresh %r: no usable servers; keeping old list", sub.label)
            continue
        await state.replace_subscription_servers(sub.id, servers)
        refreshed += 1
        if snap.active_server is not None and snap.active_server.subscription_id == sub.id:
            active_sub_changed = True
    if active_sub_changed:
        await commit_and_signal(state, pipeline, _mark_applying)
    if refreshed:
        logger.info("auto-refreshed %d/%d subscription(s)", refreshed, len(snap.subscriptions))
    return refreshed
