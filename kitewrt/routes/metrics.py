"""Live data-plane metrics — GET /api/metrics.

A small summary of sing-box's Clash `/connections` endpoint (the controller is
local-only on the router, so the browser can't reach it directly — kitewrt
relays a summary). Ephemeral, not persisted: the UI polls this a few times a
second while the VPN is on to show throughput / connection counts. Returns
`{"available": false}` when the VPN is off or the controller isn't reachable,
so the UI can simply hide the panel.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from kitewrt.deps import ClashDep, StateDep
from kitewrt.singbox.clash import ClashError
from kitewrt.singbox.config import SELECTOR_TAG

router = APIRouter(prefix="/api", tags=["metrics"])


def build_metrics_summary(conns: dict[str, Any], now: str) -> dict[str, Any]:
    """Summarise a Clash `/connections` payload for the UI. Shared by the
    polling endpoint and the WebSocket pump so they stay identical."""
    items = conns.get("connections") or []
    # A connection went through the proxy iff the selector is in its chain;
    # otherwise it was routed direct (home / private). Lets the UI show the split.
    proxied = sum(1 for c in items if SELECTOR_TAG in (c.get("chains") or []))

    def _bytes(c: dict[str, Any]) -> int:
        return int(c.get("download", 0)) + int(c.get("upload", 0))

    # Top connections by total bytes — "where is traffic going right now".
    top = []
    for c in sorted(items, key=_bytes, reverse=True)[:6]:
        meta = c.get("metadata") or {}
        top.append(
            {
                "host": meta.get("host") or meta.get("destinationIP") or "?",
                "down": int(c.get("download", 0)),
                "up": int(c.get("upload", 0)),
                "proxied": SELECTOR_TAG in (c.get("chains") or []),
                "net": (meta.get("network") or "").lower(),  # tcp / udp(quic)
            }
        )

    return {
        "available": True,
        "now": now,  # active outbound tag the selector points at
        "download_total": int(conns.get("downloadTotal", 0)),
        "upload_total": int(conns.get("uploadTotal", 0)),
        "connections": len(items),
        "proxied": proxied,
        "direct": len(items) - proxied,
        "memory": int(conns.get("memory", 0)),
        "top": top,
        "clients": _client_rollup(items),
    }


def _client_rollup(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-LAN-device traffic, the most useful "deeper" metric on a home router:
    aggregate every active connection by its source IP so the UI can show which
    device is using how much. Top 6 by total bytes.

    Keyed by metadata.sourceIP — on the router that's the LAN client (phone,
    laptop, TV); router-originated traffic (DNS, health checks) shows as the tun
    gateway and stays tiny, so real devices naturally sort to the top.
    """
    by_ip: dict[str, dict[str, int]] = {}
    for c in items:
        ip = (c.get("metadata") or {}).get("sourceIP") or "?"
        agg = by_ip.setdefault(ip, {"down": 0, "up": 0, "conns": 0})
        agg["down"] += int(c.get("download", 0))
        agg["up"] += int(c.get("upload", 0))
        agg["conns"] += 1
    rows = [{"ip": ip, **agg} for ip, agg in by_ip.items()]
    rows.sort(key=lambda r: r["down"] + r["up"], reverse=True)
    return rows[:6]


@router.get("/metrics")
async def metrics(request: Request, state: StateDep, clash: ClashDep) -> dict[str, Any]:
    """Returns the server-cached metrics frame when one is available
    (computed by the pump every ~1s, with rates and history). Falls back
    to a live Clash call on a fresh boot before the pump has ticked.

    The cached path is what makes WebSocket-less clients (or the
    fallback poll loop while WS is reconnecting) see rates + history
    instead of zero-rate, no-history frames.
    """
    store = getattr(request.app.state, "kitewrt_metrics_store", None)
    if store is not None:
        latest = store.latest_frame()
        if latest is not None:
            return latest
    # No cached frame yet (pump hasn't ticked) — do a one-shot live query
    # so the first /api/metrics caller after boot still gets something.
    # Rates will be zero (no prior totals to delta against); history empty.
    snap = state.snapshot()
    if not snap.vpn_on or clash is None:
        return {"available": False}
    try:
        conns = await clash.connections()
        now = await clash.current(SELECTOR_TAG)
    except ClashError:
        return {"available": False}
    return {**build_metrics_summary(conns, now), "down_rate": 0.0, "up_rate": 0.0, "history": []}
