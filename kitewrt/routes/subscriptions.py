"""Subscription CRUD: add / delete / refresh / rename."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException

from kitewrt.autoselect import pick_fastest, rank_by_delay
from kitewrt.deps import (
    ClashDep,
    DataPlaneDep,
    FetcherDep,
    PipelineDep,
    StateDep,
    commit_and_signal,
)
from kitewrt.fetch import FetchError
from kitewrt.schemas import AddSubscriptionReq, PatchSubscriptionReq
from kitewrt.state import ActiveServerRef, Data
from kitewrt.subscriptions import fetch_and_parse
from kitewrt.vless import NODE_SCHEMES, Server, VlessParseError, parse_node

router = APIRouter(prefix="/api/subscriptions", tags=["subscriptions"])


@router.post("")
async def add_subscription(req: AddSubscriptionReq, state: StateDep, fetcher: FetcherDep) -> Data:
    label = req.label.strip()
    source = req.source.strip()
    if not label:
        label = _derive_label(source)
    servers = await _fetch_and_parse(fetcher, source)
    if not servers:
        raise HTTPException(400, "no usable servers in subscription")
    await state.add_subscription(label, source, servers)
    # New sub doesn't change runtime state — no apply needed.
    return state.snapshot()


@router.delete("/{sub_id}")
async def delete_subscription(sub_id: str, state: StateDep, pipeline: PipelineDep) -> Data:
    if not state.has_subscription(sub_id):
        raise HTTPException(404, f"unknown subscription: {sub_id!r}")
    prev = state.snapshot()
    affected = prev.active_server is not None and prev.active_server.subscription_id == sub_id
    await state.delete_subscription(sub_id)
    # Only trigger apply when deletion actually changes runtime state.
    if affected:
        await commit_and_signal(state, pipeline, _mark_applying)
    return state.snapshot()


@router.post("/{sub_id}/refresh")
async def refresh_subscription(
    sub_id: str, state: StateDep, fetcher: FetcherDep, pipeline: PipelineDep
) -> Data:
    snap = state.snapshot()
    source = next((s.source for s in snap.subscriptions if s.id == sub_id), None)
    if source is None:
        raise HTTPException(404, f"unknown subscription: {sub_id!r}")
    servers = await _fetch_and_parse(fetcher, source)
    if not servers:
        raise HTTPException(400, "no usable servers in subscription")
    was_active_here = (
        snap.active_server is not None and snap.active_server.subscription_id == sub_id
    )
    await state.replace_subscription_servers(sub_id, servers)
    if was_active_here:
        await commit_and_signal(state, pipeline, _mark_applying)
    return state.snapshot()


async def _delay_test_all(
    sub_id: str, state: StateDep, clash: ClashDep, dataplane: DataPlaneDep
) -> dict[str, int | None]:
    """Materialize the data plane, then delay-test every server in `sub_id`
    *through the proxy*; return {server_id: ms-or-None}. Shared by /test and
    /auto-select.

    Through-the-proxy (not a raw router-side TCP-connect): the tun's fake-IP DNS
    resolves every server host to a local fake-IP, so a TCP probe from the router
    terminates at the tun in ~1 ms (meaningless) and can't reach the UDP/QUIC
    protocols at all. sing-box's Clash delay-test dials through each outbound, so
    it reflects the real end-to-end RTT and covers every protocol. Materializing
    first means it works with the VPN off too (sing-box is brought up with this
    sub's outbounds purely for the test)."""
    snap = state.snapshot()
    sub = next((s for s in snap.subscriptions if s.id == sub_id), None)
    if sub is None:
        raise HTTPException(404, f"unknown subscription: {sub_id!r}")
    if not sub.servers:
        raise HTTPException(400, "subscription has no servers")
    if clash is None:
        raise HTTPException(503, "delay-test unavailable: no data plane")
    if dataplane is not None:
        ok, msg = await dataplane.ensure_materialized(snap)
        if not ok:
            raise HTTPException(503, f"could not start proxy for delay-test: {msg}")
    return await rank_by_delay(clash, sub_id, sub.servers)


@router.post("/{sub_id}/test")
async def test_subscription(
    sub_id: str, state: StateDep, clash: ClashDep, dataplane: DataPlaneDep
) -> Data:
    """Delay-test every server in this subscription through the proxy and record
    the results as latency badges, re-sorting tiles by ping. Observation-only:
    unlike /auto-select it does NOT change the active server or signal the apply
    pipeline.
    """
    results = await _delay_test_all(sub_id, state, clash, dataplane)
    return await state.merge_pings(results)


@router.post("/{sub_id}/auto-select")
async def auto_select_server(
    sub_id: str, state: StateDep, pipeline: PipelineDep, clash: ClashDep, dataplane: DataPlaneDep
) -> Data:
    """Delay-test every server in this subscription through the proxy, record the
    results as latency badges, then switch the active server to the fastest.

    Mirrors POST /server (sets active_server + applying, signals the pipeline)
    but picks the target by measured end-to-end delay instead of a manual click.
    Deliberately does NOT touch vpn_on — the existing on/off state decides
    whether the pick goes live now or is just remembered for the next on.
    """
    results = await _delay_test_all(sub_id, state, clash, dataplane)
    # Persist the badges first so the UI reflects what we measured even if no
    # node passed (the user sees every server marked down, not a bare error).
    await state.merge_pings(results)
    best = pick_fastest(results)
    if best is None:
        raise HTTPException(502, "no server passed the delay test (is sing-box running?)")

    def mutate(d: Data) -> None:
        d.active_server = ActiveServerRef(subscription_id=sub_id, server_id=best)
        d.applying = True

    return await commit_and_signal(state, pipeline, mutate)


@router.patch("/{sub_id}")
async def patch_subscription(sub_id: str, req: PatchSubscriptionReq, state: StateDep) -> Data:
    if not state.has_subscription(sub_id):
        raise HTTPException(404, f"unknown subscription: {sub_id!r}")
    label = req.label.strip()
    if not label:
        source = next((s.source for s in state.snapshot().subscriptions if s.id == sub_id), "")
        label = _derive_label(source)
    await state.rename_subscription(sub_id, label)
    return state.snapshot()


# --- Helpers ----------------------------------------------------------------


async def _fetch_and_parse(fetcher: httpx.AsyncClient, source: str) -> list[Server]:
    """Fetch + parse a subscription source, translating the service layer's
    domain errors into HTTP status codes (502 fetch, 400 parse)."""
    try:
        return await fetch_and_parse(fetcher, source)
    except FetchError as exc:
        raise HTTPException(502, str(exc)) from exc
    except VlessParseError as exc:
        raise HTTPException(400, f"subscription parse failed: {exc}") from exc


def _derive_label(source: str) -> str:
    """Auto-generate a label from a subscription source.

    URL → host:port (or just host). Inline node URI → embedded proxy host.
    Always returns a non-empty string.
    """
    s = source.strip()
    if s.startswith(NODE_SCHEMES):
        try:
            return parse_node(s).host or "proxy link"
        except VlessParseError:
            return "proxy link"
    return urlparse(s).netloc or "Subscription"


def _mark_applying(d: Data) -> None:
    d.applying = True
