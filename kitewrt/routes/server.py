"""Active-server selection — POST /api/server."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from kitewrt.dataplane import DataPlane
from kitewrt.deps import ClashDep, DataPlaneDep, PipelineDep, StateDep, commit_and_signal
from kitewrt.schemas import ServerSelectReq, state_payload
from kitewrt.singbox.clash import ClashClient
from kitewrt.singbox.outbound import outbound_tag
from kitewrt.state import ActiveServerRef, Data, State

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["server"])

# Must match the prefix web/src/components/Subscriptions.tsx looks for to offer
# "switch anyway" — pinned by tests/test_api.py.
UNREACHABLE_PREFIX = "Server did not answer a test connection"

# Per attempt. Two attempts, so a cold handshake gets a second chance.
_PREFLIGHT_TIMEOUT_MS = 4000


@router.post("/server")
async def select_server(
    req: ServerSelectReq,
    state: StateDep,
    pipeline: PipelineDep,
    clash: ClashDep,
    dataplane: DataPlaneDep,
) -> dict[str, Any]:
    new_ref: ActiveServerRef | None = None
    if req.subscription_id and req.server_id:
        if not state.has_server(req.subscription_id, req.server_id):
            raise HTTPException(
                400,
                f"unknown (subscription_id, server_id): "
                f"({req.subscription_id!r}, {req.server_id!r})",
            )
        new_ref = ActiveServerRef(subscription_id=req.subscription_id, server_id=req.server_id)
        if not req.force:
            await _preflight(new_ref, state, clash, dataplane)

    def mutate(d: Data) -> None:
        d.active_server = new_ref
        d.applying = True

    return state_payload(await commit_and_signal(state, pipeline, mutate))


async def _preflight(
    ref: ActiveServerRef,
    state: State,
    clash: ClashClient | None,
    dataplane: DataPlane | None,
) -> None:
    """Refuse to move a working VPN onto a node that does not answer.

    The incident behind this: the user picked a country whose node was blocked
    from their ISP (TCP connects, TLS never completes). The switch itself was a
    clean Clash select that returned 204, so nothing objected — and the LAN's
    tunnelled traffic simply stopped. Test the node first, the same way the
    latency badges do (a real request through that outbound).

    Only with the VPN on: with it off a pick is just remembered, and there is
    nothing working to protect. Best-effort the other way too — if the test
    cannot be run at all (no data plane, sing-box not materialized) the switch
    goes ahead as before rather than being blocked by the safety check itself.
    """
    snap = state.snapshot()
    if not snap.vpn_on or clash is None or dataplane is None:
        return
    if snap.active_server == ref:
        return
    ok, msg = await dataplane.ensure_materialized(snap)
    if not ok:
        logger.warning("pre-switch test skipped: %s", msg)
        return
    tag = outbound_tag(ref.subscription_id, ref.server_id)
    ms = None
    for _ in range(2):
        ms = await clash.delay(tag, timeout_ms=_PREFLIGHT_TIMEOUT_MS)
        if ms is not None:
            break
    await state.merge_pings({ref.server_id: ms})
    if ms is None:
        name = next(
            (
                srv.name
                for sub in snap.subscriptions
                if sub.id == ref.subscription_id
                for srv in sub.servers
                if srv.id == ref.server_id
            ),
            ref.server_id,
        )
        raise HTTPException(
            409,
            f"{UNREACHABLE_PREFIX}: {name} — the VPN stays on the current server. "
            "It may be blocked from your network.",
        )
