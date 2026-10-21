"""VPN on/off toggle — POST /api/toggle."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from kitewrt.deps import PipelineDep, StateDep, commit_and_signal
from kitewrt.schemas import ToggleReq, state_payload
from kitewrt.state import Data

router = APIRouter(prefix="/api", tags=["vpn"])


@router.post("/toggle")
async def toggle_vpn(req: ToggleReq, state: StateDep, pipeline: PipelineDep) -> dict[str, Any]:
    def mutate(d: Data) -> None:
        if req.on and not any(
            d.active_server is not None
            and sub.id == d.active_server.subscription_id
            and any(srv.id == d.active_server.server_id for srv in sub.servers)
            for sub in d.subscriptions
        ):
            raise HTTPException(400, "no active server selected")
        d.vpn_on = req.on
        d.applying = True

    return state_payload(await commit_and_signal(state, pipeline, mutate))
