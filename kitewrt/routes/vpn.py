"""VPN on/off toggle — POST /api/toggle."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from kitewrt.deps import PipelineDep, StateDep, commit_and_signal
from kitewrt.schemas import ToggleReq
from kitewrt.state import Data

router = APIRouter(prefix="/api", tags=["vpn"])


@router.post("/toggle")
async def toggle_vpn(req: ToggleReq, state: StateDep, pipeline: PipelineDep) -> Data:
    if req.on and state.active_server() is None:
        raise HTTPException(400, "no active server selected")

    def mutate(d: Data) -> None:
        d.vpn_on = req.on
        d.applying = True

    return await commit_and_signal(state, pipeline, mutate)
