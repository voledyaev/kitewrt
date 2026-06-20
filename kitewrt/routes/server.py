"""Active-server selection — POST /api/server."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from kitewrt.deps import PipelineDep, StateDep, commit_and_signal
from kitewrt.schemas import ServerSelectReq
from kitewrt.state import ActiveServerRef, Data

router = APIRouter(prefix="/api", tags=["server"])


@router.post("/server")
async def select_server(req: ServerSelectReq, state: StateDep, pipeline: PipelineDep) -> Data:
    new_ref: ActiveServerRef | None = None
    if req.subscription_id and req.server_id:
        if not state.has_server(req.subscription_id, req.server_id):
            raise HTTPException(
                400,
                f"unknown (subscription_id, server_id): "
                f"({req.subscription_id!r}, {req.server_id!r})",
            )
        new_ref = ActiveServerRef(subscription_id=req.subscription_id, server_id=req.server_id)

    def mutate(d: Data) -> None:
        d.active_server = new_ref
        d.applying = True

    return await commit_and_signal(state, pipeline, mutate)
