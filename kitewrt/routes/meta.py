"""Health/state/catch-all routes."""

from __future__ import annotations

import socket

from fastapi import APIRouter, HTTPException

from kitewrt.deps import StateDep
from kitewrt.state import Data

router = APIRouter(prefix="/api", tags=["meta"])


@router.get("/state")
async def get_state(state: StateDep) -> Data:
    return state.snapshot()


@router.get("/health")
async def get_health() -> dict[str, object]:
    return {"ok": True, "host": socket.gethostname()}


# Catch-all for unknown /api/* paths. Registered last via the app factory
# so specific routes take precedence. `api_route` covers all HTTP methods
# in one decorator.
catch_all_router = APIRouter(prefix="/api", include_in_schema=False)


@catch_all_router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def unknown_api(path: str) -> None:
    raise HTTPException(404, "unknown endpoint")
