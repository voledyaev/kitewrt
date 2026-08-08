"""DNS config — POST /api/dns/config (foreign DoH)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from kitewrt.deps import PipelineDep, StateDep, commit_and_signal
from kitewrt.schemas import DnsConfigReq, state_payload
from kitewrt.state import Data

router = APIRouter(prefix="/api/dns", tags=["dns"])


@router.post("/config")
async def set_dns_config(
    req: DnsConfigReq, state: StateDep, pipeline: PipelineDep
) -> dict[str, Any]:
    def mutate(d: Data) -> None:
        if req.doh_url is not None:
            d.dns.doh_url = req.doh_url
        if req.direct_dns is not None:
            d.dns.direct_dns = req.direct_dns
        d.applying = True

    # Always signal — apply pipeline figures out whether to swap the upstream
    # right now (if VPN is on) or just record the new default (if off).
    return state_payload(await commit_and_signal(state, pipeline, mutate))
