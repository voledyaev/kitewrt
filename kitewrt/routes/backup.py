"""Settings backup — GET /api/backup (download) and POST /api/backup (restore).

`/etc/kitewrt` survives a firmware upgrade (keep.d), but not a factory reset, a
replaced router, or an uninstall — and it is the only copy of the
subscriptions. This is the copy you keep yourself.

**The file contains credentials** (VLESS UUIDs, passwords, Reality keys,
subscription URLs with their tokens): a backup without them restores nothing.
Every other `/api` response has them stripped, by `_redact_secrets` matching a
top-level `subscriptions` list; the backup nests everything under `state`, so it
passes through deliberately. Who can fetch it is the same set of people who can
already drive the VPN — the LAN, which this project treats as trusted — and the
Host check plus the browser's same-origin rule keep other web pages out.

What it carries is configuration only. Not `vpn_on` (restoring must not flip the
tunnel under anyone), not pings or results (they describe a moment, not a
choice).
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field, ValidationError

from kitewrt.deps import PipelineDep, StateDep, commit_and_signal
from kitewrt.schemas import state_payload
from kitewrt.state import (
    ActiveServerRef,
    Data,
    DnsState,
    ResolvedEndpoint,
    Subscription,
    now_iso,
)

router = APIRouter(prefix="/api", tags=["backup"])

FORMAT = "kitewrt-backup"
FORMAT_VERSION = 1
# Generous: a large rules document with its bypass list is a few hundred KB.
MAX_BACKUP_BYTES = 16 << 20


class BackupState(BaseModel):
    subscriptions: list[Subscription] = Field(default_factory=list)
    active_server: ActiveServerRef | None = None
    rules_url: str = ""
    rules_fetched_at: str = ""
    rules: list[dict[str, Any]] = Field(default_factory=list)
    rule_sets: list[dict[str, Any]] = Field(default_factory=list)
    rules_bypass_address: list[str] = Field(default_factory=list)
    dns: DnsState = Field(default_factory=DnsState)
    endpoints: dict[str, ResolvedEndpoint] = Field(default_factory=dict)


class Backup(BaseModel):
    format: str
    version: int
    exported_at: str = ""
    state: BackupState


_FIELDS = tuple(BackupState.model_fields)


@router.get("/backup")
async def download_backup(state: StateDep) -> Response:
    snap = state.snapshot()
    body = Backup(
        format=FORMAT,
        version=FORMAT_VERSION,
        exported_at=now_iso(),
        state=BackupState(**{f: getattr(snap, f) for f in _FIELDS}),
    )
    stamp = body.exported_at.replace(":", "").replace("-", "")[:15]
    return Response(
        content=body.model_dump_json(indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="kitewrt-backup-{stamp}.json"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/backup")
async def restore_backup(
    request: Request, state: StateDep, pipeline: PipelineDep
) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_BACKUP_BYTES:
        raise HTTPException(413, "backup file is too large")
    try:
        backup = Backup.model_validate(json.loads(raw))
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, f"not a kitewrt backup: {str(exc)[:200]}") from None
    if backup.format != FORMAT:
        raise HTTPException(400, "not a kitewrt backup file")
    if backup.version > FORMAT_VERSION:
        raise HTTPException(400, "backup was made by a newer kitewrt — update this router first")
    restored = backup.state
    # Validated as a whole Data too, so the cross-field checks the daemon relies
    # on (an active server that exists, …) hold before anything is written.
    candidate = Data(**{f: getattr(restored, f) for f in _FIELDS})
    if candidate.active_server is not None and not any(
        sub.id == candidate.active_server.subscription_id
        and any(srv.id == candidate.active_server.server_id for srv in sub.servers)
        for sub in candidate.subscriptions
    ):
        candidate.active_server = None

    def mutate(d: Data) -> None:
        for f in _FIELDS:
            setattr(d, f, getattr(candidate, f))
        d.applying = True

    return state_payload(await commit_and_signal(state, pipeline, mutate))
