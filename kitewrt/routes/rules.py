"""Routing rules — set URL + refresh."""

from __future__ import annotations

import httpx
from fastapi import APIRouter, HTTPException

from kitewrt.deps import (
    FetcherDep,
    PipelineDep,
    RulesParser,
    RulesParserDep,
    StateDep,
    commit_and_signal,
)
from kitewrt.fetch import FetchError, fetch_url
from kitewrt.rules import RulesParseError
from kitewrt.schemas import RulesURLReq
from kitewrt.state import Data, now_iso

router = APIRouter(prefix="/api", tags=["rules"])


@router.post("/rules-url")
async def set_rules_url(
    req: RulesURLReq,
    state: StateDep,
    fetcher: FetcherDep,
    pipeline: PipelineDep,
    parse_rules: RulesParserDep,
) -> Data:
    if not req.url:
        # Clear: fall back to the bundled default rules.
        def clear(d: Data) -> None:
            d.rules_url = ""
            d.rules_fetched_at = ""
            d.rules = []
            d.rule_sets = []
            d.rules_warnings = []
            d.rules_skipped_count = 0
            d.applying = True

        return await commit_and_signal(state, pipeline, clear)

    parsed = await _fetch_and_validate(fetcher, req.url, parse_rules)

    def install(d: Data) -> None:
        d.rules_url = req.url  # type: ignore[assignment]
        d.rules_fetched_at = now_iso()
        d.rules = parsed["rules"]
        d.rule_sets = parsed["rule_set"]
        d.rules_warnings = []
        d.rules_skipped_count = 0
        d.applying = True

    return await commit_and_signal(state, pipeline, install)


@router.post("/rules/refresh")
async def refresh_rules(
    state: StateDep,
    fetcher: FetcherDep,
    pipeline: PipelineDep,
    parse_rules: RulesParserDep,
) -> Data:
    snap = state.snapshot()
    if not snap.rules_url:
        raise HTTPException(400, "no rules_url configured")
    parsed = await _fetch_and_validate(fetcher, snap.rules_url, parse_rules)

    def install(d: Data) -> None:
        d.rules_fetched_at = now_iso()
        d.rules = parsed["rules"]
        d.rule_sets = parsed["rule_set"]
        d.rules_warnings = []
        d.rules_skipped_count = 0
        d.applying = True

    return await commit_and_signal(state, pipeline, install)


async def _fetch_and_validate(
    fetcher: httpx.AsyncClient, url: str, parse_rules: RulesParser
) -> dict[str, list[dict]]:
    try:
        raw = await fetch_url(fetcher, url)
    except FetchError as exc:
        raise HTTPException(502, str(exc)) from exc
    try:
        return parse_rules(raw)
    except RulesParseError as exc:
        raise HTTPException(400, str(exc)) from exc
