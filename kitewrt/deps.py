"""FastAPI dependency accessors.

The app factory attaches state / pipeline / fetcher onto `app.state`; route
handlers pull them via `Annotated[..., Depends(get_X)]`. Tests can override
these dependencies via `app.dependency_overrides[get_X] = lambda: fake`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any, Optional, Protocol, Union

import httpx
from fastapi import Depends, Request

from kitewrt.dataplane import DataPlane
from kitewrt.rules import parse_singbox_rules
from kitewrt.singbox.clash import ClashClient
from kitewrt.state import Data, State

# `Union`/`Optional`, not `X | Y`, in these module-level aliases: they're
# evaluated at runtime (not deferred by `from __future__ import annotations`),
# and the router runs python 3.9 where `type | type` raises.
RulesParser = Callable[[Union[bytes, str]], dict[str, list[dict[str, Any]]]]


class PipelineLike(Protocol):
    """Surface ApplyPipeline exposes to the API layer.

    Route handlers only need to nudge the pipeline; they don't care about
    its internal lifecycle. Protocol-typed so tests can pass any minimal
    stand-in that just records `signal()` calls.
    """

    def signal(self) -> None: ...


def get_state(request: Request) -> State:
    return request.app.state.kitewrt_state  # type: ignore[no-any-return]


def get_pipeline(request: Request) -> PipelineLike:
    return request.app.state.kitewrt_pipeline  # type: ignore[no-any-return]


def get_fetcher(request: Request) -> httpx.AsyncClient:
    return request.app.state.kitewrt_fetcher  # type: ignore[no-any-return]


def get_clash(request: Request) -> Optional[ClashClient]:  # noqa: UP045 — see below
    # `Optional[...]`, not `X | None`: FastAPI evaluates this dependency's
    # return annotation at runtime, which raises on python 3.9 for the `|`
    # form even under `from __future__ import annotations`.
    """The Clash API client, or None when no data plane is wired (test mode).

    Optional so the metrics route degrades to 'unavailable' rather than 500ing
    when the daemon isn't fully wired.
    """
    return getattr(request.app.state, "kitewrt_clash", None)


def get_rules_parser(request: Request) -> RulesParser:
    """The rules parser from the active data plane.

    Falls back to the sing-box parser when no data plane is wired (test mode).
    """
    dp = getattr(request.app.state, "kitewrt_dataplane", None)
    return dp.parse_rules if dp is not None else parse_singbox_rules


def get_dataplane(request: Request) -> Optional[DataPlane]:  # noqa: UP045 — runtime-eval'd, see get_clash
    """The active data plane, or None in pure test mode (no data plane wired).

    Auto-select uses it to materialize a subscription's outbounds before
    delay-testing; routes that get None simply skip that step.
    """
    return getattr(request.app.state, "kitewrt_dataplane", None)


StateDep = Annotated[State, Depends(get_state)]
PipelineDep = Annotated[PipelineLike, Depends(get_pipeline)]
FetcherDep = Annotated[httpx.AsyncClient, Depends(get_fetcher)]
RulesParserDep = Annotated[RulesParser, Depends(get_rules_parser)]
# Direct type ref (not a "ClashClient" forward-ref string): consumers like
# routes/metrics.py don't import ClashClient, so a string ref would fail to
# resolve when FastAPI evaluates the route's type hints (notably on 3.9).
ClashDep = Annotated[Optional[ClashClient], Depends(get_clash)]
DataPlaneDep = Annotated[Optional[DataPlane], Depends(get_dataplane)]


async def commit_and_signal(
    state: State,
    pipeline: PipelineLike,
    mutate: Callable[[Data], None],
    *,
    signal: bool | Callable[[Data], bool] = True,
) -> Data:
    """Apply `mutate` under the state lock, then nudge the apply pipeline.

    Centralises the update → (maybe) signal → return-snapshot boilerplate every
    mutating route shares. `signal` is either a bool or a predicate evaluated on
    the resulting snapshot — e.g. ``lambda d: d.vpn_on`` to signal only on a
    given condition. Returns the new snapshot.
    """
    snap = await state.update(mutate)
    do_signal = signal(snap) if callable(signal) else signal
    if do_signal:
        pipeline.signal()
    return snap
