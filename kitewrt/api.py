"""FastAPI app factory + lifespan for the kitewrt daemon.

Two construction modes share `create_app()`:

* **Production**: call `create_app()` with no deps. The default `lifespan`
  reads env vars and builds State / ApplyPipeline / Watchdog / the sing-box
  service + Clash client / httpx fetcher on startup; tears them down on shutdown.
  Uvicorn drives the lifespan via SIGINT/SIGTERM, so `__main__.py` can be
  a five-line entry point.

* **Tests**: pass pre-built deps directly. No lifespan runs; tests retain
  full control over wiring and shutdown.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from kitewrt import killswitch
from kitewrt.apply import ApplyPipeline
from kitewrt.dataplane import SingBoxDataPlane, SingBoxWatchdogDeps
from kitewrt.deps import PipelineLike
from kitewrt.fetch import DEFAULT_TIMEOUT_S
from kitewrt.hub import Broadcaster
from kitewrt.metrics_store import MetricsStore
from kitewrt.routes import (
    connectivity,
    dns,
    exit_ip,
    meta,
    metrics,
    rules,
    server,
    subscriptions,
    vpn,
    ws,
)
from kitewrt.routes.metrics import build_metrics_summary
from kitewrt.security import is_local_host
from kitewrt.singbox.clash import ClashClient, ClashError
from kitewrt.singbox.config import SELECTOR_TAG, selector_default
from kitewrt.singbox.service import SINGBOX_CONFIG, SingBoxService
from kitewrt.state import State, redact_state_dict, redacted_state_dict
from kitewrt.subscriptions import refresh_all as refresh_all_subscriptions
from kitewrt.watchdog import Watchdog

logger = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    state: State | None = None,
    pipeline: PipelineLike | None = None,
    fetcher: httpx.AsyncClient | None = None,
    *,
    data_plane: object | None = None,
) -> FastAPI:
    """Build the FastAPI app.

    If all three deps are passed, the app skips the lifespan and uses the
    given objects as-is (test mode). If any dep is `None`, the production
    `_lifespan` runs at startup to read env vars and build the missing deps.
    `data_plane` is optional in test mode (the rules route falls back to the
    sing-box parser when it's absent).
    """
    test_mode = state is not None and pipeline is not None and fetcher is not None
    app = FastAPI(
        title="kitewrt",
        default_response_class=JSONResponse,
        lifespan=None if test_mode else _lifespan,
    )

    if test_mode:
        app.state.kitewrt_state = state
        app.state.kitewrt_pipeline = pipeline
        app.state.kitewrt_fetcher = fetcher
        if data_plane is not None:
            app.state.kitewrt_dataplane = data_plane

    _register_middleware(app)
    _register_exception_handlers(app)
    _include_routers(app)
    _register_static(app)
    return app


# --- Security + redaction middleware ---------------------------------------

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _register_middleware(app: FastAPI) -> None:
    # Added inner-first: the guard (added last) runs outermost, so it rejects a
    # bad request before the route; redaction (added first) wraps the response.
    @app.middleware("http")
    async def _redact_secrets(request: Request, call_next):  # noqa: ANN202
        """Strip per-server secrets (VLESS UUIDs / passwords / Reality keys) from
        every /api JSON response, so neither a cross-origin reader nor a LAN
        snooper (curl, bypassing CORS) can harvest the subscription credentials."""
        response = await call_next(request)
        ctype = response.headers.get("content-type", "")
        if not (request.url.path.startswith("/api/") and ctype.startswith("application/json")):
            return response
        body = b"".join([section async for section in response.body_iterator])
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("subscriptions"), list):
            body = json.dumps(redact_state_dict(data)).encode()
        headers = {
            k: v
            for k, v in response.headers.items()
            if k.lower() not in ("content-length", "content-type")
        }
        return Response(
            content=body,
            status_code=response.status_code,
            headers=headers,
            media_type="application/json",
        )

    @app.middleware("http")
    async def _guard(request: Request, call_next):  # noqa: ANN202
        """Rebinding + CSRF defense for the unauthenticated LAN API: reject a
        non-local Host header, and reject cross-origin mutating requests."""
        host = request.headers.get("host", "")
        if not is_local_host(host):
            return JSONResponse(status_code=403, content={"error": "host not allowed"})
        if request.method in _MUTATING:
            origin = request.headers.get("origin")
            if origin is not None and urlparse(origin).netloc != host:
                return JSONResponse(status_code=403, content={"error": "cross-origin blocked"})
        return await call_next(request)


def _include_routers(app: FastAPI) -> None:
    # Specific routers first; catch-all 404 last so it only matches what
    # nothing else picked up.
    for module in (
        subscriptions,
        server,
        vpn,
        dns,
        rules,
        metrics,
        exit_ip,
        connectivity,
        ws,
        meta,
    ):
        app.include_router(module.router)
    app.include_router(meta.catch_all_router)


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _validation_to_400(_req: Request, exc: RequestValidationError) -> JSONResponse:
        # Go returned 400 for body/field validation errors; FastAPI defaults
        # to 422. Surface a single human-readable message so the UI shows
        # something useful instead of FastAPI's verbose error list.
        msg = exc.errors()[0].get("msg", "invalid request") if exc.errors() else "invalid request"
        if msg.startswith("Value error, "):
            msg = msg[len("Value error, ") :]
        return JSONResponse(status_code=400, content={"error": msg})

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_as_error(_req: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Normalise to `{"error": msg}` (Go API shape). Covers both our
        # raised HTTPExceptions and Starlette's auto-raised ones (405 for
        # wrong method, etc).
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail or "error"},
        )


def _register_static(app: FastAPI) -> None:
    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        # `no-cache` = revalidate before use. The built index.html references
        # content-hashed asset filenames that change every build (the build
        # wipes old ones), so a stale cached index.html would point at assets
        # that 404 after an upgrade. Forcing revalidation avoids a broken UI
        # post-upgrade; the hashed assets themselves stay cacheable.
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        # The page sets an inline SVG icon; answer the browser's default probe
        # so it doesn't log a 404.
        return Response(status_code=204)

    # Mounted last so explicit routes above (and the catch-all 404 for
    # /api/*) take precedence; this only serves static files at non-/api
    # paths like /assets/* (the hashed Vite bundles) and index.html.
    app.mount("/", StaticFiles(directory=STATIC_DIR), name="static")


# --- Production lifespan ---------------------------------------------------


async def _metrics_pump(
    hub: Broadcaster, state: State, clash: ClashClient, store: MetricsStore
) -> None:
    """Push live metrics to WS clients ~1/s. Idle (and cheap) when VPN is
    off — but we still tick periodically to update the `available: false`
    cache so a newly-connected client sees an accurate state during the
    priming frame.

    The store computes throughput rates server-side from successive totals
    and keeps the last 30 samples of history, so a fresh WS client gets
    a populated sparkline + meaningful rate numbers on the first frame
    (no client-side warm-up needed)."""
    while True:
        try:
            await asyncio.sleep(1.0)
            snap = state.snapshot()
            if not snap.vpn_on:
                # Mark unavailable in the cache so a new WS client sees the
                # right state on connect. Don't bother publishing — there's
                # nothing observable changing, and active clients have
                # already been told VPN is off through the `state` channel.
                store.mark_unavailable()
                continue
            conns = await clash.connections()
            now = await clash.current(SELECTOR_TAG)
            frame = store.update(build_metrics_summary(conns, now))
            if hub.has_clients:
                hub.publish({"type": "metrics", "data": frame})
        except asyncio.CancelledError:
            raise
        except ClashError:
            store.mark_unavailable()
            continue
        except Exception:  # noqa: BLE001 — a metrics hiccup must not kill the pump
            # warning, not debug: a router misbehaving in the field is debugged
            # over SSH from logread, and INFO is the default level there.
            logger.warning("metrics pump tick failed", exc_info=True)


# Subscriptions change rarely (a provider rotates servers occasionally), so a
# slow cadence keeps them fresh for "set and forget" without hammering the
# source. First tick is delayed a full interval — startup already has whatever
# was persisted, and we don't want a refresh storm on every daemon restart.
SUBSCRIPTION_REFRESH_INTERVAL_S = 6 * 3600


async def _subscription_refresh_pump(
    state: State, fetcher: httpx.AsyncClient, pipeline: PipelineLike, interval_s: float
) -> None:
    """Periodically re-fetch every subscription so rotated servers appear
    without the user clicking *Refresh*. Best-effort: kitewrt.subscriptions
    .refresh_all logs and skips a failed source, and the loop survives any
    unexpected error so a single bad tick never kills auto-refresh."""
    while True:
        try:
            await asyncio.sleep(interval_s)
            await refresh_all_subscriptions(state, fetcher, pipeline)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — a refresh hiccup must not kill the pump
            logger.warning("subscription refresh tick failed", exc_info=True)


# Below this year the system clock is almost certainly unset (pre-NTP). It sits
# above any plausible OpenWrt 21.02 firmware build date (2021-2023) and below
# now, so a post-power-loss clock that started at the build date or the epoch
# reads as stale. See _await_clock_sane.
_CLOCK_MIN_YEAR = 2024


async def _await_clock_sane(
    *, min_year: int = _CLOCK_MIN_YEAR, attempts: int = 60, delay: float = 1.0
) -> bool:
    """Block (bounded) until the system clock looks NTP-synced.

    Consumer routers have no RTC; after a power-loss reboot (the #1 home
    "reboot") the clock starts at the firmware build date or the epoch, and
    sysntpd corrects it a few seconds later. Bringing a TLS-validating proxy
    (hysteria2 / tuic / trojan, and Reality's timestamp window) up before then
    makes it reject the server cert as "not yet valid" → strict_route drops
    everything → the LAN is dark precisely when a user is power-cycling to "fix"
    things. Returns True once the clock is sane, False if it never synced within
    the budget (we then proceed anyway rather than stay dark forever). Returns
    immediately when the clock is already sane (the steady-state restart case)."""
    for _ in range(attempts):
        if datetime.now(timezone.utc).year >= min_year:
            return True
        await asyncio.sleep(delay)
    logger.warning(
        "system clock still looks unset (year < %d) after waiting; proceeding anyway", min_year
    )
    return False


async def _boot_reconcile(state: State, clash: ClashClient, pipeline: PipelineLike) -> None:
    """First reconcile after (re)start. procd brings sing-box up — restoring its
    cached selector — before the daemon runs, so if `vpn_on` persisted we bracket
    the reconcile with the kill switch and lift it only once the selector is
    confirmed on target. Closes the boot window where a stale cache-restored
    `direct` could route live LAN traffic. In the common case (cache already on
    target) the very first check confirms and the guard lifts immediately."""
    snap = state.snapshot()
    if not snap.vpn_on:
        pipeline.signal()
        return
    # Wait out an unsynced post-reboot clock before standing the proxy up, so a
    # TLS "not yet valid" cert rejection doesn't keep the LAN dark. sing-box is
    # already fail-closed (strict_route) during the wait, so we lose nothing.
    await _await_clock_sane()
    target = selector_default(snap)
    wan = await killswitch.detect_wan()
    engaged = await killswitch.engage(wan) if wan else False
    try:
        pipeline.signal()
        for _ in range(16):  # ~8s; reload inside nests safely (refcounted)
            try:
                if await clash.current(SELECTOR_TAG) == target:
                    return
            except ClashError:
                pass
            await asyncio.sleep(0.5)
    finally:
        if engaged:
            await killswitch.disengage(wan)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Wire deps from env on startup; tear down on shutdown."""
    base_dir = os.environ.get("KITEWRT_BASE_DIR")
    if not base_dir:
        raise RuntimeError("KITEWRT_BASE_DIR is not set; refusing to guess where to put state.json")
    sb_config = os.environ.get("KITEWRT_SINGBOX_CONFIG") or SINGBOX_CONFIG
    clash_url = os.environ.get("KITEWRT_CLASH_API") or "http://127.0.0.1:9090"

    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    state_path = base / "state.json"
    logger.info("state path: %s", state_path)
    logger.info("sing-box config: %s; clash api: %s", sb_config, clash_url)

    state = State(state_path)
    fetcher = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_S)
    clash_http = httpx.AsyncClient(timeout=10.0)
    service = SingBoxService(killswitch_enabled=True)
    clash = ClashClient(clash_http, base_url=clash_url)
    data_plane = SingBoxDataPlane(service, clash, config_path=sb_config)
    watchdog = Watchdog(SingBoxWatchdogDeps(state, service, clash))
    hub = Broadcaster()
    metrics_store = MetricsStore()

    pipeline = ApplyPipeline(state, data_plane)

    app.state.kitewrt_state = state
    app.state.kitewrt_pipeline = pipeline
    app.state.kitewrt_fetcher = fetcher
    app.state.kitewrt_dataplane = data_plane
    app.state.kitewrt_clash = clash  # for the /api/metrics route
    app.state.kitewrt_hub = hub  # for the /ws push channel
    app.state.kitewrt_metrics_store = metrics_store  # for /ws priming

    # Push every state change to WS clients so the UI reflects toggle / server
    # switches instantly, without polling. Redacted — the WS bypasses CORS, so a
    # cross-origin page could otherwise read raw credentials off the broadcast.
    state.add_listener(
        lambda snap: hub.publish({"type": "state", "data": redacted_state_dict(snap)})
    )

    # Clear any kill-switch DROP left over from a hard kill (SIGKILL skips the
    # disengage `finally`) before anything else, so we never boot with egress
    # silently blocked.
    await killswitch.sweep()

    await pipeline.start()
    await watchdog.start()
    metrics_task = asyncio.create_task(
        _metrics_pump(hub, state, clash, metrics_store), name="kitewrt-metrics-pump"
    )
    refresh_task = asyncio.create_task(
        _subscription_refresh_pump(state, fetcher, pipeline, SUBSCRIPTION_REFRESH_INTERVAL_S),
        name="kitewrt-subscription-refresh",
    )
    # Reconcile the data plane with whatever vpn_on persisted from the last
    # run — a daemon restart never leaves the proxy out of sync. Bracketed
    # fail-closed when vpn_on, so the boot window (procd started sing-box with a
    # cache-restored selector before we got here) can't leak via a stale value.
    # Runs as a background task: it may wait out an unsynced post-reboot clock,
    # and the UI must come up immediately regardless. The kill-switch bracket it
    # holds keeps egress fail-closed for the duration.
    boot_task = asyncio.create_task(
        _boot_reconcile(state, clash, pipeline), name="kitewrt-boot-reconcile"
    )

    try:
        yield
    finally:
        logger.info("shutting down background tasks")
        metrics_task.cancel()
        refresh_task.cancel()
        boot_task.cancel()  # may still be waiting on the clock / holding the bracket
        # Best-effort: gather all teardowns so a failure in one doesn't
        # leak the others.
        await asyncio.gather(
            pipeline.stop(),
            watchdog.stop(),
            metrics_task,
            refresh_task,
            boot_task,
            fetcher.aclose(),
            clash_http.aclose(),
            return_exceptions=True,
        )
