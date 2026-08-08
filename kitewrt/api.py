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
import contextlib
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
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from kitewrt import divert, killswitch
from kitewrt.apply import ApplyPipeline
from kitewrt.dataplane import SingBoxDataPlane, SingBoxWatchdogDeps
from kitewrt.deps import PipelineLike
from kitewrt.fetch import DEFAULT_TIMEOUT_S
from kitewrt.hub import Broadcaster
from kitewrt.metrics_store import MetricsStore
from kitewrt.proxied import ProxiedFetcher
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
from kitewrt.schemas import state_payload
from kitewrt.security import is_local_host
from kitewrt.singbox.clash import ClashClient, ClashError
from kitewrt.singbox.config import LOCAL_PROXY_URL, SELECTOR_TAG, selector_default
from kitewrt.singbox.service import SINGBOX_CONFIG, SingBoxService
from kitewrt.state import State, redact_state_dict
from kitewrt.subscriptions import refresh_all as refresh_all_subscriptions
from kitewrt.sysmetrics import SystemMetrics
from kitewrt.watchdog import Watchdog

logger = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"

# Per-step budget for the shutdown path. The init script asks procd for
# term_timeout=20, so bounding each step keeps a wedged worker from eating the
# whole allowance and starving the capture teardown, which is the step that
# matters.
#
# The two workers get 3 s; the teardown gets more, because 3 s was **shorter
# than a single call inside it**. `divert` runs `iptables -w 5`, so one
# contended call blocks 5.02 s and the whole bounded teardown timed out having
# done nothing — deterministically, under any contention past 3 s. Measured:
# `stop` returned rc=0 in under a second, the log said "teardown did not finish
# within 3.0s", and the capture was left complete — hook, 16 rules, INPUT
# accept, ip rule and table 2023 all present. procd then stops sing-box at
# STOP=10, and the LAN goes fully dark: TCP timeout, DNS timeout, ping 100%
# loss, because the chain's terminal DROP eats ICMP too. Nothing self-heals; it
# needs SSH.
#
# 12 s fits two contended calls with room, and still leaves 8 s of procd's 20 s
# for the workers above it and for procd's own SIGKILL fallback.
_STOP_BUDGET_S = 3.0
_TEARDOWN_BUDGET_S = 12.0


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
        # No Swagger UI. `/docs` was the one page in this daemon that loaded
        # third-party JavaScript — `swagger-ui-dist@5` from a CDN, on a floating
        # major tag with no SRI — into the daemon's own origin. Every guard here
        # (the Host check, the Origin check, the WebSocket's re-check) trusts
        # same-origin script absolutely, so a compromised release of that
        # package would have had full unauthenticated control of the router's
        # VPN. The real UI is entirely self-contained; this was not.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
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
    async def _redact_secrets(request: Request, call_next):
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
    async def _guard(request: Request, call_next):
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

    # Added LAST, so it is outermost and compresses on the way out — after
    # `_redact_secrets` has read and rewritten the JSON. Added first it would be
    # innermost, handing redaction an already-gzipped body to `json.loads`,
    # which fails silently and ships the response through unredacted.
    #
    # The SPA is served straight off `StaticFiles`, uncompressed: measured on
    # the wire from a LAN client, 242,425 B of JS and 79,082 B of CSS where
    # gzip -9 gives 73,682 and 13,477 — 323 KB shipped for 88 KB of content, to
    # clients that are usually on wifi. `minimum_size` keeps it off the small
    # JSON responses, where the router's CPU is worth more than the bytes.
    app.add_middleware(GZipMiddleware, minimum_size=1024)


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
    # GET *and* HEAD: FastAPI's router, unlike Starlette's, does not add HEAD
    # for you, so `curl -I http://router:8088/` fell through to the StaticFiles
    # mount below and 404'd while GET returned the page — a false alarm for any
    # uptime check that probes with HEAD.
    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
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

    class _HashedAssets(StaticFiles):
        """`StaticFiles`, plus the caching header the hashed bundles have
        earned.

        `index()` above already claimed "the hashed assets themselves stay
        cacheable" — and they were not. Measured on the wire: `/assets/*`
        returned `etag` and `last-modified` and **no `Cache-Control`**, so the
        browser fell back to heuristic freshness and revalidated on every
        reload. Vite content-hashes these filenames and the build deletes the
        old ones, so a given URL's bytes can never change: `immutable` is
        exactly true here, and it is the difference between a reload costing a
        round-trip per asset and costing nothing.

        Scoped to `/assets/` on purpose — everything else under the mount,
        `index.html` included, must keep revalidating or an upgrade leaves the
        browser pointing at asset names that no longer exist.
        """

        def file_response(self, *args, **kwargs):  # type: ignore[override]
            resp = super().file_response(*args, **kwargs)
            if resp.headers.get("content-type") and self._is_hashed(args):
                resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return resp

        @staticmethod
        def _is_hashed(args) -> bool:
            path = str(args[0]) if args else ""
            return "/assets/" in path.replace("\\", "/")

    # Mounted last so explicit routes above (and the catch-all 404 for
    # /api/*) take precedence; this only serves static files at non-/api
    # paths like /assets/* (the hashed Vite bundles) and index.html.
    app.mount("/", _HashedAssets(directory=STATIC_DIR), name="static")


# --- Production lifespan ---------------------------------------------------


async def _metrics_pump(
    hub: Broadcaster,
    state: State,
    clash: ClashClient,
    store: MetricsStore,
    system: SystemMetrics | None = None,
) -> None:
    """Push live metrics to WS clients ~1/s. Idle (and cheap) when VPN is
    off — but we still tick periodically to update the `available: false`
    cache so a newly-connected client sees an accurate state during the
    priming frame.

    The store computes throughput rates server-side from successive totals
    and keeps the last 30 samples of history, so a fresh WS client gets
    a populated sparkline + meaningful rate numbers on the first frame
    (no client-side warm-up needed)."""
    system = system or SystemMetrics()
    while True:
        sys_sample: dict | None = None
        try:
            await asyncio.sleep(1.0)
            # Sampled first and unconditionally: router CPU, WAN throughput and
            # temperature are just as real with the VPN off, and they are the
            # only numbers that still describe the *whole* link once
            # `bypass_address` takes traffic away from sing-box entirely.
            sys_sample = system.sample()
            snap = state.snapshot()
            if not snap.vpn_on:
                frame = store.mark_unavailable(sys_sample)
                if hub.has_clients:
                    hub.publish({"type": "metrics", "data": frame})
                continue
            conns = await clash.connections()
            now = await clash.current(SELECTOR_TAG)
            frame = store.update(build_metrics_summary(conns, now), system=sys_sample)
            if hub.has_clients:
                hub.publish({"type": "metrics", "data": frame})
        except asyncio.CancelledError:
            raise
        except ClashError:
            # Publish, don't merely cache. A client that is already connected
            # otherwise receives no frame at all and keeps rendering the last
            # live throughput and connection counts as though the tunnel were
            # healthy — only a page reload, which primes from `latest_frame()`,
            # revealed `available: false`. Measured: 3 s of Clash errors with
            # the VPN on delivered zero frames to a registered client.
            #
            # And reuse this tick's sample rather than taking a second one: a
            # fresh `system.sample()` here deltas over a sub-millisecond window,
            # which reported `cpu_percent 50.0` on an idle router against an
            # honest 1.99 — and that is the frame `/api/metrics` and every new
            # WS client are handed.
            frame = store.mark_unavailable(
                sys_sample if sys_sample is not None else system.sample()
            )
            if hub.has_clients:
                hub.publish({"type": "metrics", "data": frame})
            continue
        except Exception:
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
        except Exception:
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
    makes it reject the server cert as "not yet valid" → every proxied
    connection fails → the LAN is dark precisely when a user is power-cycling
    to "fix" things. Returns True once the clock is sane, False if it never synced within
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
    # TLS "not yet valid" cert rejection doesn't keep the LAN dark. Nothing is
    # captured yet during this wait (sweep() cleared any stale chain and we
    # haven't installed ours), so the kill switch below is what covers it —
    # this is the one window where it still earns its keep.
    await _await_clock_sane()
    target = selector_default(snap)
    # The one place the kill switch still earns its keep. Everywhere else it is
    # inert under TPROXY — captured packets are consumed in mangle/PREROUTING
    # and never reach FORWARD. But right here the capture may not exist yet:
    # procd starts sing-box and then us, and the divert only goes in once the
    # apply below runs. Until then the LAN is on the plain FORWARD path, which
    # is exactly what this DROP covers.
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
    # The daemon's own egress goes through sing-box's loopback HTTP proxy when
    # it's up, and direct when it isn't (fresh install: no subscription yet, so
    # no sing-box, so no proxy — see kitewrt.proxied).
    fetcher = ProxiedFetcher(
        httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_S, proxy=LOCAL_PROXY_URL),
        httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_S),
        proxy_url=LOCAL_PROXY_URL,
    )
    clash_http = httpx.AsyncClient(timeout=10.0)
    service = SingBoxService(capture_enabled=True)
    clash = ClashClient(clash_http, base_url=clash_url)
    data_plane = SingBoxDataPlane(service, clash, config_path=sb_config)
    hub = Broadcaster()
    metrics_store = MetricsStore()
    watchdog = Watchdog(
        SingBoxWatchdogDeps(state, service, clash, capture_sink=metrics_store.set_capture)
    )

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
    state.add_listener(lambda snap: hub.publish({"type": "state", "data": state_payload(snap)}))

    # Clear any kill-switch DROP left over from a hard kill (SIGKILL skips the
    # disengage `finally`) before anything else, so we never boot with egress
    # silently blocked.
    await killswitch.sweep()
    # Same idea for the LAN capture, but the failure mode is worse: divert
    # rules pointing at a port nothing listens on black-hole every LAN TCP
    # connection while ICMP keeps working. A daemon that was SIGKILL'd leaves
    # exactly that behind, so clear it before we (re)install a live one.
    await divert.sweep()

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
        # Every step here is BOUNDED, and that is the whole point. procd sends
        # SIGTERM and SIGKILLs us `term_timeout` seconds later (the init script
        # asks for 20; the stock default is 5). Anything we haven't finished by
        # then simply doesn't happen — and the one thing that must happen is
        # the capture teardown at the bottom. A graceful-only stop is unbounded:
        # a watchdog tick sits up to 15 s in `_wait_for_listener` and an
        # in-flight apply longer, which measured 13.6 s before `divert.remove()`
        # was even reached. The capture then survived the SIGKILL, sing-box
        # stopped after us, and the LAN went dark behind a listener-less
        # TPROXY rule — verbatim the failure this teardown exists to prevent.
        #
        # Deliberately three separate waits rather than one `wait_for` over a
        # gather of everything. Cancelling a gather cancels the *coroutines* in
        # it: `pipeline.stop()` would be cut off while sitting inside
        # `asyncio.wait({task})`, leaving the worker task alive and unawaited —
        # exactly the straggler the freeze latch below then has to catch — and
        # `boot_task` would take a *second* cancellation, this time inside
        # `killswitch.disengage`, stranding a FORWARD DROP.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(
                asyncio.gather(
                    pipeline.stop(timeout=_STOP_BUDGET_S),
                    watchdog.stop(timeout=_STOP_BUDGET_S),
                    return_exceptions=True,
                ),
                timeout=_STOP_BUDGET_S * 2,
            )
        # `asyncio.wait` on the TASKS: it neither raises nor cancels on
        # timeout, so a `boot_task` still unwinding its kill-switch bracket is
        # left to finish rather than interrupted mid-`disengage`. A DROP
        # stranded past this budget is cleared by the next start's
        # `killswitch.sweep()`.
        await asyncio.wait({metrics_task, refresh_task, boot_task}, timeout=_STOP_BUDGET_S)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(
                asyncio.gather(fetcher.aclose(), clash_http.aclose(), return_exceptions=True),
                timeout=_STOP_BUDGET_S,
            )
        # Take the LAN capture down last, once nothing can reinstall it: procd
        # stops us before sing-box, so leaving it up hands the LAN a divert
        # whose listener is about to vanish, with nothing running that could
        # notice. Harmless on a reboot (netfilter goes with it), but
        # `/etc/init.d/kitewrt stop` or an opkg upgrade would black-hole the
        # LAN until someone intervened.
        #
        # Forcing past the lock is safe *here* and nowhere else, because the
        # bounded stops above cancelled the only tasks that could still be
        # installing — and `divert.remove(force_after_s=…)` raises the one-way
        # `_frozen` latch, which `_install_locked` re-checks immediately before
        # it hooks PREROUTING, so a straggler cannot re-hook behind us. (It was
        # a generation counter once; the latch replaced it because a counter can
        # only say "a teardown happened during *my* run", which depends on where
        # the straggler sampled it.)
        if not await divert.remove(force_after_s=_TEARDOWN_BUDGET_S):
            # Nothing left to sweep it: procd stops sing-box right after us, so
            # a surviving hook means a black-holed LAN with no daemon running.
            # The next start's sweep() fixes it — but only if there is one.
            logger.error(
                "the LAN capture could not be fully removed on shutdown; "
                "run `/etc/init.d/kitewrt start` or clear the kitewrt_tproxy chain by hand"
            )
