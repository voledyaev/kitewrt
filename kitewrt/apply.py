"""Single-worker apply pipeline.

One coroutine consumes apply signals and runs the active data plane's `apply`.
The pipeline owns the *machinery* (signal coalescing, the applying flag,
recording the result); the injected `DataPlane` owns *how* an apply happens
(sing-box reload for structural changes vs. live Clash switch for a plain
server selection). See `kitewrt.dataplane`.

Handlers do not call apply steps directly. They mutate state + call
`pipeline.signal()`, which is non-blocking. Multiple rapid clicks coalesce
into one extra worker iteration (the worker re-reads `state.snapshot()` on
each pass, so the final intent always wins).

`data.applying` is the UI-visible "we're churning" flag. Handlers set it to
True *before* responding to the user (so the very next poll shows it true); the
worker also sets it at the start of every iteration (guarded, so a persist error
can't kill the worker) and, when a signal is already queued, keeps it True after
the iteration (`still_pending` in `_record_result`) instead of clearing it. So
the flag stays continuously on across coalesced applies — the watchdog keeps
deferring — without relying on a handler to re-set it; it drops to False only
when no further pass is queued.
"""

from __future__ import annotations

import asyncio
import logging

from kitewrt.dataplane import DataPlane
from kitewrt.state import ApplyResult, Data, State, now_iso

logger = logging.getLogger(__name__)


class ApplyPipeline:
    """Owns the apply worker coroutine and its signaling Event.

    Construct once at daemon startup with a `DataPlane`, call `await start()`
    to spawn the worker, and `await stop()` for shutdown. Handlers call
    `signal()` (sync, never blocks) to request an apply.
    """

    def __init__(self, state: State, data_plane: DataPlane):
        self._state = state
        self._data_plane = data_plane
        self._signal_event = asyncio.Event()
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._loop(), name="kitewrt-apply-loop")

    async def stop(self) -> None:
        self._stop_event.set()
        self._signal_event.set()  # wake the loop so it observes stop_event
        if self._task is not None:
            await self._task
            self._task = None

    def signal(self) -> None:
        """Non-blocking request for an apply. Coalesces with pending signals."""
        self._signal_event.set()

    async def _loop(self) -> None:
        logger.info("apply loop started")
        try:
            while not self._stop_event.is_set():
                await self._signal_event.wait()
                # Clear BEFORE doing work, so any signal arriving during the
                # iteration triggers another pass — same coalescing semantics
                # as Go's buffered-1 channel.
                self._signal_event.clear()
                if self._stop_event.is_set():
                    break
                # Mark applying for the whole iteration. The watchdog defers its
                # own recovery restart while applying() is true (so it can't run
                # service.restart() concurrently with our reload — that
                # concurrency is exactly what the killswitch refcount has to
                # survive). A handler-triggered apply already set this, but a
                # coalesced 2nd pass or a non-handler trigger might not have —
                # so set it unconditionally here, at the start of the work.
                # Guarded: this persists state (durable write), which can raise
                # OSError on a full overlay; that must NOT kill the worker (it
                # would strand applying=True forever and the watchdog would defer
                # recovery permanently). Failing to flag applying just means the
                # watchdog isn't deferred for this pass — the apply still runs.
                try:
                    await self._set_applying(True)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("failed to set applying flag")
                # An apply that raises must NOT kill the worker or strand the
                # `applying` flag at True: record it as a failure and keep
                # serving signals. Previously an unexpected exception here let
                # the loop exit, leaving the UI stuck on "applying…" forever and
                # every later signal a no-op until a daemon restart.
                try:
                    ok, msg = await self._apply_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 — last-resort guard
                    logger.exception("apply failed")
                    ok, msg = False, f"apply crashed: {exc}"
                try:
                    await self._record_result(ok, msg)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("failed to record apply result")
        except asyncio.CancelledError:
            raise
        finally:
            logger.info("apply loop exited")

    async def _apply_once(self) -> tuple[bool, str]:
        return await self._data_plane.apply(self._state.snapshot())

    async def _set_applying(self, value: bool) -> None:
        await self._state.update(lambda d: setattr(d, "applying", value))

    async def _record_result(self, ok: bool, msg: str) -> None:
        result = ApplyResult(at=now_iso(), ok=ok, msg=msg)
        # Keep applying=True if another pass is already queued, so the flag
        # stays continuously on across coalesced applies (and the watchdog keeps
        # deferring). It drops to False only when this was the last pending pass.
        # On shutdown the signal is set just to wake the loop, not for real work,
        # so don't strand applying=True there.
        still_pending = self._signal_event.is_set() and not self._stop_event.is_set()

        def mutate(d: Data) -> None:
            d.applying = still_pending
            d.last_apply = result
            d.last_error = "" if ok else msg

        await self._state.update(mutate)
        logger.info("apply: ok=%s msg=%r", ok, msg)
