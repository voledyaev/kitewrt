"""Keeps the proxy alive when state.vpn_on is true.

Runs as a background coroutine inside the daemon. Every `interval` it:

1. reads vpn_on; if false, sleeps one tick
2. checks if sing-box is healthy (process up AND Clash API responding); if
   so, sleeps one tick
3. else calls services.restart() — re-launches sing-box with the current
   config on disk; the tun + auto_route capture comes back up with it

Failure mode is important and fails closed in both phases:

* While sing-box is dead, strict_route leaves the captured traffic with no
  working tunnel, so it's dropped rather than leaked to the WAN. No leak.
* During the recovery restart itself, the tun drops and the auto_route rules
  briefly disappear; that gap would otherwise leak to the direct route.
  `services.restart()` brackets it with a fail-closed FORWARD DROP (see
  kitewrt.killswitch), so the window drops egress instead of leaking.

The watchdog does NOT go through the apply pipeline: a recovery restart
doesn't need to re-write the sing-box config, since the only thing that
changed is that sing-box went down. Direct `services.restart()` is faster
and avoids interfering with an in-flight apply.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol

logger = logging.getLogger(__name__)


class WatchdogDeps(Protocol):
    """Minimal surface the watchdog needs.

    Protocol-typed so the prod implementation (SingBoxWatchdogDeps in
    kitewrt.dataplane) and test fakes are both accepted.
    """

    def vpn_on(self) -> bool: ...
    def applying(self) -> bool: ...
    async def is_running(self) -> bool: ...
    async def restart(self) -> tuple[bool, str]: ...


class Watchdog:
    """Background process supervisor for sing-box.

    Construct with a WatchdogDeps implementation, start with `await start()`,
    stop with `await stop()`.
    """

    def __init__(
        self,
        deps: WatchdogDeps,
        *,
        interval_s: float = 30.0,
        backoff_max_s: float = 300.0,
    ):
        self._deps = deps
        self._interval = interval_s
        self._backoff_max = backoff_max_s
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # Consecutive "down" detections. We defer the restart until the second
        # one so a single transient blip — the Clash API still warming up right
        # after a (re)start, a one-off timeout — doesn't trigger a needless
        # restart that bounces the tun capture (churn that was itself dropping
        # traffic to 0 B during the day-long debug).
        self._down_streak = 0

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._loop(), name="kitewrt-watchdog")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def _loop(self) -> None:
        logger.info("watchdog started (interval=%ss)", self._interval)
        failures = 0
        try:
            while not self._stop_event.is_set():
                failures = await self._tick(failures)
                sleep_s = self._sleep_for(failures)
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=sleep_s)
                    break  # stop_event set
                except asyncio.TimeoutError:
                    pass  # normal tick interval elapsed
        finally:
            logger.info("watchdog exited")

    async def _tick(self, failures: int) -> int:
        """One supervision pass. Returns the updated failure counter."""
        try:
            # Defer if the apply pipeline currently owns the world. Without
            # this we have a race: tick reads vpn_on=True, then the user
            # toggles off, apply stops sing-box, and we'd then restart it
            # after the user said "off". Apply pipeline always
            # sets applying=True synchronously before its work and clears
            # it at the end, so checking here naturally serialises.
            if self._deps.applying():
                logger.debug("apply in flight; skipping tick")
                self._down_streak = 0  # an apply owns recovery; don't carry a stale down
                return failures
            if not self._deps.vpn_on():
                self._down_streak = 0  # nothing to watch; reset so it can't carry across on/off
                return 0
            if await self._deps.is_running():
                # Healthy: process up AND Clash API responding. The tun capture
                # is part of the process, so a live sing-box implies live
                # capture — nothing extra to assert.
                self._down_streak = 0
                return 0
            # Down — but debounce: defer the restart until a second consecutive
            # down, so a Clash-API warmup blip right after a (re)start doesn't
            # churn the process + tun.
            self._down_streak += 1
            if self._down_streak < 2:
                logger.info("sing-box looks down (streak 1); deferring restart one tick")
                return failures
            ok, msg = await self._deps.restart()
            if ok:
                logger.warning("sing-box was down; restart OK: %s", msg)
                return 0
            logger.error("sing-box was down; restart FAILED: %s", msg)
            return failures + 1
        except Exception:
            # Swallow exceptions from deps so a buggy dependency can't kill
            # the watchdog. Counter advances so backoff kicks in.
            logger.exception("watchdog tick errored")
            return failures + 1

    def _sleep_for(self, failures: int) -> float:
        """Exponential backoff when restarts keep failing, capped."""
        if failures == 0:
            return self._interval
        return min(self._interval * (2**failures), self._backoff_max)
