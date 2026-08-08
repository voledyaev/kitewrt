"""Keeps the proxy alive when state.vpn_on is true.

Runs as a background coroutine inside the daemon. Every `interval` it:

1. reads vpn_on; if false, sleeps one tick
2. checks if sing-box is healthy (process up AND Clash API responding); if
   so, sleeps one tick
3. else calls services.restart() — re-launches sing-box with the current
   config on disk; the capture stays installed across it

Failure mode is important and fails closed in both phases:

* While sing-box is dead, captured traffic reaches a TPROXY rule with nothing
  listening behind it, so the kernel drops it rather than letting it out the
  WAN. No leak.
* The recovery restart keeps the capture installed throughout, so that window
  is fail-closed for the same reason. (The kill-switch FORWARD DROP in
  kitewrt.killswitch now covers only the boot window, before any capture
  exists.)

The capture itself fails *open*: on fw3, `/etc/init.d/firewall restart` rebuilds
the mangle table and takes our chain with it, after which traffic goes direct
with nothing black-holed and nobody complaining. (Measured on fw4 it does not —
fw4 rebuilds only `table inet fw4` while our chain lives in `table ip mangle` —
so this trigger is much rarer there.) Re-asserting the capture every healthy
tick is what heals it, and step 3 below reports a failure to do so.

The watchdog does NOT go through the apply pipeline: a recovery restart
doesn't need to re-write the sing-box config, since the only thing that
changed is that sing-box went down. Direct `services.restart()` is faster
and avoids interfering with an in-flight apply.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Protocol

from kitewrt.state import now_iso

logger = logging.getLogger(__name__)

# Failed restarts to tolerate before un-capturing a LAN that the VPN is not
# even supposed to be protecting. Backoff makes this several minutes of real
# time, which is long enough that a transient failure won't trip it.
_GIVE_UP_AFTER = 3

# Consecutive ticks the watchdog will stand down for an in-flight apply before
# supervising anyway. At the 30 s interval that is five minutes — far longer
# than any real apply, and short enough that a stranded flag cannot silently
# retire the supervisor.
_MAX_DEFERRALS = 10


class WatchdogDeps(Protocol):
    """Minimal surface the watchdog needs.

    Protocol-typed so the prod implementation (SingBoxWatchdogDeps in
    kitewrt.dataplane) and test fakes are both accepted.
    """

    def vpn_on(self) -> bool: ...
    def applying(self) -> bool: ...
    async def is_running(self) -> bool: ...
    async def restart(self) -> tuple[bool, str]: ...

    async def resync_selector(self) -> bool | None: ...
    # The LAN capture. `ensure_capture` re-asserts it (idempotent, cheap when
    # already correct); `capture_installed` says whether it is live, which is
    # what decides if sing-box is worth supervising with the VPN off — a dead
    # listener behind a live capture black-holes every LAN TCP connection.
    async def ensure_capture(self) -> bool: ...
    # True / False / None, where None means "could not tell" (the xtables lock
    # was held past our wait). Callers that act destructively on a False must
    # check for None first.
    async def capture_installed(self) -> bool | None: ...
    # Does the process exist at all — weaker than `is_running`, which also
    # requires a healthy Clash API.
    async def process_alive(self) -> bool: ...
    async def remove_capture(self) -> None: ...
    async def report_capture_lost(self, since: str) -> bool: ...
    # A gap that the same tick already healed — recorded, but not as a fault.
    async def report_capture_gap(self, since: str) -> None: ...
    # Publish the observation above so the UI can distinguish "VPN on"
    # from "traffic is actually being captured".
    def record_capture_state(self, state: bool | None) -> None: ...
    async def report_capture_restored(self) -> None: ...
    # True/False if the active node passes/fails a real exit-path probe;
    # None when there's nothing to probe (vpn off / no active server) or the
    # probe couldn't run. Must not raise.
    async def active_reachable(self) -> bool | None: ...


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
        # restart. Under the tun that churn bounced the capture with it and
        # dropped traffic to 0 B during the day-long debug; the TPROXY capture
        # deliberately survives a restart, so the cost now is the restart
        # itself: every LAN connection dropped and re-dialled for nothing.
        self._down_streak = 0
        # Consecutive "up but not carrying traffic" detections. A node can be
        # process-healthy yet exit nowhere (dead server, blocked IP, stale
        # resolution) — the exact state that read "healthy" and silently ate
        # traffic during the DNS-bootstrap debug. Surface it (a WARNING), not
        # restart: a restart won't revive an unreachable server, and
        # auto-switching would override the user's deliberate node choice.
        self._unreachable_streak = 0
        # Whether we've already told the UI the capture is gone. Edge-triggered
        # so a persistent failure writes state (and flash) once, not every 30 s.
        self._capture_lost = False
        # Whether we've looked for a banner left behind by a previous process.
        # `last_error` outlives the daemon; `_capture_lost` does not.
        self._banner_checked = False
        # Whether this episode of "sing-box up, capture gone" has already had
        # its one repair attempt. That branch returns 0, which resets the
        # caller's failure counter, so it gets no backoff and no give-up —
        # without this latch a persistent failure recycles sing-box every tick,
        # forever.
        self._hybrid_recycled = False
        # Consecutive ticks stood down for an in-flight apply. See _MAX_DEFERRALS.
        self._deferred = 0

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._loop(), name="kitewrt-watchdog")

    async def stop(self, *, timeout: float | None = None) -> None:
        """Ask the loop to finish; with `timeout`, cancel it if it doesn't.

        A tick can sit 15s in `_wait_for_listener` and longer on a restart, so
        a graceful-only stop is unbounded — and on shutdown that is fatal:
        procd SIGKILLs at `term_timeout` and then stops sing-box, leaving the
        LAN behind a capture with no listener. The caller that has a deadline
        passes one.
        """
        self._stop_event.set()
        if self._task is None:
            return
        if timeout is not None:
            done, _pending = await asyncio.wait({self._task}, timeout=timeout)
            if not done:
                logger.warning("watchdog did not stop in %ss; cancelling", timeout)
                self._task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._task
        else:
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
        # Stamped before any awaiting: an apply can start AND finish inside the
        # ~15s `ensure_capture` spends waiting for the listener, and its result
        # is the one the user is looking at. Passed to report_capture_lost so
        # it declines to overwrite anything recorded after this instant.
        tick_started = now_iso()
        try:
            # Defer if the apply pipeline currently owns the world. Without
            # this we have a race: tick reads vpn_on=True, then the user
            # toggles off, apply stops sing-box, and we'd then restart it
            # after the user said "off". Apply pipeline always
            # sets applying=True synchronously before its work and clears
            # it at the end, so checking here naturally serialises.
            if self._deps.applying():
                self._deferred += 1
                if self._deferred <= _MAX_DEFERRALS:
                    logger.debug("apply in flight; skipping tick")
                    self._down_streak = 0  # an apply owns recovery; don't carry a stale down
                    return failures
                # Past the bound we stop deferring entirely until the flag
                # actually clears — we do NOT reset the counter and stand down
                # again. Alternating would be worse than useless: the deferral
                # path resets `_down_streak`, so a single deferred tick between
                # supervising ones means the two-tick debounce never completes
                # and sing-box is never restarted. (Caught by its own test.)
                #
                # Bounded at all because an unbounded defer is one flag that can
                # switch supervision off forever. Not hypothetical: a state
                # write failing on a full disk used to leave `applying=True`
                # with no apply queued to clear it, and the LAN then sat dark —
                # capture up, nothing listening — for as long as anyone watched,
                # with the dashboard green. `State.update` is all-or-nothing now
                # so that route is closed, but any future way of stranding the
                # flag would retire the watchdog just as completely.
                logger.error(
                    "apply has been in flight for %d ticks; supervising anyway", self._deferred
                )
            else:
                self._deferred = 0
            capture_up = await self._deps.capture_installed()
            self._deps.record_capture_state(capture_up)
            if capture_up:
                # A capture we can see ends the episode, so the next time one
                # goes missing gets its own single repair attempt.
                self._hybrid_recycled = False
            if not self._deps.vpn_on() and capture_up is not True:
                # "VPN off and no capture" is only idle if sing-box is *also*
                # down. With it up this is the black-hole hybrid: its
                # transparent UDP sockets stay bound to the LAN resolver
                # address from earlier tproxy sessions, so with the capture
                # gone they swallow client DNS that dnsmasq would have
                # answered. Our own shutdown creates exactly this pairing
                # (capture removed, procd-supervised sing-box left running),
                # and returning 0 here is what let it persist for hours with
                # the dashboard green.
                #
                # Restart, not just ensure_capture: re-asserting the capture
                # over those sockets was measured on a real kernel and does not
                # clear them (see the table in dataplane.apply). Only recycling
                # the process does.
                #
                # Three guards, because this branch `return 0`s — which resets
                # the caller's failure counter, so it gets neither backoff nor
                # the give-up path, and an unconditional restart here is an
                # unbounded 30 s loop:
                #   * `capture_up is False`, never None. None means the ruleset
                #     read failed (xtables lock held past `-w 5`), and a
                #     transient read error must not recycle the data plane.
                #   * `_hybrid_recycled` — one attempt per episode.
                #   * `failures == 0` — stay out of the way of the give-up path
                #     below, which deliberately un-captures a sing-box that is
                #     not coming back; re-installing would re-arm what it just
                #     disarmed.
                may_repair = capture_up is False and not self._hybrid_recycled and failures == 0
                # `process_alive`, not `is_running`: the latter also requires a
                # healthy Clash API, and a sing-box wedged badly enough to sit on
                # the LAN resolver port and answer nothing is exactly the one
                # whose API stops responding. Using it here skipped the branch in
                # the worst case it exists for.
                if may_repair and await self._deps.process_alive():
                    self._hybrid_recycled = True
                    logger.warning(
                        "sing-box is running with no LAN capture; restarting it "
                        "to clear the stale sockets that black-hole LAN DNS"
                    )
                    ok, msg = await self._deps.restart()
                    if not ok:
                        logger.error("restart to clear the LAN DNS black-hole failed: %s", msg)
                    elif not await self._deps.ensure_capture():
                        logger.error("LAN capture could not be restored after the restart")
                        ok = False
                    if not ok and not self._capture_lost:
                        # Surface it. Without this the only trace is a log line
                        # on a router nobody is tailing, which is how the
                        # original outage stayed invisible for hours.
                        self._capture_lost = await self._deps.report_capture_lost(tick_started)
                self._down_streak = 0  # nothing to watch; reset so it can't carry across on/off
                return 0
            if await self._deps.is_running():
                # Process up AND Clash API responding — but that's not the same
                # as "traffic is exiting". Probe the real exit path so a
                # dead-but-valid active node is surfaced instead of silently
                # persisting as "healthy".
                self._down_streak = 0
                if not self._deps.vpn_on():
                    # VPN off but the capture is up (that is why we got here):
                    # sing-box is alive and egressing direct, which is correct.
                    # Don't re-assert or probe reachability — there is no
                    # active node to probe. We are here purely to notice if
                    # sing-box dies, because a dead listener behind a live
                    # capture black-holes the LAN.
                    return 0
                # Re-assert the LAN capture. It is netfilter state, and unlike
                # the old policy-routing capture it does not survive everything:
                # on fw3, `/etc/init.d/firewall restart` rebuilds the whole
                # mangle table and takes our chain with it. (A plain `reload` —
                # the WAN-flap / DHCP-renew / Save&Apply path — leaves us alone,
                # and so does a restart on fw4, which rebuilds only `table inet
                # fw4`. Both measured.) That failure
                # is fail-*open*: traffic quietly goes direct with nothing
                # black-holed, so nobody complains and the VPN just stops
                # protecting anyone. Asserting here is what heals it.
                # Where the traffic goes, not just whether it is diverted.
                # Every other check here asks if packets reach sing-box; none
                # asked what sing-box then does with them, so a selector left on
                # `direct` with the VPN on was invisible indefinitely — measured
                # at 75 s across two ticks on a real router, with the dashboard
                # reading CAPTURED and `/api/exit-ip` showing the user's own ISP.
                # Cheap: one GET against a local API, and only when the VPN is
                # meant to be carrying traffic.
                if await self._deps.resync_selector():
                    logger.warning("sing-box was not routing through the tunnel; corrected")

                healed = await self._deps.ensure_capture()
                if not healed:
                    # Log, but do NOT count it as a failure: the backoff would
                    # stretch the tick towards its 300 s cap, and a capture
                    # problem (which fails open — traffic goes direct) would
                    # then also degrade detection of sing-box actually dying
                    # (which fails closed). Keep the cadence; keep retrying.
                    logger.error("LAN capture is missing and could not be restored")
                # Two reasons to raise the banner, and it must be raised at most
                # ONCE per tick or a dropped write is counted twice:
                #
                #  * the re-assert failed — the LAN is unproxied right now;
                #  * or it succeeded, but the capture was ALREADY gone when this
                #    tick began. That second case used to record nothing at all,
                #    which is the more insidious one: `/etc/init.d/firewall
                #    restart` (any UCI firewall edit, LuCI Save&Apply, some
                #    package installs) flushes mangle, and measured on a real
                #    kernel the LAN then egressed plaintext TCP *and* cleartext
                #    DNS for 4-21 s until this tick healed it — with
                #    `last_apply.ok` true and `last_error` empty the whole time.
                #    A browsing-history disclosure has to leave a mark even when
                #    it self-heals. The heal below clears it.
                if not healed and not self._capture_lost:
                    # Latch only if the write actually landed — a dropped one
                    # (a real apply in flight) must be retried next tick, not
                    # silently swallowed for the whole episode.
                    self._capture_lost = await self._deps.report_capture_lost(tick_started)
                elif healed and capture_up is False:
                    # Healed within this tick. One write, saying what actually
                    # happened; raising the "could not be restored" banner and
                    # clearing it again in the same tick spent two fsyncs to
                    # leave a message that was false.
                    await self._deps.report_capture_gap(tick_started)
                if healed and (self._capture_lost or not self._banner_checked):
                    # Healed. Clear the banner we raised — the watchdog's own
                    # recovery is not an apply, so nothing else ever would,
                    # and a self-healed `firewall restart` would otherwise
                    # leave a permanent red "traffic is NOT being proxied"
                    # over a fully working VPN.
                    #
                    # `_banner_checked` covers the restart case: the flag is
                    # in-memory but `last_error` is persisted, so a daemon that
                    # restarts while the banner is up would come back with the
                    # flag False and never clear it. Once, on the first healthy
                    # tick; the clear is a no-op unless the message is ours.
                    self._capture_lost = False
                    self._banner_checked = True
                    await self._deps.report_capture_restored()
                await self._check_reachable()
                return 0
            # Down — but debounce: defer the restart until a second consecutive
            # down, so a Clash-API warmup blip right after a (re)start doesn't
            # churn the process for nothing.
            self._down_streak += 1
            if self._down_streak < 2:
                logger.info("sing-box looks down (streak 1); deferring restart one tick")
                return failures
            ok, msg = await self._deps.restart()
            if ok:
                logger.warning("sing-box was down; restart OK: %s", msg)
                return 0
            if not self._deps.vpn_on() and failures + 1 >= _GIVE_UP_AFTER:
                # Give up and un-capture. sing-box is not coming back, and with
                # the VPN off the capture is holding the LAN hostage: TPROXY
                # with no listener black-holes every TCP connection (and the
                # DNS divert means dnsmasq never sees a query either), so the
                # LAN is fully dark. Worse, the toggle a user would reach for
                # is the one they already flipped — recovery would need SSH.
                #
                # Deliberately only when the VPN is off. With it on, dark is
                # the *intended* failure: dropping beats leaking real traffic
                # to the ISP. With it off the user asked for a plain router, so
                # falling back to one is what they wanted anyway.
                logger.error(
                    "sing-box has not recovered after %d attempts and the VPN is off; "
                    "removing the LAN capture so traffic flows unproxied",
                    failures + 1,
                )
                await self._deps.remove_capture()
            logger.error("sing-box was down; restart FAILED: %s", msg)
            return failures + 1
        except Exception:
            # Swallow exceptions from deps so a buggy dependency can't kill
            # the watchdog. Counter advances so backoff kicks in.
            logger.exception("watchdog tick errored")
            return failures + 1

    async def _check_reachable(self) -> None:
        """With sing-box process-healthy, probe whether the active node actually
        carries traffic and WARN (once) on a sustained failure.

        Detection only — deliberately no restart (won't revive an unreachable
        server) and no auto-switch (that would silently override the user's
        chosen node). Debounced one tick so a cold-handshake blip doesn't cry
        wolf. A probe error never touches the restart/backoff path.
        """
        try:
            reachable = await self._deps.active_reachable()
        except Exception:
            logger.debug("reachability probe errored", exc_info=True)
            return
        if reachable is None or reachable:
            self._unreachable_streak = 0
            return
        self._unreachable_streak += 1
        if self._unreachable_streak == 2:
            logger.warning(
                "active node is UP but UNREACHABLE — sing-box is healthy yet the exit "
                "probe fails, so traffic isn't leaving. Likely a dead/blocked server or "
                "stale server-domain resolution; switch nodes or check the server."
            )

    def _sleep_for(self, failures: int) -> float:
        """Exponential backoff when restarts keep failing, capped."""
        if failures == 0:
            return self._interval
        return min(self._interval * (2**failures), self._backoff_max)
