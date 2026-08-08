from __future__ import annotations

import asyncio

import pytest
from kitewrt.watchdog import Watchdog


class FakeDeps:
    """Scriptable WatchdogDeps implementation."""

    def __init__(self):
        self._vpn_on = True
        self._applying = False
        self._is_running = True
        self._process_alive: bool | None = None  # None → mirror _is_running
        self._active_reachable: bool | None = None
        self.restart_results: list[tuple[bool, str]] = []  # popped per call
        self.restart_calls = 0
        self.resync_calls = 0
        self.resync_result: bool | None = False
        self.is_running_raises: Exception | None = None
        self.restart_raises: Exception | None = None
        self.active_reachable_raises: Exception | None = None
        # LAN capture: netfilter state the watchdog re-asserts each healthy
        # tick, because `firewall restart` flushes the mangle table it lives in.
        self.capture_result = True
        self.capture_calls = 0
        self._capture_installed = False
        self.capture_removals = 0
        self.capture_lost_reports = 0
        self.capture_gap_reports = 0
        self.recorded_capture: list = []
        self.capture_restored_reports = 0
        # Whether the state write lands. False models a real apply having
        # recorded its own result during the tick, which drops ours.
        self.capture_lost_write_lands = True

    async def report_capture_lost(self, since: str) -> bool:
        assert since, "the tick timestamp guards against clobbering a real apply result"
        self.capture_lost_reports += 1
        return self.capture_lost_write_lands

    async def report_capture_gap(self, since: str) -> None:
        assert since, "the tick timestamp guards against clobbering a real apply result"
        self.capture_gap_reports += 1

    async def report_capture_restored(self) -> None:
        self.capture_restored_reports += 1

    async def remove_capture(self) -> None:
        self.capture_removals += 1
        self._capture_installed = False

    async def ensure_capture(self) -> bool:
        self.capture_calls += 1
        # Mirror the real service: a successful assert leaves the capture
        # installed, so the *next* tick reads it as present. Without this the
        # fake reports "capture missing" forever and hides ticks that should be
        # quiet.
        if self.capture_result:
            self._capture_installed = True
        return self.capture_result

    def record_capture_state(self, state: bool | None) -> None:
        self.recorded_capture.append(state)

    async def capture_installed(self) -> bool | None:
        # None models "could not tell" (xtables lock held) — must never be
        # treated as "no capture" by anything that acts destructively.
        return self._capture_installed

    async def process_alive(self) -> bool:
        # Weaker than is_running(): the process exists, the Clash API need not
        # answer. Defaults to tracking _is_running so existing tests are
        # unaffected; set explicitly to model a wedged sing-box.
        return self._is_running if self._process_alive is None else self._process_alive

    def vpn_on(self) -> bool:
        return self._vpn_on

    def applying(self) -> bool:
        return self._applying

    async def is_running(self) -> bool:
        if self.is_running_raises:
            raise self.is_running_raises
        return self._is_running

    async def resync_selector(self) -> bool | None:
        """Whether sing-box's selector had to be dragged back to the intent.

        Defaults to False (it already agreed), so every existing test keeps
        describing a router that routes where it says it does.
        """
        self.resync_calls += 1
        return self.resync_result

    async def restart(self) -> tuple[bool, str]:
        self.restart_calls += 1
        if self.restart_raises:
            raise self.restart_raises
        return self.restart_results.pop(0) if self.restart_results else (True, "")

    async def active_reachable(self) -> bool | None:
        if self.active_reachable_raises:
            raise self.active_reachable_raises
        return self._active_reachable


# --- _tick state machine ----------------------------------------------------


async def test_tick_noop_when_vpn_off():
    deps = FakeDeps()
    deps._vpn_on = False
    deps._is_running = False  # genuinely idle; see the hybrid test below
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    assert deps.restart_calls == 0


async def test_tick_noop_when_singbox_running():
    deps = FakeDeps()
    deps._vpn_on = True
    deps._is_running = True
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    assert deps.restart_calls == 0


async def test_tick_defers_then_restarts_when_dead():
    # Debounce: the first down tick defers (no restart); the second restarts.
    deps = FakeDeps()
    deps._vpn_on = True
    deps._is_running = False
    deps.restart_results = [(True, "")]
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0  # first down → deferred
    assert deps.restart_calls == 0
    assert await wd._tick(0) == 0  # second down → restart
    assert deps.restart_calls == 1


async def test_tick_increments_failures_on_restart_error():
    deps = FakeDeps()
    deps._vpn_on = True
    deps._is_running = False
    deps.restart_results = [(False, "boom")]
    wd = Watchdog(deps)
    assert await wd._tick(2) == 2  # first down → deferred (counter untouched)
    assert await wd._tick(2) == 3  # second down → restart fails → counter++


async def test_tick_resets_failures_on_restart_success():
    deps = FakeDeps()
    deps._vpn_on = True
    deps._is_running = False
    deps.restart_results = [(True, "")]
    wd = Watchdog(deps)
    # Carried 5 prior failures; debounced restart success clears them.
    assert await wd._tick(5) == 5  # deferred
    assert await wd._tick(5) == 0  # restart success


async def test_tick_recovery_resets_down_streak():
    # A healthy tick between downs resets the debounce, so the streak must be
    # consecutive — a flapping check doesn't accumulate toward a restart.
    deps = FakeDeps()
    deps._vpn_on = True
    deps._is_running = False
    wd = Watchdog(deps)
    await wd._tick(0)  # down (streak 1)
    deps._is_running = True
    await wd._tick(0)  # healthy → streak reset
    deps._is_running = False
    deps.restart_results = [(True, "")]
    await wd._tick(0)  # down again (streak 1) → deferred, no restart
    assert deps.restart_calls == 0


async def test_tick_defers_when_apply_in_flight():
    # The race we discovered in the live-install end-to-end: user toggles
    # off, apply pipeline stops sing-box, watchdog tick reads vpn_on=True
    # (decision made before user's flip propagated) and restarts it.
    # Fixed by deferring while applying=True.
    deps = FakeDeps()
    deps._vpn_on = True
    deps._applying = True
    deps._is_running = False  # sing-box died mid-apply, looks like recovery
    wd = Watchdog(deps)
    # Carry a non-zero failure counter to verify we don't reset it on defer.
    assert await wd._tick(2) == 2
    assert deps.restart_calls == 0


async def test_deferring_to_an_apply_is_bounded():
    """An unbounded defer is one flag that switches supervision off forever."""
    deps = FakeDeps()
    deps._vpn_on = True
    deps._applying = True  # and never clears
    deps._is_running = False  # sing-box is down and nobody else will notice
    deps.restart_results = [(True, "")] * 5
    wd = Watchdog(deps)

    for _ in range(10):
        await wd._tick(0)
    assert deps.restart_calls == 0  # stood down, as designed

    await wd._tick(0)  # the 11th: supervise anyway
    await wd._tick(0)  # (one more for the down-streak debounce)
    assert deps.restart_calls == 1


async def test_tick_resumes_after_apply_completes():
    # Counterpart of the defer test: once applying flips back to False,
    # the next tick proceeds normally.
    deps = FakeDeps()
    deps._vpn_on = True
    deps._applying = True
    deps._is_running = False
    wd = Watchdog(deps)
    await wd._tick(0)  # deferred (applying)
    assert deps.restart_calls == 0
    deps._applying = False
    deps.restart_results = [(True, "")]
    await wd._tick(0)  # first non-applying down → debounce defer
    assert await wd._tick(0) == 0  # second down → restart
    assert deps.restart_calls == 1


async def test_tick_survives_dep_exception():
    deps = FakeDeps()
    deps.is_running_raises = RuntimeError("dep buggy")
    wd = Watchdog(deps)
    assert await wd._tick(1) == 2  # counter advances; no propagation


# --- Reachability probe (dead-but-process-healthy node) ---------------------


async def test_reachable_ok_no_warning(caplog):
    deps = FakeDeps()
    deps._is_running = True
    deps._active_reachable = True
    wd = Watchdog(deps)
    with caplog.at_level("WARNING"):
        await wd._tick(0)
    assert wd._unreachable_streak == 0
    assert deps.restart_calls == 0
    assert not any("UNREACHABLE" in r.getMessage() for r in caplog.records)


async def test_unreachable_warns_on_second_consecutive(caplog):
    # First miss debounces (transient cold-handshake blip); the second warns.
    deps = FakeDeps()
    deps._is_running = True
    deps._active_reachable = False
    wd = Watchdog(deps)
    with caplog.at_level("WARNING"):
        await wd._tick(0)
        assert wd._unreachable_streak == 1
        assert not any("UNREACHABLE" in r.getMessage() for r in caplog.records)
        await wd._tick(0)
    assert wd._unreachable_streak == 2
    assert any("UNREACHABLE" in r.getMessage() for r in caplog.records)
    # Detection only: unreachability never triggers a restart or a node switch.
    assert deps.restart_calls == 0


async def test_unreachable_none_is_not_a_miss(caplog):
    # None = "can't tell" (vpn off / no active server / probe error): must not
    # accumulate toward a warning.
    deps = FakeDeps()
    deps._is_running = True
    deps._active_reachable = None
    wd = Watchdog(deps)
    with caplog.at_level("WARNING"):
        await wd._tick(0)
        await wd._tick(0)
    assert wd._unreachable_streak == 0
    assert not any("UNREACHABLE" in r.getMessage() for r in caplog.records)


async def test_unreachable_streak_resets_on_recovery():
    deps = FakeDeps()
    deps._is_running = True
    deps._active_reachable = False
    wd = Watchdog(deps)
    await wd._tick(0)  # miss (streak 1)
    deps._active_reachable = True
    await wd._tick(0)  # reachable again → reset
    assert wd._unreachable_streak == 0


async def test_reachable_probe_exception_does_not_destabilise_tick():
    # is_running is True (healthy); a raising probe must be swallowed — no
    # counter advance, no restart.
    deps = FakeDeps()
    deps._is_running = True
    deps.active_reachable_raises = RuntimeError("probe boom")
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    assert deps.restart_calls == 0


# --- Backoff ---------------------------------------------------------------


def test_sleep_no_backoff_when_no_failures():
    wd = Watchdog(FakeDeps(), interval_s=30, backoff_max_s=300)
    assert wd._sleep_for(0) == 30


def test_sleep_doubles_per_failure():
    wd = Watchdog(FakeDeps(), interval_s=30, backoff_max_s=10_000)
    assert wd._sleep_for(1) == 60
    assert wd._sleep_for(2) == 120
    assert wd._sleep_for(3) == 240


def test_sleep_capped_at_backoff_max():
    wd = Watchdog(FakeDeps(), interval_s=30, backoff_max_s=300)
    # 30 * 2**10 = 30720; should clamp to 300.
    assert wd._sleep_for(10) == 300


# --- Loop lifecycle --------------------------------------------------------


async def test_loop_starts_and_stops_cleanly():
    deps = FakeDeps()
    deps._is_running = True
    wd = Watchdog(deps, interval_s=0.01)
    await wd.start()
    await asyncio.sleep(0.05)  # let a few ticks run
    await wd.stop()
    # Idempotent stop:
    await wd.stop()


async def test_loop_calls_restart_when_singbox_dies():
    deps = FakeDeps()
    deps._vpn_on = True
    deps._is_running = False
    deps.restart_results = [(True, "")] * 100
    wd = Watchdog(deps, interval_s=0.01)
    await wd.start()
    await asyncio.sleep(0.1)
    await wd.stop()
    assert deps.restart_calls >= 1


async def test_loop_does_not_restart_when_vpn_off():
    deps = FakeDeps()
    deps._vpn_on = False
    deps._is_running = False  # sing-box happens to be down, but vpn is off
    wd = Watchdog(deps, interval_s=0.01)
    await wd.start()
    await asyncio.sleep(0.1)
    await wd.stop()
    assert deps.restart_calls == 0


# --- LAN capture healing ----------------------------------------------------


async def test_healthy_tick_reasserts_the_capture():
    """`/etc/init.d/firewall restart` rebuilds the whole mangle table and takes
    our chain with it. That fails *open* — traffic goes direct, nothing is
    black-holed, so nobody notices the VPN stopped protecting them. The
    watchdog is what heals it."""
    deps = FakeDeps()
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    assert deps.capture_calls == 1


async def test_capture_failure_does_not_degrade_down_detection():
    """A capture that won't restore is logged, not counted as a failure.

    Counting it would let the backoff stretch the tick towards its 300 s cap —
    so a capture problem (which fails *open*: traffic goes direct) would also
    slow down noticing that sing-box died (which fails *closed*: LAN dark).
    Keep the cadence and keep retrying.
    """
    deps = FakeDeps()
    deps.capture_result = False
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    assert deps.capture_calls == 1


async def test_a_lost_capture_reaches_the_ui_once_per_episode():
    """The realistic failure this branch exists for — `/etc/init.d/firewall
    restart` flushes mangle, the re-install then fails — fails *open* and
    silent: sing-box is healthy, vpn_on stays True, last_apply.ok stays True.
    Logging alone left a green "Connected" dashboard over a 100% unproxied LAN.
    Edge-triggered, because writing state every 30 s churns router flash.
    """
    deps = FakeDeps()
    deps.capture_result = False
    wd = Watchdog(deps)

    await wd._tick(0)
    await wd._tick(0)
    assert deps.capture_lost_reports == 1

    deps.capture_result = True  # healed
    await wd._tick(0)
    # ...and the banner is taken down; nothing else ever would, because the
    # watchdog's own recovery is not an apply.
    assert deps.capture_restored_reports == 1

    deps.capture_result = False  # and lost again — a new episode, so report again
    await wd._tick(0)
    assert deps.capture_lost_reports == 2


async def test_a_dropped_banner_write_is_retried_not_swallowed():
    """The edge trigger latched before knowing whether the write landed.

    `report_capture_lost` declines to overwrite an apply result recorded during
    the tick — and `now_iso()` is second-precision, so an apply that finished
    *before* the tick, in the same second, counts. Latching anyway silenced the
    banner for the rest of the episode: a green "Connected" over a fully
    unproxied LAN, which is the exact failure this path exists to prevent.
    """
    deps = FakeDeps()
    deps.capture_result = False
    deps.capture_lost_write_lands = False
    wd = Watchdog(deps)

    await wd._tick(0)
    await wd._tick(0)
    assert deps.capture_lost_reports == 2  # retried, not latched

    deps.capture_lost_write_lands = True
    await wd._tick(0)
    assert deps.capture_lost_reports == 3
    await wd._tick(0)
    assert deps.capture_lost_reports == 3  # now latched


async def test_a_banner_left_by_a_previous_process_is_cleared():
    """`_capture_lost` is in-memory; `last_error` is persisted. A daemon that
    restarts while the banner is up comes back with the flag False, so without
    a one-shot check on the first healthy tick the red "traffic is NOT being
    proxied" would stay pinned over a working VPN forever."""
    deps = FakeDeps()
    deps._capture_installed = True  # the stated premise: capture healthy
    wd = Watchdog(deps)  # fresh process, flag never set
    await wd._tick(0)
    assert deps.capture_restored_reports == 1
    await wd._tick(0)
    assert deps.capture_restored_reports == 1  # one-shot, not every tick


async def test_a_self_healed_capture_gap_is_still_reported():
    """`/etc/init.d/firewall restart` flushes mangle and takes the capture with
    it. The next tick re-asserts it and succeeds — so nothing was ever recorded,
    and the window was invisible. Measured on a real kernel with a sniffer on
    the WAN: 4-21 s of plaintext TCP *and* cleartext DNS from LAN clients, with
    last_apply.ok true and last_error empty the whole time. A browsing-history
    disclosure has to leave a mark even when it self-heals.
    """
    deps = FakeDeps()
    deps._vpn_on = True
    deps._capture_installed = False  # what a firewall restart leaves behind
    wd = Watchdog(deps)

    assert await wd._tick(0) == 0
    assert deps.capture_gap_reports == 1  # recorded, as a past event...
    assert deps.capture_lost_reports == 0  # ...not as a current fault
    assert deps.capture_calls == 1

    # Steady state afterwards is quiet: no churn on every tick.
    await wd._tick(0)
    assert deps.capture_gap_reports == 1


async def test_a_gap_and_a_failed_reassert_report_once_not_twice():
    """Both reasons to raise the banner can hold in the same tick. Reporting
    each separately double-counts, and a dropped write would be retried twice
    as fast as the latch expects."""
    deps = FakeDeps()
    deps._vpn_on = True
    deps._capture_installed = False
    deps.capture_result = False  # the re-assert also fails
    wd = Watchdog(deps)
    await wd._tick(0)
    assert deps.capture_lost_reports == 1
    assert deps.capture_gap_reports == 0  # a live fault, not a healed gap


async def test_every_tick_publishes_what_it_observed():
    """The UI cannot distinguish "VPN on" from "traffic is actually captured"
    unless someone publishes the second fact. The watchdog already probes it."""
    deps = FakeDeps()
    deps._vpn_on = True
    deps._capture_installed = True
    wd = Watchdog(deps)
    await wd._tick(0)
    assert deps.recorded_capture == [True]

    deps._capture_installed = False  # a firewall restart flushed mangle
    await wd._tick(0)
    assert deps.recorded_capture == [True, False]

    deps._capture_installed = None  # xtables lock held; could not tell
    await wd._tick(0)
    assert deps.recorded_capture == [True, False, None]


async def test_capture_not_reasserted_while_vpn_is_off():
    """With the VPN off there is no active node and nothing to re-assert — but
    we still watch, because a dead listener behind a live capture black-holes
    the LAN."""
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = True
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    assert deps.capture_calls == 0


async def test_singbox_is_supervised_while_the_capture_is_up_and_vpn_off():
    """The failure this exists for: VPN off, capture still installed (fake-IP
    leases outlive the toggle), sing-box crash-loops → every LAN TCP
    connection black-holed with ICMP still working. Somebody has to restart
    it."""
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = True
    deps._is_running = False
    deps.restart_results = [(True, "")]
    wd = Watchdog(deps)
    await wd._tick(0)  # first down is debounced
    assert await wd._tick(0) == 0
    assert deps.restart_calls == 1


async def test_nothing_watched_when_vpn_off_and_no_capture():
    """Genuinely idle: VPN off, no capture, and sing-box down too."""
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = False
    deps._is_running = False
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    assert deps.restart_calls == 0
    assert deps.capture_calls == 0


async def test_capture_restored_when_singbox_runs_without_one():
    """The DNS black-hole that took the LAN down on the live router.

    Our own shutdown removes the capture; sing-box is supervised by procd and
    keeps running. sing-box's transparent UDP sockets stay bound to the LAN
    resolver address from earlier tproxy sessions, so with the capture gone
    they receive client DNS directly and answer nothing — dnsmasq never gets
    the query. This tick used to return 0 and call it idle.
    """
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = False
    deps._is_running = True
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    # Recycled first: re-asserting the capture over the stale sockets was
    # measured on a real kernel and does not clear them.
    assert deps.restart_calls == 1
    assert deps.capture_calls == 1


async def test_hybrid_repair_runs_once_not_every_tick():
    """This branch returns 0, which resets the caller's failure counter — so it
    gets neither backoff nor the give-up path. Without a latch a persistent
    failure recycles sing-box every 30s forever, and reports nothing."""
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = False
    deps._is_running = True
    deps.capture_result = False  # ensure_capture keeps failing
    wd = Watchdog(deps)
    for _ in range(10):
        assert await wd._tick(0) == 0
    assert deps.restart_calls == 1
    assert deps.capture_lost_reports == 1  # and the dashboard was told, once


async def test_hybrid_repair_rearms_after_the_capture_comes_back():
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = False
    deps._is_running = True
    wd = Watchdog(deps)
    await wd._tick(0)
    assert deps.restart_calls == 1
    deps._capture_installed = True  # episode over
    await wd._tick(0)
    deps._capture_installed = False  # a new one starts
    await wd._tick(0)
    assert deps.restart_calls == 2


async def test_hybrid_repair_covers_a_wedged_singbox():
    """The worst form of the bug: the process is alive and sitting on the LAN
    resolver port, but its Clash API stopped answering — so `is_running()`,
    which requires both, reads False and the branch was skipped entirely."""
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = False
    deps._is_running = False  # pidof AND clash → False
    deps._process_alive = True  # ...but the process is there
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    assert deps.restart_calls == 1


async def test_unreadable_capture_state_does_not_recycle():
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = None  # xtables lock held; could not tell
    deps._is_running = True
    wd = Watchdog(deps)
    assert await wd._tick(0) == 0
    assert deps.restart_calls == 0


async def test_hybrid_repair_defers_to_the_give_up_path():
    """The give-up below deliberately un-captures a sing-box that is not coming
    back. Re-installing would re-arm exactly what it just disarmed."""
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = False
    deps._is_running = True
    wd = Watchdog(deps)
    assert await wd._tick(2) == 0  # carrying failures → stay out of the way
    assert deps.restart_calls == 0


# --- give-up path -----------------------------------------------------------


async def test_gives_up_and_uncaptures_when_vpn_is_off():
    """The recovery the user would expect from the toggle.

    With the VPN off and sing-box gone for good, the capture holds the LAN
    hostage: TPROXY with no listener black-holes TCP, and the DNS divert means
    dnsmasq never sees a query either — the LAN is fully dark. The toggle they
    would reach for is the one they already flipped, so without this the only
    way out is SSH.
    """
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = True
    deps._is_running = False
    deps.restart_results = [(False, "boom")] * 10

    wd = Watchdog(deps)
    failures = 0
    for _ in range(8):
        failures = await wd._tick(failures)
    assert deps.capture_removals >= 1
    assert not deps._capture_installed


async def test_never_gives_up_while_the_vpn_is_on():
    """With the VPN on, dark is the *intended* failure: dropping beats leaking
    real traffic to the ISP. Un-capturing here would silently turn a
    fail-closed outage into an unprotected one."""
    deps = FakeDeps()
    deps._vpn_on = True
    deps._capture_installed = True
    deps._is_running = False
    deps.restart_results = [(False, "boom")] * 10

    wd = Watchdog(deps)
    failures = 0
    for _ in range(8):
        failures = await wd._tick(failures)
    assert deps.capture_removals == 0


async def test_a_single_failure_does_not_trip_the_give_up():
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = True
    deps._is_running = False
    deps.restart_results = [(False, "boom"), (True, "")]

    wd = Watchdog(deps)
    await wd._tick(0)  # debounced
    await wd._tick(0)  # first real restart attempt, fails
    assert deps.capture_removals == 0


async def test_stop_cancels_a_tick_that_overruns_the_budget():
    """Shutdown is a deadline, not a request.

    procd SIGKILLs at `term_timeout` and then stops sing-box, so anything the
    daemon hasn't finished by then simply doesn't happen — and the thing that
    must happen is removing the LAN capture, which runs *after* this. A tick
    can sit 15 s in `_wait_for_listener` and longer on a restart; measured
    13.6 s before `divert.remove()` was even reached, after which the capture
    survived the SIGKILL and the LAN went dark behind a listener-less TPROXY
    rule on a plain `/etc/init.d/kitewrt stop`.
    """
    deps = FakeDeps()
    started = asyncio.Event()

    async def hang():
        started.set()
        await asyncio.sleep(3600)
        return True

    deps.ensure_capture = hang
    wd = Watchdog(deps, interval_s=0.01)
    await wd.start()
    await asyncio.wait_for(started.wait(), timeout=2)

    loop = asyncio.get_event_loop()
    began = loop.time()
    await wd.stop(timeout=0.1)
    assert loop.time() - began < 1.0, "graceful-only stop is unbounded"


async def test_stop_without_a_timeout_still_waits():
    """The default has no deadline: everywhere except shutdown, cutting a tick
    short is worse than waiting for it."""
    deps = FakeDeps()
    wd = Watchdog(deps, interval_s=0.01)
    await wd.start()
    await asyncio.sleep(0.05)
    await wd.stop()
    assert wd._task is None


async def test_the_tick_checks_where_traffic_goes_not_just_that_it_is_diverted():
    """The project's defining failure, in its purest form.

    Measured on a stock OpenWrt 23.05 router: `vpn_on` true, process healthy,
    capture installed — and the selector sitting on `direct` for 75 s across
    more than two ticks, every LAN packet leaving via the ISP, while
    `/api/state` said `vpn_on: true` with `last_apply.ok: true` and
    `/api/exit-ip` returned the user's own ISP address next to `vpn_on: true`.
    Every existing check passed, because they all ask whether traffic reaches
    sing-box and none asks where sing-box sends it.
    """
    deps = FakeDeps()
    deps._vpn_on = True
    deps._is_running = True
    deps._capture_installed = True
    deps.resync_result = True  # the selector had drifted

    wd = Watchdog(deps)
    assert await wd._tick(0) == 0

    assert deps.resync_calls == 1, "the selector must be checked on a healthy tick"


async def test_a_selector_that_already_agrees_costs_nothing_extra():
    deps = FakeDeps()
    deps._vpn_on = True
    deps._is_running = True
    deps._capture_installed = True
    deps.resync_result = False

    wd = Watchdog(deps)
    assert await wd._tick(0) == 0

    assert deps.resync_calls == 1
