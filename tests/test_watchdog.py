import asyncio

import pytest
from kitewrt.watchdog import Watchdog


class FakeDeps:
    """Scriptable WatchdogDeps implementation."""

    def __init__(self):
        self._vpn_on = True
        self._applying = False
        self._is_running = True
        self.restart_results: list[tuple[bool, str]] = []  # popped per call
        self.restart_calls = 0
        self.is_running_raises: Exception | None = None
        self.restart_raises: Exception | None = None

    def vpn_on(self) -> bool:
        return self._vpn_on

    def applying(self) -> bool:
        return self._applying

    async def is_running(self) -> bool:
        if self.is_running_raises:
            raise self.is_running_raises
        return self._is_running

    async def restart(self) -> tuple[bool, str]:
        self.restart_calls += 1
        if self.restart_raises:
            raise self.restart_raises
        return self.restart_results.pop(0) if self.restart_results else (True, "")


# --- _tick state machine ----------------------------------------------------


async def test_tick_noop_when_vpn_off():
    deps = FakeDeps()
    deps._vpn_on = False
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
