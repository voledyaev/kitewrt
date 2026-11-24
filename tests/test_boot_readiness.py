"""Boot may release FORWARD only after the LAN is captured on intended VPN."""

from __future__ import annotations

import asyncio
import shlex

import pytest
from kitewrt import api, killswitch
from kitewrt.state import ActiveServerRef, ApplyResult, State, Subscription
from kitewrt.vless import Server


class Boot:
    def __init__(self, state):
        self.state = state
        self.events = []
        self.clock = asyncio.Event()
        self.clock_started = asyncio.Event()
        self.clock_cancelled = False
        self.signaled = asyncio.Event()
        self.protected = False
        self.captured = False
        self.workers = 0
        self.signals = 0
        self.protect_ok = True
        self.release_ok = True

    async def prepare(self):
        self.events.append("protect")
        self.protected = self.protect_ok
        return self.protect_ok

    async def release(self):
        self.events.append("release")
        if self.release_ok:
            self.protected = False
        return self.release_ok

    async def wait_clock(self):
        self.events.append("clock")
        self.clock_started.set()
        try:
            await self.clock.wait()
        except asyncio.CancelledError:
            self.clock_cancelled = True
            raise
        return True

    async def start(self):
        self.events.append("workers")
        self.workers += 1

    def signal(self):
        self.events.append("signal")
        self.signals += 1
        self.signaled.set()

    async def current(self, _selector):
        return "s/n"

    async def capture(self):
        return self.captured

    async def sweep_capture(self):
        self.events.append("sweep_capture")

    def run(self, **kwargs):
        return asyncio.create_task(
            api._boot_reconcile(
                self.state, self, self, start_workers=self.start, poll_s=0.005, **kwargs
            )
        )


@pytest.fixture
async def boot(tmp_path, monkeypatch):
    state = State(tmp_path / "state.json")

    def configure(data):
        data.vpn_on = True
        data.active_server = ActiveServerRef(subscription_id="s", server_id="n")
        data.subscriptions = [
            Subscription(
                id="s",
                label="test",
                source="",
                fetched_at="",
                servers=[Server(id="n", name="test", country="ZZ", host="example.test", port=443)],
            )
        ]

    await state.update(configure)
    result = Boot(state)
    monkeypatch.setattr(killswitch, "prepare_boot", result.prepare)
    monkeypatch.setattr(killswitch, "sweep", result.release)
    monkeypatch.setattr(api, "_await_clock_sane", result.wait_clock)
    monkeypatch.setattr(api.divert, "installed_state", result.capture)
    monkeypatch.setattr(api.divert, "sweep", result.sweep_capture)
    return result


async def cancel(task):
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def complete(boot, *, ok=True):
    def apply(data):
        data.applying = False
        data.last_apply = ApplyResult(at="2026-01-01T00:00:01Z", ok=ok, msg="")

    await boot.state.update(apply)


async def test_protects_before_clock_and_before_uncapture_without_workers(boot):
    task = boot.run(capture_swept=False)
    await asyncio.wait_for(boot.clock_started.wait(), 1)
    assert boot.events == ["protect", "sweep_capture", "clock"]
    assert boot.protected and boot.workers == 0
    await cancel(task)
    assert boot.protected  # cancellation with VPN-on must not release
    assert boot.clock_cancelled


async def test_cached_selector_does_not_release_before_successful_apply_and_capture(boot):
    boot.clock.set()
    task = boot.run()
    await asyncio.wait_for(boot.signaled.wait(), 1)
    assert boot.protected
    await complete(boot)
    await asyncio.sleep(0.02)
    assert boot.protected  # successful apply alone is not an observed capture
    boot.captured = True
    await asyncio.wait_for(task, 1)
    assert not boot.protected
    assert boot.workers == 1


async def test_apply_failure_keeps_guard_until_user_turns_off(boot):
    boot.clock.set()
    task = boot.run()
    await asyncio.wait_for(boot.signaled.wait(), 1)
    boot.captured = True
    await complete(boot, ok=False)
    await asyncio.sleep(0.03)
    assert boot.protected and not task.done()
    await boot.state.update(lambda data: setattr(data, "vpn_on", False))
    await asyncio.wait_for(task, 1)
    assert not boot.protected


async def test_off_during_unsynced_clock_starts_workers_and_releases(boot):
    task = boot.run()
    await asyncio.wait_for(boot.clock_started.wait(), 1)
    await boot.state.update(lambda data: setattr(data, "vpn_on", False))
    await asyncio.wait_for(task, 1)
    assert boot.clock_cancelled
    assert boot.workers == 1 and boot.signals == 1
    assert not boot.protected


async def test_cannot_uncapture_if_boot_protection_failed(boot):
    boot.protect_ok = False
    task = boot.run(capture_swept=False)
    await asyncio.sleep(0.02)
    assert "sweep_capture" not in boot.events
    assert not boot.clock_started.is_set()
    await cancel(task)


async def test_failed_guard_release_is_retried_not_reported_complete(boot):
    boot.clock.set()
    boot.release_ok = False
    task = boot.run()
    await asyncio.wait_for(boot.signaled.wait(), 1)
    boot.captured = True
    await complete(boot)
    await asyncio.sleep(0.03)
    assert not task.done() and boot.protected
    boot.release_ok = True
    await asyncio.wait_for(task, 1)
    assert not boot.protected


async def test_boot_drop_is_route_independent_and_never_deletes_unrelated_rules(monkeypatch):
    rules = [["-o", "wwan0", "-j", "ACCEPT"]]
    calls = []

    async def capture(args, timeout=5):
        return 0, "\n".join("-A FORWARD " + shlex.join(rule) for rule in rules)

    async def ipt(args, timeout=5):
        calls.append(args)
        if args[:3] == ["-I", "FORWARD", "1"]:
            rules.insert(0, args[3:])
        elif args[:4] == ["-t", "filter", "-D", "FORWARD"]:
            rules.remove(args[4:])
        else:
            pytest.fail(str(args))
        return 0

    monkeypatch.setattr(killswitch, "_ipt_capture", capture)
    monkeypatch.setattr(killswitch, "_ipt", ipt)
    monkeypatch.setattr(killswitch, "_lock", None)
    assert await killswitch.prepare_boot()
    assert "-o" not in rules[0] and rules[0][-1] == "DROP"
    assert await killswitch.prepare_boot()
    assert len(calls) == 1  # idempotent, including without a default route
    assert await killswitch.sweep()
    assert rules == [["-o", "wwan0", "-j", "ACCEPT"]]


async def test_reenable_during_off_cleanup_rearms_before_reporting_done(boot, monkeypatch):
    await boot.state.update(lambda data: setattr(data, "vpn_on", False))
    reenabled = asyncio.Event()
    original = boot.release

    async def release():
        if not reenabled.is_set():
            await original()

            def on(data):
                data.vpn_on = True
                data.applying = True

            await boot.state.update(on)
            reenabled.set()
            return True
        return await original()

    monkeypatch.setattr(killswitch, "sweep", release)
    boot.clock.set()
    task = boot.run()
    await asyncio.wait_for(reenabled.wait(), 1)
    await asyncio.sleep(0.03)
    assert boot.protected and not task.done()
    boot.captured = True
    await complete(boot)
    await asyncio.wait_for(task, 1)
    assert not boot.protected


async def test_apply_change_during_ready_cleanup_rearms(boot, monkeypatch):
    changed = asyncio.Event()
    original = boot.release

    async def release():
        if not changed.is_set():
            await original()
            await boot.state.update(lambda data: setattr(data, "applying", True))
            changed.set()
            return True
        return await original()

    monkeypatch.setattr(killswitch, "sweep", release)
    boot.clock.set()
    task = boot.run()
    await asyncio.wait_for(boot.signaled.wait(), 1)
    boot.captured = True
    await complete(boot)
    await asyncio.wait_for(changed.wait(), 1)
    await asyncio.sleep(0.03)
    assert boot.protected and not task.done()
    await complete(boot)
    await asyncio.wait_for(task, 1)
    assert not boot.protected


@pytest.mark.parametrize("vpn_off", [False, True])
async def test_watchdog_waits_for_boot_readiness_or_explicit_off(boot, vpn_off):
    class Watchdog:
        started = False

        async def start(self):
            self.started = True

    watchdog = Watchdog()
    boot.clock.set()
    task = asyncio.create_task(
        api._boot_then_watchdog(
            api._boot_reconcile(boot.state, boot, boot, start_workers=boot.start, poll_s=0.005),
            watchdog,
        )
    )
    await asyncio.wait_for(boot.signaled.wait(), 1)
    await complete(boot, ok=False)
    await asyncio.sleep(0.02)
    assert boot.workers == 1 and not watchdog.started
    if vpn_off:
        await boot.state.update(lambda data: setattr(data, "vpn_on", False))
    else:
        boot.captured = True
        await complete(boot)
    await asyncio.wait_for(task, 1)
    assert watchdog.started and not boot.protected


async def test_initial_apply_retries_after_wan_recovers_without_ui_action(boot):
    from kitewrt.apply import ApplyPipeline

    calls = 0
    wan_ready = asyncio.Event()
    first_failed = asyncio.Event()

    class Plane:
        async def apply(self, snap):
            nonlocal calls
            calls += 1
            if not wan_ready.is_set():
                first_failed.set()
                return False, "no default route"
            boot.captured = True
            return True, ""

    pipe = ApplyPipeline(boot.state, Plane())
    boot.clock.set()
    task = asyncio.create_task(
        api._boot_reconcile(
            boot.state,
            boot,
            pipe,
            start_workers=pipe.start,
            poll_s=0.005,
            retry_initial_s=0.01,
            retry_max_s=0.02,
        )
    )
    try:
        await asyncio.wait_for(first_failed.wait(), 1)
        assert boot.protected
        wan_ready.set()
        await asyncio.wait_for(task, 1)
        assert calls >= 2 and not boot.protected
        assert boot.state.snapshot().last_apply.ok
    finally:
        if not task.done():
            await cancel(task)
        await pipe.stop()


@pytest.mark.parametrize(
    "on,guard_ok,removed", [(True, True, True), (True, False, False), (False, False, True)]
)
async def test_shutdown_protects_before_capture_removal(
    tmp_path, monkeypatch, on, guard_ok, removed
):
    state = State(tmp_path / "state.json")
    await state.update(lambda data: setattr(data, "vpn_on", on))
    events = []

    async def protect():
        events.append("protect")
        return guard_ok

    async def remove(**kwargs):
        events.append("uncapture")
        return True

    monkeypatch.setattr(killswitch, "prepare_boot", protect)
    monkeypatch.setattr(api.divert, "remove", remove)
    assert await api._shutdown_capture(state) is removed
    assert events == (
        ["protect", "uncapture"] if on and guard_ok else ["protect"] if on else ["uncapture"]
    )
