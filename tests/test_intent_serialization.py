"""Observation reloads must not overwrite newer routing intent."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import pytest
from kitewrt import dataplane, killswitch
from kitewrt.singbox.config import SELECTOR_TAG, active_tag, build_config
from kitewrt.state import ActiveServerRef, State

from tests.test_dataplane_singbox import FakeClash, FakeService, _data, _server


@pytest.fixture(autouse=True)
def no_real_firewall(monkeypatch):
    monkeypatch.setattr(killswitch, "sweep", AsyncMock(return_value=True))
    monkeypatch.setattr(killswitch, "prepare_boot", AsyncMock(return_value=True))
    monkeypatch.setattr(killswitch, "prepare_reload", AsyncMock(return_value=True))
    monkeypatch.setattr(killswitch, "release_reload", AsyncMock(return_value=True))


async def configured_state(tmp_path, *, vpn_on=False, servers=None):
    state = State(tmp_path / "state.json")
    data = _data(vpn_on=vpn_on, servers=servers)

    def set_config(d):
        d.subscriptions = data.subscriptions
        d.active_server = data.active_server
        d.vpn_on = data.vpn_on

    await state.update(set_config)
    return state


class PausedFirstStart(FakeService):
    def __init__(self):
        super().__init__(running=False)
        self.entered = asyncio.Event()
        self.resume = asyncio.Event()

    async def restart(self, *, after=None):
        if not self.entered.is_set():
            self.running = False
            self.entered.set()
            await self.resume.wait()
        return await super().restart(after=after)


def plane_for(tmp_path, state, service, clash):
    return dataplane.SingBoxDataPlane(
        service,
        clash,
        state=state,
        config_path=tmp_path / "config.json",
        reselect_delay=0,
        unusable_delay=0,
    )


async def test_old_off_test_waiting_for_new_on_apply_keeps_new_proxy(tmp_path):
    state = await configured_state(tmp_path)
    old_off = state.snapshot()
    (tmp_path / "config.json").write_text(json.dumps(build_config(old_off)))
    await state.update(lambda d: setattr(d, "vpn_on", True))
    service, clash = PausedFirstStart(), FakeClash()
    plane = plane_for(tmp_path, state, service, clash)

    apply = asyncio.create_task(plane.apply(state.snapshot()))
    await asyncio.wait_for(service.entered.wait(), 1)
    observation = asyncio.create_task(plane.ensure_materialized(old_off))
    await asyncio.sleep(0)
    service.resume.set()

    assert await asyncio.wait_for(apply, 1) == (True, "")
    assert await asyncio.wait_for(observation, 1) == (True, "")
    assert await clash.current(SELECTOR_TAG) == active_tag(state.snapshot())
    assert service.capture_installed
    assert service.reloads == 1  # the old test sees the already materialized current config


async def test_queued_test_and_start_callback_use_latest_node(tmp_path):
    servers = [_server(), _server("second.example")]
    state = await configured_state(tmp_path, vpn_on=True, servers=servers)
    stale = state.snapshot()
    service, clash = PausedFirstStart(), FakeClash()
    plane = plane_for(tmp_path, state, service, clash)
    apply = asyncio.create_task(plane.apply(stale))
    await asyncio.wait_for(service.entered.wait(), 1)
    observation = asyncio.create_task(plane.ensure_materialized(stale))

    await state.update(
        lambda d: setattr(
            d, "active_server", ActiveServerRef(subscription_id="sub-1", server_id=servers[1].id)
        )
    )
    service.resume.set()
    assert await asyncio.wait_for(apply, 1) == (True, "")
    assert await asyncio.wait_for(observation, 1) == (True, "")
    assert await clash.current(SELECTOR_TAG) == active_tag(state.snapshot())
    assert service.reloads == 1


async def test_observation_rebuilds_current_structure_after_waiting(tmp_path):
    state = await configured_state(tmp_path, vpn_on=True)
    stale = state.snapshot()
    service, clash = PausedFirstStart(), FakeClash()
    plane = plane_for(tmp_path, state, service, clash)
    apply = asyncio.create_task(plane.apply(stale))
    await asyncio.wait_for(service.entered.wait(), 1)
    observation = asyncio.create_task(plane.ensure_materialized(stale))
    await state.update(lambda d: setattr(d.dns, "direct_dns", "9.9.9.9"))
    service.resume.set()
    await asyncio.wait_for(apply, 1)
    assert await asyncio.wait_for(observation, 1) == (True, "")
    assert json.loads((tmp_path / "config.json").read_text()) == build_config(state.snapshot())
    assert service.reloads == 2


async def test_structure_change_during_validation_never_promotes_old_snapshot(tmp_path):
    state = await configured_state(tmp_path, vpn_on=True)
    old = build_config(state.snapshot())
    path = tmp_path / "config.json"
    path.write_text(json.dumps(old))
    entered, resume = asyncio.Event(), asyncio.Event()

    class Service(FakeService):
        async def check_config(self, _path):
            entered.set()
            await resume.wait()
            return True, ""

    service = Service(running=False)
    plane = plane_for(tmp_path, state, service, FakeClash())
    task = asyncio.create_task(plane.ensure_materialized(state.snapshot()))
    await asyncio.wait_for(entered.wait(), 1)
    await state.update(lambda d: setattr(d.dns, "direct_dns", "9.9.9.9"))
    resume.set()
    ok, msg = await asyncio.wait_for(task, 1)
    assert not ok and "settings changed" in msg
    assert json.loads(path.read_text()) == old
    assert service.reloads == 0


async def test_selector_confirmation_rechecks_changed_intent(tmp_path):
    state = await configured_state(tmp_path)
    cfg = build_config(state.snapshot())
    entered, resume = asyncio.Event(), asyncio.Event()

    class Clash(FakeClash):
        async def current(self, selector):
            if not entered.is_set():
                entered.set()
                await resume.wait()
            return await super().current(selector)

    clash = Clash()
    plane = plane_for(tmp_path, state, FakeService(), clash)
    task = asyncio.create_task(plane._select_latest_after_reload(cfg, "direct"))
    await asyncio.wait_for(entered.wait(), 1)
    await state.update(lambda d: setattr(d, "vpn_on", True))
    resume.set()
    await asyncio.wait_for(task, 1)
    assert await clash.current(SELECTOR_TAG) == active_tag(state.snapshot())
    assert clash.selects[0][1] == "direct"
    assert clash.selects[-1][1] != "direct"


async def test_selector_confirmation_refuses_new_node_absent_from_running_config(tmp_path):
    state = await configured_state(tmp_path, vpn_on=True)
    cfg = build_config(state.snapshot())
    new = _server("new.example")

    def change(d):
        d.subscriptions[0].servers.append(new)
        d.active_server = ActiveServerRef(subscription_id="sub-1", server_id=new.id)

    await state.update(change)
    clash = FakeClash()
    plane = plane_for(tmp_path, state, FakeService(), clash)
    with pytest.raises(RuntimeError, match="absent from running config"):
        await plane._select_latest_after_reload(cfg, "direct")
    assert not clash.selects


async def test_stale_off_fallback_does_not_stop_new_on_intent(tmp_path):
    state = await configured_state(tmp_path, vpn_on=True)
    service = FakeService()
    plane = plane_for(tmp_path, state, service, FakeClash())
    ok, msg = await plane._fall_back_direct("old off recovery")
    assert not ok and "intent changed" in msg
    assert service.stops == 0


@pytest.mark.parametrize("vpn_on", [True, False])
async def test_ready_live_apply_releases_launch_guards(tmp_path, vpn_on):
    state = await configured_state(tmp_path, vpn_on=vpn_on)
    snap = state.snapshot()
    (tmp_path / "config.json").write_text(json.dumps(build_config(snap)))
    service, clash = FakeService(running=True), FakeClash()
    service.capture_installed = True
    plane = plane_for(tmp_path, state, service, clash)
    assert await plane.apply(snap) == (True, "")
    killswitch.release_reload.assert_awaited_once_with(dataplane.divert.TPROXY_MARK)
    killswitch.sweep.assert_awaited_once()


async def test_guard_cleanup_failure_stays_explicit_and_bounded(tmp_path):
    state = await configured_state(tmp_path, vpn_on=True)
    clash = FakeClash()
    await clash.select(SELECTOR_TAG, active_tag(state.snapshot()))
    plane = plane_for(tmp_path, state, FakeService(running=True), clash)
    killswitch.release_reload.return_value = False
    ok, msg = await plane._finish_ready()
    assert not ok and "protection could not be released" in msg
    assert killswitch.release_reload.await_count == 3
    killswitch.sweep.assert_not_awaited()


async def test_cleanup_rearms_guards_if_new_on_intent_arrives(tmp_path):
    state = await configured_state(tmp_path)
    clash = FakeClash()
    await clash.select(SELECTOR_TAG, "direct")
    plane = plane_for(tmp_path, state, FakeService(running=True), clash)

    async def changed(_mark):
        await state.update(lambda d: setattr(d, "vpn_on", True))
        return True

    killswitch.release_reload.side_effect = changed
    ok, msg = await plane._finish_ready()
    assert not ok and "intent changed" in msg
    killswitch.prepare_reload.assert_awaited_once()
    killswitch.prepare_boot.assert_awaited_once()
    killswitch.sweep.assert_not_awaited()


async def test_watchdog_restart_uses_on_intent_that_arrives_during_start(tmp_path):
    state = await configured_state(tmp_path)
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(build_config(state.snapshot())))
    service, clash = PausedFirstStart(), FakeClash()
    deps = dataplane.SingBoxWatchdogDeps(state, service, clash, config_path=cfg, reselect_delay=0)
    task = asyncio.create_task(deps.restart())
    await asyncio.wait_for(service.entered.wait(), 1)
    await state.update(lambda d: setattr(d, "vpn_on", True))
    service.resume.set()
    assert await asyncio.wait_for(task, 1) == (True, "")
    assert clash.selects == [(SELECTOR_TAG, active_tag(state.snapshot()))]


async def test_watchdog_correction_uses_latest_node_after_controller_wait(tmp_path):
    servers = [_server(), _server("second.example")]
    state = await configured_state(tmp_path, vpn_on=True, servers=servers)
    entered, resume = asyncio.Event(), asyncio.Event()

    class Clash(FakeClash):
        async def current(self, selector):
            if not entered.is_set():
                entered.set()
                await resume.wait()
                return "direct"
            return await super().current(selector)

    clash = Clash()
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(build_config(state.snapshot())))
    deps = dataplane.SingBoxWatchdogDeps(
        state, FakeService(), clash, config_path=cfg, reselect_delay=0
    )
    task = asyncio.create_task(deps.resync_selector())
    await asyncio.wait_for(entered.wait(), 1)
    await state.update(
        lambda d: setattr(
            d, "active_server", ActiveServerRef(subscription_id="sub-1", server_id=servers[1].id)
        )
    )
    resume.set()
    assert await asyncio.wait_for(task, 1) is True
    assert clash.selects == [(SELECTOR_TAG, active_tag(state.snapshot()))]


@pytest.mark.parametrize("vpn_on", [True, False])
async def test_watchdog_restores_and_releases_launch_guards_only_when_ready(tmp_path, vpn_on):
    state = await configured_state(tmp_path, vpn_on=vpn_on)
    service, clash = FakeService(running=True), FakeClash()
    service._capture_enabled = True
    await clash.select(SELECTOR_TAG, active_tag(state.snapshot()) if vpn_on else "direct")
    deps = dataplane.SingBoxWatchdogDeps(state, service, clash)
    assert await deps.ensure_capture()
    killswitch.release_reload.assert_awaited_once()
    killswitch.sweep.assert_awaited_once()


async def test_watchdog_off_giveup_does_not_release_when_new_on_arrives(tmp_path):
    state = await configured_state(tmp_path)
    entered, resume = asyncio.Event(), asyncio.Event()

    class Service(FakeService):
        _capture_enabled = True
        released = False

        async def stop(self, *, may_release):
            entered.set()
            await resume.wait()
            self.released = may_release()
            return (self.released, "" if self.released else "new on intent")

    service = Service()
    deps = dataplane.SingBoxWatchdogDeps(state, service, FakeClash())
    task = asyncio.create_task(deps.remove_capture())
    await asyncio.wait_for(entered.wait(), 1)
    await state.update(lambda d: setattr(d, "vpn_on", True))
    resume.set()
    await asyncio.wait_for(task, 1)
    assert not service.released


@pytest.mark.parametrize("owner", ["apply", "watchdog"])
async def test_readiness_and_guard_release_exclude_concurrent_managed_restart(tmp_path, owner):
    state = await configured_state(tmp_path, vpn_on=True)
    reading, resume, restarted = asyncio.Event(), asyncio.Event(), asyncio.Event()

    class Service(FakeService):
        _capture_enabled = True

        async def restart(self, *, after=None):
            async with self.op_lock():
                restarted.set()
                return True, ""

    class Clash(FakeClash):
        async def current(self, selector):
            reading.set()
            await resume.wait()
            return await super().current(selector)

    service, clash = Service(running=True), Clash()
    await clash.select(SELECTOR_TAG, active_tag(state.snapshot()))
    if owner == "apply":
        plane = plane_for(tmp_path, state, service, clash)
        ready = asyncio.create_task(plane._finish_ready())
    else:
        deps = dataplane.SingBoxWatchdogDeps(state, service, clash)
        ready = asyncio.create_task(deps.ensure_capture())
    await asyncio.wait_for(reading.wait(), 1)
    restart = asyncio.create_task(service.restart())
    await asyncio.sleep(0)
    assert not restarted.is_set()
    resume.set()
    result = await asyncio.wait_for(ready, 1)
    assert result == (True, "") if owner == "apply" else result is True
    await asyncio.wait_for(restart, 1)
    assert restarted.is_set()


async def test_invalid_on_apply_protects_existing_direct_capture_before_validation(tmp_path):
    state = await configured_state(tmp_path, vpn_on=True)
    service, clash = FakeService(running=False), FakeClash()
    service._capture_enabled = True
    service.capture_installed = True
    service.check_result = False, "invalid config"
    await clash.select(SELECTOR_TAG, "direct")
    plane = plane_for(tmp_path, state, service, clash)
    ok, msg = await plane.apply(state.snapshot())
    assert not ok and "config rejected" in msg
    killswitch.prepare_reload.assert_awaited_once()
    killswitch.release_reload.assert_not_awaited()
    assert service.capture_installed


async def test_readiness_file_lock_excludes_an_independent_procd_launch(tmp_path):
    import subprocess
    import sys

    state = await configured_state(tmp_path, vpn_on=True)
    reading, resume = asyncio.Event(), asyncio.Event()

    class Clash(FakeClash):
        async def current(self, selector):
            reading.set()
            await resume.wait()
            return await super().current(selector)

    clash = Clash()
    await clash.select(SELECTOR_TAG, active_tag(state.snapshot()))
    plane = plane_for(tmp_path, state, FakeService(running=True), clash)
    ready = asyncio.create_task(plane._finish_ready())
    await asyncio.wait_for(reading.wait(), 1)
    code = (
        "import fcntl,os,sys; "
        "fd=os.open(sys.argv[1],os.O_CREAT|os.O_RDWR,0o600); "
        "fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)"
    )

    def launcher_attempt():
        return subprocess.run(
            [sys.executable, "-c", code, str(killswitch.RELOAD_LOCK_PATH)],
            capture_output=True,
            timeout=5,
        )

    assert launcher_attempt().returncode != 0
    resume.set()
    assert await asyncio.wait_for(ready, 1) == (True, "")
    assert launcher_attempt().returncode == 0


async def new_node_on_state(tmp_path, *, malformed_old=False):
    state = await configured_state(tmp_path)
    path = tmp_path / "config.json"
    old = (
        b"{invalid old JSON"
        if malformed_old
        else json.dumps(build_config(state.snapshot())).encode()
    )
    path.write_bytes(old)
    new = _server("added.example")

    def change(d):
        d.subscriptions[0].servers.append(new)
        d.active_server = ActiveServerRef(subscription_id="sub-1", server_id=new.id)
        d.vpn_on = True

    await state.update(change)
    return state, path, old


@pytest.mark.parametrize("malformed_old", [False, True])
async def test_valid_new_node_can_replace_old_off_config_without_proxy_rollback(
    tmp_path, malformed_old
):
    state, path, old = await new_node_on_state(tmp_path, malformed_old=malformed_old)
    service, clash = FakeService(running=False), FakeClash()
    service._capture_enabled = True
    service.capture_installed = True
    await clash.select(SELECTOR_TAG, "direct")
    plane = plane_for(tmp_path, state, service, clash)
    assert await plane.apply(state.snapshot()) == (True, "")
    assert service.reloads == 1
    assert await clash.current(SELECTOR_TAG) == active_tag(state.snapshot())
    assert json.loads(path.read_text()) == build_config(state.snapshot())
    assert path.with_suffix(".json.last-good").read_bytes() == old
    killswitch.release_reload.assert_awaited_once()


@pytest.mark.parametrize("malformed_old", [False, True])
async def test_failed_new_node_restores_old_bytes_without_starting_unsafe_direct(
    tmp_path, malformed_old
):
    state, path, old = await new_node_on_state(tmp_path, malformed_old=malformed_old)

    class Service(FakeService):
        _capture_enabled = True
        protected_stops = 0

        async def stop_protected(self):
            self.protected_stops += 1
            self.running = False
            return True, ""

    service, clash = Service(running=False), FakeClash()
    service.capture_installed = True
    service.restart_results = [(False, "candidate failed"), (False, "cache retry failed")]
    await clash.select(SELECTOR_TAG, "direct")
    plane = plane_for(tmp_path, state, service, clash)
    ok, msg = await plane.apply(state.snapshot())
    assert not ok and "no safe proxy rollback target" in msg
    assert service.reloads == 2  # candidate attempts only, no old direct restart
    assert service.protected_stops == 1
    assert service.capture_installed and not service.running
    assert path.read_bytes() == old
    assert clash.selects == [(SELECTOR_TAG, "direct")]  # no callback selected old direct
    killswitch.release_reload.assert_not_awaited()


async def test_explicit_off_during_failed_new_candidate_can_restore_old_direct(tmp_path):
    state, path, old = await new_node_on_state(tmp_path)

    class Service(FakeService):
        _capture_enabled = True

        async def restart_without_cache(self, *, after=None):
            self.cache_drops += 1
            result = await self.restart(after=after)
            await state.update(lambda d: setattr(d, "vpn_on", False))
            return result

    service, clash = Service(running=False), FakeClash()
    service.capture_installed = True
    service.restart_results = [
        (False, "candidate failed"),
        (False, "cache retry failed"),
        (True, ""),
    ]
    await clash.select(SELECTOR_TAG, "direct")
    plane = plane_for(tmp_path, state, service, clash)
    ok, msg = await plane.apply(state.snapshot())
    assert not ok and "cache retry failed" in msg  # requested candidate still failed
    assert service.reloads == 3 and service.running
    assert path.read_bytes() == old
    assert await clash.current(SELECTOR_TAG) == "direct"
    assert not state.snapshot().vpn_on
    killswitch.release_reload.assert_awaited_once()


async def test_rollback_copy_read_io_error_still_aborts_promotion(tmp_path):
    state, path, old = await new_node_on_state(tmp_path)
    service, clash = FakeService(running=False), FakeClash()
    plane = plane_for(tmp_path, state, service, clash)
    plane._rollback_target = AsyncMock(side_effect=OSError("backup unreadable"))
    ok, msg = await plane.apply(state.snapshot())
    assert not ok and "backup config failed" in msg
    assert service.reloads == 0 and path.read_bytes() == old
