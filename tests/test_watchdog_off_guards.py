"""A healthy off-state respawn must finish guarded selector readiness."""

from unittest.mock import AsyncMock

import pytest
from kitewrt import killswitch
from kitewrt.dataplane import SingBoxWatchdogDeps
from kitewrt.singbox.clash import ClashError
from kitewrt.singbox.config import SELECTOR_TAG, active_tag
from kitewrt.state import State
from kitewrt.watchdog import Watchdog

from tests.test_dataplane_singbox import FakeClash, FakeService, _data
from tests.test_watchdog import FakeDeps


async def off_state(tmp_path):
    state = State(tmp_path / "state.json")
    data = _data(vpn_on=False)

    def configure(d):
        d.vpn_on = False
        d.subscriptions = data.subscriptions
        d.active_server = data.active_server

    await state.update(configure)
    return state


@pytest.mark.parametrize("toggle_on", [False, True])
async def test_off_respawn_confirms_current_intent_then_releases_guards(
    tmp_path, monkeypatch, toggle_on
):
    state = await off_state(tmp_path)
    guards = {"armed": True}

    async def release(_mark):
        guards["armed"] = False
        return True

    monkeypatch.setattr(killswitch, "release_reload", release)
    monkeypatch.setattr(killswitch, "prepare_reload", AsyncMock(return_value=True))
    monkeypatch.setattr(killswitch, "prepare_boot", AsyncMock(return_value=True))
    monkeypatch.setattr(killswitch, "sweep", AsyncMock(return_value=True))

    class Clash(FakeClash):
        flipped = False

        async def current(self, selector):
            if toggle_on and not self.flipped:
                self.flipped = True
                await state.update(lambda d: setattr(d, "vpn_on", True))
            return await super().current(selector)

    clash = Clash()
    await clash.select(SELECTOR_TAG, active_tag(state.snapshot()))  # cached old proxy
    service = FakeService(running=True)
    service._capture_enabled = True
    service.capture_installed = True
    deps = SingBoxWatchdogDeps(state, service, clash, reselect_delay=0)
    deps.capture_installed = AsyncMock(return_value=True)
    deps.active_reachable = AsyncMock()
    assert await Watchdog(deps)._tick(0) == 0
    expected = active_tag(state.snapshot()) if toggle_on else "direct"
    assert await clash.current(SELECTOR_TAG) == expected
    assert not guards["armed"]
    assert service.capture_calls == 1
    assert service.reloads == 0
    deps.active_reachable.assert_not_awaited()


async def test_off_unknown_selector_does_not_release_guards_or_restart():
    deps = FakeDeps()
    deps._vpn_on = False
    deps._capture_installed = True
    deps.resync_result = None
    assert await Watchdog(deps)._tick(0) == 0
    assert deps.resync_calls == 1
    assert deps.capture_calls == 0
    assert deps.restart_calls == 0
