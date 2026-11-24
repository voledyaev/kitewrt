"""A running TPROXY socket is unsafe if its selector cannot be confirmed."""

import json
from unittest.mock import AsyncMock

import pytest
from kitewrt import dataplane
from kitewrt.singbox import service


def config(default="old", current_member="old"):
    return {
        "outbounds": [
            {
                "type": "selector",
                "tag": "select",
                "outbounds": [current_member, "direct"],
                "default": default,
            },
            {"type": "vless", "tag": current_member},
            {"type": "direct", "tag": "direct"},
        ]
    }


@pytest.mark.parametrize(
    "current,default,expected",
    [
        ("old", "direct", "old"),
        ("direct", "old", "old"),
        ("missing", "old", "old"),
    ],
)
async def test_rollback_uses_previous_actual_proxy_or_previous_default(
    tmp_path, current, default, expected
):
    path = tmp_path / "last-good"
    path.write_text(json.dumps(config(default)))
    clash = type("Clash", (), {"current": AsyncMock(return_value=current)})()
    plane = dataplane.SingBoxDataPlane(None, clash, config_path=path)
    assert await plane._rollback_target(path) == expected


@pytest.mark.parametrize("old", [{"old": True}, config("direct"), config("alias", "alias")])
async def test_unusable_rollback_does_not_block_valid_candidate(tmp_path, old):
    if old == config("alias", "alias"):
        old["outbounds"][1]["type"] = "direct"
    live = tmp_path / "config.json"
    live.write_text(json.dumps(old))
    svc = type(
        "Service",
        (),
        {
            "check_config": AsyncMock(return_value=(True, "")),
            "restart": AsyncMock(return_value=(True, "")),
        },
    )()
    clash = type("Clash", (), {"current": AsyncMock(return_value="direct")})()
    plane = dataplane.SingBoxDataPlane(svc, clash, config_path=live)
    ok, message = await plane._reload_locked(config("new", "new"), "key", "new")
    assert ok and not message
    assert json.loads(live.read_text()) == config("new", "new")
    svc.restart.assert_awaited_once()


async def test_failed_new_node_rolls_back_to_old_proxy_not_missing_new_tag(tmp_path):
    live = tmp_path / "config.json"
    live.write_text(json.dumps(config()))
    selected = []

    class Service:
        async def check_config(self, path):
            return True, ""

        async def restart(self, *, after):
            if len(selected) == 0:
                selected.append("candidate failed")
                return False, "candidate failed"
            await after()
            return True, ""

        async def restart_without_cache(self, *, after):
            return False, "candidate failed again"

    clash = type("Clash", (), {"current": AsyncMock(return_value="old")})()
    plane = dataplane.SingBoxDataPlane(Service(), clash, config_path=live)
    plane._select_after_reload = AsyncMock()
    ok, _ = await plane._reload_locked(config("new", "new"), "newkey", "new")
    assert not ok
    plane._select_after_reload.assert_awaited_once_with("old")
    assert json.loads(live.read_text()) == config()


async def test_exhausted_reselect_is_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(dataplane, "reassert_selector", AsyncMock(return_value=False))
    plane = dataplane.SingBoxDataPlane(None, None, config_path=tmp_path / "config")
    with pytest.raises(RuntimeError, match="not confirmed"):
        await plane._select_after_reload("proxy")


@pytest.mark.parametrize("stop_ok", [True, False])
async def test_after_failure_stops_listener_without_removing_capture(
    tmp_path, monkeypatch, stop_ok
):
    svc = service.SingBoxService(init_path=tmp_path / "absent")
    svc._invoke = AsyncMock(
        side_effect=[(True, ""), (stop_ok, "stop error" if not stop_ok else "")]
    )
    svc.remove_capture = AsyncMock()

    async def failed():
        raise RuntimeError("selector not confirmed")

    ok, message = await svc.restart(after=failed)
    assert not ok and "selector not confirmed" in message
    assert [call.args[0] for call in svc._invoke.await_args_list] == ["restart", "stop"]
    svc.remove_capture.assert_not_awaited()
    assert ("stop failed" in message) is (not stop_ok)


@pytest.mark.parametrize("observed", [None, "direct", "proxy"])
async def test_watchdog_capture_requires_confirmed_intended_proxy(tmp_path, observed):
    from types import SimpleNamespace
    from unittest.mock import Mock

    state = SimpleNamespace(egress_revision=1)
    state.snapshot = lambda: SimpleNamespace(vpn_on=True)
    svc = SimpleNamespace(ensure_capture=AsyncMock(return_value=True))
    clash = SimpleNamespace(current=AsyncMock(return_value=observed))
    deps = dataplane.SingBoxWatchdogDeps(state, svc, clash)
    original = dataplane.active_tag
    try:
        dataplane.active_tag = Mock(return_value="proxy")
        assert await deps.ensure_capture() is (observed == "proxy")
        assert svc.ensure_capture.await_count == (1 if observed == "proxy" else 0)
    finally:
        dataplane.active_tag = original


async def test_watchdog_capture_rejects_stale_selector_snapshot(monkeypatch):
    from types import SimpleNamespace

    state = SimpleNamespace(egress_revision=1)
    state.snapshot = lambda: SimpleNamespace(vpn_on=True)

    async def current(selector):
        state.egress_revision += 1
        return "proxy"

    svc = SimpleNamespace(ensure_capture=AsyncMock(return_value=True))
    deps = dataplane.SingBoxWatchdogDeps(state, svc, SimpleNamespace(current=current))
    monkeypatch.setattr(dataplane, "active_tag", lambda snap: "proxy")
    assert not await deps.ensure_capture()
    svc.ensure_capture.assert_not_awaited()


async def test_off_to_on_can_restore_explicit_intended_old_member(tmp_path):
    path = tmp_path / "last-good"
    path.write_text(json.dumps(config("direct")))
    clash = type("Clash", (), {"current": AsyncMock(return_value="direct")})()
    plane = dataplane.SingBoxDataPlane(None, clash, config_path=path)
    assert await plane._rollback_target(path, "old") == "old"
    with pytest.raises(ValueError, match="rollback target"):
        await plane._rollback_target(path, "new-absent")


async def test_malformed_selector_member_string_cannot_authorize_rollback(tmp_path):
    old = config()
    old["outbounds"][0]["outbounds"] = "old,direct"
    path = tmp_path / "last-good"
    path.write_text(json.dumps(old))
    clash = type("Clash", (), {"current": AsyncMock(return_value="old")})()
    plane = dataplane.SingBoxDataPlane(None, clash, config_path=path)
    with pytest.raises(ValueError, match="safe rollback selector"):
        await plane._rollback_target(path, "old")
