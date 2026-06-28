"""Tests for SingBoxDataPlane: structural change → reload, selection → live API.

Hermetic — a fake SingBoxService (records reloads, scriptable running state)
and a fake ClashClient (records selects). No router, no sing-box.
"""

from __future__ import annotations

import asyncio

import pytest
from kitewrt.dataplane import SingBoxDataPlane, reassert_selector
from kitewrt.singbox.clash import ClashError
from kitewrt.state import ActiveServerRef, Data, DnsState, Subscription
from kitewrt.vless import Server


class FakeService:
    def __init__(self, running=False):
        self.running = running
        self.reloads = 0
        self.restart_result = (True, "")
        self.restart_results: list[tuple[bool, str]] | None = None  # per-call sequence
        self.check_result = (True, "")  # sing-box check verdict
        self.cache_drops = 0
        self.stops = 0

    async def stop(self):
        # The runtime data plane must NEVER call this (see the invariant test): a
        # clean stop removes sing-box's strict_route rules, turning the
        # fail-closed-on-crash property into a leak.
        self.stops += 1

    async def is_running(self):
        return self.running

    async def restart(self, *, after=None):
        self.reloads += 1
        if self.restart_results:
            r = self.restart_results.pop(0)
        else:
            r = self.restart_result
        self.running = r[0]
        # The selector re-assertion runs inside the kill-switch bracket on a
        # successful restart (mirrors the real service).
        if r[0] and after is not None:
            await after()
        return r

    async def check_config(self, path):
        return self.check_result

    async def drop_cache(self):
        self.cache_drops += 1


class _AllRegistered(dict):
    """A /proxies map that reports every tag as present — the fake sing-box has
    no warmup race, so outbounds are 'registered' the instant after a reload."""

    def __contains__(self, _key):
        return True


class FakeClash:
    def __init__(self):
        self.selects: list[tuple[str, str]] = []
        self.error: Exception | None = None

    async def select(self, selector, name):
        if self.error:
            raise self.error
        self.selects.append((selector, name))

    async def healthy(self):
        # Used by the post-reload force-select to wait for the API; always up
        # here so the fake doesn't sleep through the retry loop.
        return True

    async def current(self, selector):
        # The post-reload confirm reads this back; echo the last selection so a
        # successful select() confirms on the first iteration.
        return self.selects[-1][1] if self.selects else ""

    async def proxies(self):
        # Readiness poll after a reload sees all outbounds present immediately.
        return _AllRegistered()


def _server(host="de-dp-01.com", port=8443) -> Server:
    return Server(
        id=f"{host}:{port}",
        name="DE",
        country="DE",
        host=host,
        port=port,
        uuid="11111111-1111-1111-1111-111111111111",
        params={
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": "s",
            "fp": "firefox",
            "pbk": "k",
            "sid": "x",
        },
    )


def _data(servers=None, *, vpn_on=True, active=True, rules=None) -> Data:
    servers = servers if servers is not None else [_server()]
    sub = Subscription(id="sub-1", label="L", source="x", fetched_at="t", servers=servers)
    ref = (
        ActiveServerRef(subscription_id="sub-1", server_id=servers[0].id)
        if active and servers
        else None
    )
    return Data(
        subscriptions=[sub], active_server=ref, vpn_on=vpn_on, rules=rules or [], dns=DnsState()
    )


def _plane(service, clash, tmp_path):
    # reselect_delay=0: the post-reload confirm loop spins without real sleeps
    # (matters only for the clash-error retry path).
    return SingBoxDataPlane(
        service, clash, config_path=tmp_path / "config.json", reselect_delay=0.0
    )


async def test_first_apply_reloads_and_writes_config(tmp_path):
    svc, clash = FakeService(running=False), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    ok, msg = await plane.apply(_data())
    assert ok and msg == ""
    assert svc.reloads == 1  # not running → reload (start)
    # post-reload the selector is force-set to the active server (cache_file
    # could otherwise restore a stale choice over the config default).
    assert clash.selects == [("select", "sub-1/de-dp-01.com:8443")]
    assert (tmp_path / "config.json").is_file()


async def test_pure_selection_change_uses_live_switch(tmp_path):
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    # First apply establishes the structural baseline (reload).
    await plane.apply(_data(vpn_on=True))
    svc.reloads = 0
    clash.selects.clear()  # drop the baseline's post-reload force-select
    # Flip vpn off — same servers/rules, only the selection changes.
    ok, _ = await plane.apply(_data(vpn_on=False))
    assert ok
    assert svc.reloads == 0  # NO restart
    assert clash.selects == [("select", "direct")]  # live switch to direct


async def test_on_after_off_selects_active_server(tmp_path):
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    await plane.apply(_data(vpn_on=True))  # baseline
    svc.reloads = 0
    await plane.apply(_data(vpn_on=False))  # → direct
    await plane.apply(_data(vpn_on=True))  # → back to the server
    assert svc.reloads == 0
    assert clash.selects[-1] == ("select", "sub-1/de-dp-01.com:8443")


async def test_adding_a_server_is_structural_and_reloads(tmp_path):
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    await plane.apply(_data(servers=[_server()]))  # baseline
    svc.reloads = 0
    clash.selects.clear()  # drop the baseline's post-reload force-select
    # A new server changes the selector membership → structural → reload.
    two = [_server(), _server(host="fi-01.com", port=443)]
    ok, _ = await plane.apply(_data(servers=two))
    assert ok
    assert svc.reloads == 1
    # reload, not a live switch — but the selector is re-asserted to active.
    assert clash.selects == [("select", "sub-1/de-dp-01.com:8443")]


async def test_rules_change_is_structural_and_reloads(tmp_path):
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    await plane.apply(_data())  # baseline (default rules)
    svc.reloads = 0
    ok, _ = await plane.apply(_data(rules=[{"domain_suffix": ["x.com"], "outbound": "direct"}]))
    assert ok
    assert svc.reloads == 1


async def test_reload_forces_selector_to_active_server(tmp_path):
    # After a structural reload sing-box restores the selector from cache_file,
    # which can be a stale choice that overrides the config `default`. The plane
    # must re-assert the intended target so vpn-on never silently routes direct.
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    await plane.apply(_data(vpn_on=True))  # baseline reload
    svc.reloads = 0
    clash.selects.clear()
    # A rules change forces a structural reload; selector must be re-asserted.
    ok, _ = await plane.apply(_data(rules=[{"domain_suffix": ["x.com"], "outbound": "direct"}]))
    assert ok
    assert svc.reloads == 1
    assert clash.selects == [("select", "sub-1/de-dp-01.com:8443")]


async def test_clash_failure_falls_back_to_reload(tmp_path):
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    await plane.apply(_data(vpn_on=True))  # baseline: last_key set, running
    svc.reloads = 0
    clash.error = ClashError("controller down")
    # Same structural config + vpn on → a pure selection change (live switch).
    # The live switch hits the dead controller and must fall back to a reload.
    ok, msg = await plane.apply(_data(vpn_on=True))
    assert ok
    assert svc.reloads == 1


async def test_vpn_off_selects_direct_without_reload(tmp_path):
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    ok, _ = await plane.apply(_data(vpn_on=False))
    assert ok
    # Off is a pure live switch to `direct` (tun stays up); never a restart.
    assert clash.selects == [("select", "direct")]
    assert svc.reloads == 0


async def test_vpn_off_when_not_running_is_noop(tmp_path):
    # Nothing to switch if sing-box isn't up; off must not start it or error.
    svc, clash = FakeService(running=False), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    ok, _ = await plane.apply(_data(vpn_on=False))
    assert ok
    assert clash.selects == []
    assert svc.reloads == 0


async def test_vpn_on_selection_is_live_switch_no_reload(tmp_path):
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    await plane.apply(_data(vpn_on=True))  # baseline reload sets last_key
    svc.reloads = 0
    ok, _ = await plane.apply(_data(vpn_on=True))  # pure selection change
    assert ok
    assert svc.reloads == 0  # no restart — capture follows the process
    assert clash.selects  # switched live


async def test_first_apply_with_matching_disk_config_skips_reload(tmp_path):
    # sing-box already running with a config whose structure matches what we'd
    # build → seed last_key from disk → live switch, NOT a needless reload.
    import json

    from kitewrt.singbox.config import build_config

    cfg_path = tmp_path / "config.json"
    snap = _data(vpn_on=True)
    cfg_path.write_text(json.dumps(build_config(snap)))
    svc, clash = FakeService(running=True), FakeClash()
    plane = SingBoxDataPlane(svc, clash, config_path=cfg_path)

    ok, _ = await plane.apply(snap)
    assert ok
    assert svc.reloads == 0  # seeded from disk → no restart
    assert clash.selects  # switched live instead


async def test_not_running_forces_reload_even_without_structural_change(tmp_path):
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    await plane.apply(_data())  # baseline, now running
    svc.reloads = 0
    clash.selects.clear()  # drop the baseline's post-reload force-select
    svc.running = False  # sing-box died
    ok, _ = await plane.apply(_data())  # same config, but not running
    assert ok
    assert svc.reloads == 1  # reload to bring it back
    assert clash.selects == [("select", "sub-1/de-dp-01.com:8443")]  # selector re-asserted


async def test_reload_failure_reported_and_forces_next_reload(tmp_path):
    svc, clash = FakeService(running=False), FakeClash()
    svc.restart_result = (False, "config error")
    plane = _plane(svc, clash, tmp_path)
    ok, msg = await plane.apply(_data())
    assert not ok
    assert "sing-box" in msg
    # next apply must reload again (don't trust the half-applied run)
    svc.restart_result = (True, "")
    svc.running = True
    ok2, _ = await plane.apply(_data())
    assert ok2
    # First apply restarts twice (initial + cache-drop retry, both fail); second
    # apply restarts once (succeeds). 3 total.
    assert svc.reloads == 3


# --- reload validation + rollback (config safety) --------------------------


async def test_reload_rejects_invalid_config_without_touching_live(tmp_path):
    import json as _json

    from kitewrt.singbox.config import build_config

    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(_json.dumps(build_config(_data(servers=[_server()], vpn_on=True))))
    svc, clash = FakeService(running=True), FakeClash()
    plane = SingBoxDataPlane(svc, clash, config_path=cfg_path)
    svc.check_result = (False, "bad rule at $.route.rules[2]")
    # A structural change whose config sing-box would reject.
    two = _data(servers=[_server(), _server(host="fi-01.com", port=443)], vpn_on=True)
    ok, msg = await plane.apply(two)
    assert not ok and "rejected" in msg
    assert svc.reloads == 0  # never restarted
    # Live config on disk is untouched — the LAN keeps running the good config.
    assert "fi-01.com" not in cfg_path.read_text()


async def test_reload_drops_cache_and_retries_on_restart_failure(tmp_path):
    svc, clash = FakeService(running=True), FakeClash()
    svc.restart_results = [(False, "boom"), (True, "")]  # fail, then succeed
    plane = _plane(svc, clash, tmp_path)
    ok, _ = await plane.apply(_data())
    assert ok
    assert svc.cache_drops == 1  # dropped a possibly-corrupt cache before retry
    assert svc.reloads == 2


async def test_reload_restores_last_good_when_new_config_wont_start(tmp_path):
    import json as _json

    from kitewrt.singbox.config import build_config

    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(_json.dumps(build_config(_data(servers=[_server()], vpn_on=True))))
    svc, clash = FakeService(running=True), FakeClash()
    plane = SingBoxDataPlane(svc, clash, config_path=cfg_path)
    await plane.apply(_data(servers=[_server()], vpn_on=True))  # seed last_key (live switch)
    svc.reloads = 0
    # Config passes `check` but won't start (both restart attempts fail).
    svc.restart_results = [(False, "wont start"), (False, "still wont")]
    two = _data(servers=[_server(), _server(host="fi-01.com", port=443)], vpn_on=True)
    ok, _ = await plane.apply(two)
    assert not ok
    assert svc.cache_drops == 1
    # last-good restored: live config is the 1-server good one again, LAN recovers.
    assert "fi-01.com" not in cfg_path.read_text()
    assert svc.reloads == 3  # initial + cache-retry + restore-restart


async def test_reload_holds_guard_until_selector_confirmed(tmp_path):
    # The post-reload re-select is retried until clash.current reports the
    # target — so the kill-switch guard (the `after` hook) isn't lifted while
    # sing-box still sits on a stale cache-restored selector.
    class FlakyConfirm(FakeClash):
        def __init__(self):
            super().__init__()
            self.current_calls = 0

        async def current(self, selector):
            self.current_calls += 1
            if self.current_calls <= 2:
                return "direct"  # report STALE twice before the real target
            return self.selects[-1][1] if self.selects else ""

    svc, clash = FakeService(running=True), FlakyConfirm()
    plane = SingBoxDataPlane(svc, clash, config_path=tmp_path / "config.json", reselect_delay=0.0)
    ok, _ = await plane.apply(_data(vpn_on=True))
    assert ok
    assert clash.current_calls >= 3  # kept re-selecting until the target confirmed
    assert clash.selects[-1] == ("select", "sub-1/de-dp-01.com:8443")


# --- ensure_materialized (auto-select prep) --------------------------------


async def test_ensure_materialized_starts_singbox_when_down(tmp_path):
    # sing-box down (e.g. VPN off, never started) → start it so every outbound
    # is dialable for the delay-test; selector restored to direct (vpn off).
    svc, clash = FakeService(running=False), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    ok, msg = await plane.ensure_materialized(_data(vpn_on=False))
    assert ok and msg == ""
    assert svc.reloads == 1
    assert clash.selects == [("select", "direct")]
    assert (tmp_path / "config.json").is_file()


async def test_ensure_materialized_noop_when_config_current(tmp_path):
    import json

    from kitewrt.singbox.config import build_config

    cfg_path = tmp_path / "config.json"
    snap = _data(vpn_on=True)
    cfg_path.write_text(json.dumps(build_config(snap)))
    svc, clash = FakeService(running=True), FakeClash()
    plane = SingBoxDataPlane(svc, clash, config_path=cfg_path)
    ok, _ = await plane.ensure_materialized(snap)
    assert ok
    assert svc.reloads == 0  # running + disk matches → no restart blip
    assert clash.selects == []  # no reload → no re-select


async def test_ensure_materialized_reloads_when_servers_stale(tmp_path):
    import json

    from kitewrt.singbox.config import build_config

    cfg_path = tmp_path / "config.json"
    one = _data(servers=[_server()], vpn_on=True)
    cfg_path.write_text(json.dumps(build_config(one)))  # running from a 1-server config
    svc, clash = FakeService(running=True), FakeClash()
    plane = SingBoxDataPlane(svc, clash, config_path=cfg_path)
    # A second server was just added (not yet in the running process).
    two = _data(servers=[_server(), _server(host="fi-01.com", port=443)], vpn_on=True)
    ok, _ = await plane.ensure_materialized(two)
    assert ok
    assert svc.reloads == 1  # stale structure → reload to materialize the new node
    assert clash.selects == [("select", "sub-1/de-dp-01.com:8443")]  # selector re-asserted


async def test_watchdog_deps_wedged_when_clash_unhealthy(tmp_path):
    from kitewrt.dataplane import SingBoxWatchdogDeps
    from kitewrt.state import State

    state = State(tmp_path / "state.json")

    class Svc:
        async def is_running(self):
            return True

        async def restart(self):
            return (True, "")

    class HealthyClash:
        async def healthy(self):
            return True

    class WedgedClash:
        async def healthy(self):
            return False

    assert await SingBoxWatchdogDeps(state, Svc(), HealthyClash()).is_running() is True
    # process up but Clash unresponsive → treated as down (triggers recovery)
    assert await SingBoxWatchdogDeps(state, Svc(), WedgedClash()).is_running() is False


async def test_watchdog_deps_down_when_process_dead(tmp_path):
    from kitewrt.dataplane import SingBoxWatchdogDeps
    from kitewrt.state import State

    class DeadSvc:
        async def is_running(self):
            return False

        async def restart(self):
            return (True, "")

    class Clash:
        async def healthy(self):
            raise AssertionError("should not be checked when process is dead")

    deps = SingBoxWatchdogDeps(State(tmp_path / "s.json"), DeadSvc(), Clash())
    assert await deps.is_running() is False  # short-circuits before clash


async def test_watchdog_restart_reasserts_selector(tmp_path):
    # A watchdog recovery restart must re-assert the intended selector inside the
    # kill-switch bracket (like the apply pipeline does), so it doesn't come up
    # on a stale on-disk default and leak vpn-on traffic unproxied.
    from kitewrt.dataplane import SingBoxWatchdogDeps
    from kitewrt.singbox.outbound import outbound_tag
    from kitewrt.state import State

    state = State(tmp_path / "state.json")
    srv = _server()
    sub = Subscription(id="sub-1", label="x", source="https://x", fetched_at="t", servers=[srv])

    def setup(d: Data) -> None:
        d.subscriptions = [sub]
        d.active_server = ActiveServerRef(subscription_id="sub-1", server_id=srv.id)
        d.vpn_on = True

    await state.update(setup)

    svc = FakeService(running=False)
    clash = FakeClash()
    deps = SingBoxWatchdogDeps(state, svc, clash, reselect_delay=0)
    ok, _ = await deps.restart()

    assert ok
    assert clash.selects[-1] == ("select", outbound_tag("sub-1", srv.id))


async def test_watchdog_restart_reasserts_after_cache_drop(tmp_path):
    # The cache-drop retry path wipes the persisted selection; the selector must
    # still be re-asserted on the second restart.
    from kitewrt.dataplane import SingBoxWatchdogDeps
    from kitewrt.singbox.outbound import outbound_tag
    from kitewrt.state import State

    state = State(tmp_path / "state.json")
    srv = _server()
    sub = Subscription(id="sub-1", label="x", source="https://x", fetched_at="t", servers=[srv])

    def setup(d: Data) -> None:
        d.subscriptions = [sub]
        d.active_server = ActiveServerRef(subscription_id="sub-1", server_id=srv.id)
        d.vpn_on = True

    await state.update(setup)

    svc = FakeService(running=False)
    svc.restart_results = [(False, "wedged"), (True, "")]  # fail once → drop cache → ok
    clash = FakeClash()
    deps = SingBoxWatchdogDeps(state, svc, clash, reselect_delay=0)
    ok, _ = await deps.restart()

    assert ok
    assert svc.cache_drops == 1
    assert clash.selects[-1] == ("select", outbound_tag("sub-1", srv.id))


async def test_dataplane_never_stops_singbox(tmp_path):
    # Invariant: the runtime data plane NEVER calls service.stop(). A clean stop
    # removes sing-box's auto_route/strict_route rules, turning the
    # fail-closed-on-crash guarantee into a leak. The off state points the
    # selector at `direct` instead of stopping the process.
    cfg = tmp_path / "config.json"
    svc = FakeService(running=True)
    clash = FakeClash()
    plane = SingBoxDataPlane(svc, clash, config_path=str(cfg), reselect_delay=0)

    srv = _server()
    sub = Subscription(id="s1", label="x", source="https://x", fetched_at="t", servers=[srv])
    ref = ActiveServerRef(subscription_id="s1", server_id=srv.id)
    on = Data(subscriptions=[sub], active_server=ref, vpn_on=True, dns=DnsState())
    off = Data(subscriptions=[sub], active_server=ref, vpn_on=False, dns=DnsState())

    await plane.apply(on)  # structural reload
    await plane.apply(on)  # live switch (unchanged structure)
    await plane.apply(off)  # off → select `direct`
    svc.running = False
    await plane.apply(off)  # off + not running → no-op
    await plane.ensure_materialized(on)  # reload to materialize outbounds

    assert svc.stops == 0
    assert ("select", "direct") in clash.selects  # off switched, did not stop


async def test_reassert_selector_wall_clock_cap_bounds_blackout():
    # A Clash API that accepts the connection then hangs (each call slow, never
    # confirms) must not let the re-assert run all `attempts` — the wall-clock
    # cap bounds it so the kill-switch DROP can't blackout the LAN for minutes.
    calls = 0

    class SlowNeverClash:
        async def healthy(self):
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.05)
            return True

        async def select(self, selector, name):
            pass

        async def current(self, selector):
            return "never-matches"

    ok = await reassert_selector(
        SlowNeverClash(), "select", "target", attempts=1000, delay=0, max_seconds=0.1
    )
    assert ok is False
    assert calls < 100  # capped by wall-clock, nowhere near the 1000 attempts


def test_parse_rules_uses_singbox_parser():
    from kitewrt.rules import RulesParseError

    plane = SingBoxDataPlane(FakeService(), FakeClash(), config_path="/tmp/x")
    parsed = plane.parse_rules(b'[{"domain_suffix": [".example"], "outbound": "direct"}]')
    assert parsed["rules"] == [{"domain_suffix": [".example"], "outbound": "direct"}]
    assert parsed["rule_set"] == []
    with pytest.raises(RulesParseError):
        plane.parse_rules(b'[{"type": "field", "outboundTag": "direct", "ip": ["10.0.0.0/8"]}]')
