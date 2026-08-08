"""Tests for SingBoxDataPlane: structural change → reload, selection → live API.

Hermetic — a fake SingBoxService (records reloads, scriptable running state)
and a fake ClashClient (records selects). No router, no sing-box.
"""

from __future__ import annotations

import asyncio

import pytest
from kitewrt.dataplane import SingBoxDataPlane, _structural_key, reassert_selector
from kitewrt.singbox.clash import ClashError
from kitewrt.singbox.config import build_config
from kitewrt.state import ActiveServerRef, Data, DnsState, Subscription, now_iso
from kitewrt.vless import Server

_ECHO = object()


class FakeService:
    def __init__(self, running=False):
        self.running = running
        self.reloads = 0
        self.restart_result = (True, "")
        self.restart_results: list[tuple[bool, str]] | None = None  # per-call sequence
        self.check_result = (True, "")  # sing-box check verdict
        self.cache_drops = 0
        self.stops = 0
        # LAN capture: the data plane must assert it on every vpn-on apply and
        # tear it down when the VPN goes off.
        self.capture_installed = False
        self.capture_calls = 0
        self.capture_removals = 0
        self.capture_result = True
        # Override to force capture_state()'s answer; _ECHO mirrors
        # capture_installed, which is what a real router does.
        self.capture_state_result = _ECHO
        self.bypass: list[str] = []

    async def ensure_capture(self):
        self.capture_calls += 1
        self.capture_installed = self.capture_result
        return self.capture_result

    async def capture_state(self):
        # None models "could not read the ruleset" (xtables lock held past our
        # wait) — the case that must NOT be treated as "no capture".
        return (
            self.capture_state_result
            if self.capture_state_result is not _ECHO
            else (self.capture_installed)
        )

    def set_bypass(self, nets):
        self.bypass = list(nets)

    async def remove_capture(self):
        self.capture_removals += 1
        self.capture_installed = False

    async def stop(self):
        # The runtime data plane must NEVER call this (see the invariant test): a
        # clean stop removes sing-box's strict_route rules, turning the
        # fail-closed-on-crash property into a leak.
        self.stops += 1

    async def is_running(self):
        return self.running

    async def restart(self, *, after=None):
        self.reloads += 1
        r = self.restart_results.pop(0) if self.restart_results else self.restart_result
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
    svc.capture_installed = True  # the intended off state: the pair is intact
    plane = _plane(svc, clash, tmp_path)
    ok, _ = await plane.apply(_data(vpn_on=False))
    assert ok
    # Off is a pure live switch to `direct` (the capture stays up); never a
    # restart -- as long as the capture really is up. See
    # test_vpn_off_recycles_singbox_when_the_capture_is_gone for when it isn't.
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
    assert svc.capture_calls == 0  # nothing running → no pair to form


async def test_vpn_off_recycles_singbox_when_the_capture_is_gone(tmp_path):
    """The LAN DNS black-hole, reproduced on the live router.

    "Off" deliberately keeps sing-box running (fake IPs outlive the toggle),
    but our own shutdown removes the capture while procd keeps sing-box alive.
    sing-box's transparent UDP sockets stay bound to the LAN resolver address
    from earlier tproxy sessions, so with the capture gone they receive client
    DNS directly and answer nothing -- dnsmasq never sees the query. Every
    daemon restart with the VPN off left that pairing in place, and this branch
    returned ok without ever asking for the capture back.
    """
    svc, clash = FakeService(running=True), FakeClash()
    svc.capture_installed = False  # what our shutdown leaves behind
    plane = _plane(svc, clash, tmp_path)
    ok, _ = await plane.apply(_data(vpn_on=False))
    assert ok
    # Recycled, because re-asserting the capture over the stale sockets was
    # measured on a real kernel and does not clear them.
    assert svc.reloads == 1
    assert svc.capture_installed


class ColdStartClash(FakeClash):
    """A Clash API that refuses connections until sing-box has warmed up.

    sing-box's init script returns as soon as procd has forked it, well before
    the API accepts connections — measured at 0.2s on an idle x86 VM with one
    outbound, and the live router has 23 plus rule-sets. Every other restart
    site re-asserts the selector through the retrying helper for exactly this
    reason.
    """

    def __init__(self, cold_ticks=3):
        super().__init__()
        self.cold = cold_ticks

    async def healthy(self):
        if self.cold:
            self.cold -= 1
            return False
        return True

    async def select(self, selector, name):
        if self.cold:
            raise ClashError("clash select failed: All connection attempts failed")
        await super().select(selector, name)


async def test_vpn_off_recycle_survives_a_cold_clash_api(tmp_path):
    """The recycle must not be aborted by the API not being up yet.

    With a bare, un-retried select here the apply died before installing the
    capture: the repair never ran, and the worst case left vpn_on=false with
    the capture live and the selector still on the proxy server — the whole
    LAN tunnelled after the user switched the VPN off.
    """
    svc, clash = FakeService(running=True), ColdStartClash(cold_ticks=3)
    svc.capture_installed = False  # the hybrid our shutdown leaves behind
    plane = _plane(svc, clash, tmp_path)
    ok, msg = await plane.apply(_data(vpn_on=False))
    assert ok, msg
    assert svc.reloads == 1
    assert svc.capture_installed  # the repair completed
    assert clash.selects[-1] == ("select", "direct")


async def test_vpn_off_does_not_recycle_on_an_unreadable_ruleset(tmp_path):
    """`iptables -w 5` exits 4 while another writer holds the xtables lock, and
    a plain list is enough to hit it. Reading that as "no capture" would recycle
    the data plane because of someone else's fw3 reload."""
    svc, clash = FakeService(running=True), FakeClash()
    svc.capture_state_result = None  # could not tell
    plane = _plane(svc, clash, tmp_path)
    ok, _ = await plane.apply(_data(vpn_on=False))
    assert ok
    assert svc.reloads == 0
    assert clash.selects == [("select", "direct")]


async def test_vpn_off_reports_a_capture_it_cannot_install(tmp_path):
    """Failing to re-form the pair must surface, not return a green ok."""
    svc, clash = FakeService(running=True), FakeClash()
    svc.capture_result = False
    plane = _plane(svc, clash, tmp_path)
    ok, msg = await plane.apply(_data(vpn_on=False))
    assert not ok
    assert "capture" in msg
    assert svc.stops == 0  # see test_dataplane_never_stops_singbox


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
    # Invariant: the runtime data plane NEVER calls service.stop().
    #
    # The reason is not the one this comment used to give (auto_route /
    # strict_route disappearing) — that was the tun inbound and it is gone. The
    # rule still holds for a different reason: `service.stop()` calls
    # `remove_capture()` first, by design, so a data-plane stop tears the
    # capture down. sing-box hands out fake IPs with a 600 s TTL and only
    # sing-box can map them back to a domain, so every client that resolved
    # anything in the last ten minutes would be left with an address routing
    # nowhere. The off state points the selector at `direct` and keeps both the
    # process and the capture — see the off-state branch of apply().
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


# --- LAN capture assertion --------------------------------------------------
#
# Every test here pins a failure that a green suite would otherwise hide: the
# VPN reports itself healthy while LAN traffic goes straight out the WAN.


async def test_capture_is_asserted_even_when_nothing_is_reloaded(tmp_path):
    """The reboot case, and the one that motivated this.

    procd starts sing-box, then the daemon. The config on disk is unchanged, so
    the structural key matches and no reload happens — meaning nothing on the
    reload path can install the capture. Without an unconditional assert the
    VPN comes up looking perfect with zero traffic proxied.
    """
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    plane._seeded, plane._last_key = True, _structural_key(build_config(_data()))

    ok, _ = await plane.apply(_data())
    assert ok
    assert svc.reloads == 0  # nothing restarted...
    assert svc.capture_calls == 1  # ...but the capture was still asserted
    assert svc.capture_installed


async def test_capture_failure_fails_the_apply(tmp_path):
    """A capture that won't install must surface, not be swallowed. Otherwise
    the UI says "VPN on" while every LAN packet egresses unproxied — no
    last_error, nothing in the logs the user will ever see."""
    svc, clash = FakeService(running=True), FakeClash()
    svc.capture_result = False
    plane = _plane(svc, clash, tmp_path)

    ok, msg = await plane.apply(_data())
    assert not ok
    assert "capture" in msg.lower() and "NOT being proxied" in msg


async def test_vpn_off_keeps_the_capture(tmp_path):
    """Turning the VPN off must NOT tear the capture down.

    sing-box hands out fake IPs with a 600 s TTL and is the only thing that can
    map them back to a domain. Removing the capture strands every client that
    resolved anything in the last ten minutes on an address that now routes
    nowhere — a guaranteed outage on each toggle, versus the rare one it was
    meant to prevent. The crash-looping-sing-box risk is covered by the
    watchdog supervising whenever the capture is up.
    """
    svc, clash = FakeService(running=True), FakeClash()
    plane = _plane(svc, clash, tmp_path)
    await plane.apply(_data())
    assert svc.capture_installed

    ok, _ = await plane.apply(_data(vpn_on=False))
    assert ok
    assert svc.capture_removals == 0
    assert svc.capture_installed
    assert clash.selects[-1][1] == "direct"


# --- watchdog capture reporting ---------------------------------------------


def _capture_deps(tmp_path):
    from kitewrt.dataplane import SingBoxWatchdogDeps
    from kitewrt.state import State

    class Svc:
        async def is_running(self):
            return True

    class Clash:
        async def healthy(self):
            return True

    state = State(tmp_path / "state.json")
    return state, SingBoxWatchdogDeps(state, Svc(), Clash())


async def test_capture_banner_is_raised_and_then_taken_down(tmp_path):
    """A self-healed capture must not leave a permanent red banner.

    The scenario this whole path exists for — `/etc/init.d/firewall restart`
    flushes mangle, one tick fails, the next succeeds — otherwise ended with
    "traffic is NOT being proxied" pinned to a fully working VPN until the
    *user* happened to trigger an apply. The watchdog's own recovery is not an
    apply, so nothing else would ever clear it.
    """
    state, deps = _capture_deps(tmp_path)

    await deps.report_capture_lost(since=now_iso())
    snap = state.snapshot()
    assert snap.last_apply is not None and snap.last_apply.ok is False
    assert "NOT being proxied" in snap.last_error

    await deps.report_capture_restored()
    snap = state.snapshot()
    assert snap.last_error == ""
    assert snap.last_apply is not None and snap.last_apply.ok is True


async def test_capture_report_does_not_clobber_a_real_apply_error(tmp_path):
    """An apply can start *and finish* inside the ~15s `ensure_capture` spends
    waiting for a listener. Its message is the one the user just asked for, so
    a report stamped before it must not overwrite it."""
    from kitewrt.state import ApplyResult

    state, deps = _capture_deps(tmp_path)
    tick_started = now_iso()
    await asyncio.sleep(0.01)

    real = "sing-box rejected the config: bad TLS server_name on 'nl-1'"

    def record_apply(d):
        d.last_apply = ApplyResult(at=now_iso(), ok=False, msg=real)
        d.last_error = real

    await state.update(record_apply)

    await deps.report_capture_lost(since=tick_started)
    assert state.snapshot().last_error == real


async def test_capture_restore_never_wipes_someone_elses_error(tmp_path):
    """The clear is guarded on our exact message, so a real apply error that
    landed while the capture was down survives the recovery."""
    from kitewrt.state import ApplyResult

    state, deps = _capture_deps(tmp_path)
    real = "clash select direct: connection refused"

    def record_apply(d):
        d.last_apply = ApplyResult(at=now_iso(), ok=False, msg=real)
        d.last_error = real

    await state.update(record_apply)

    await deps.report_capture_restored()
    assert state.snapshot().last_error == real


async def test_a_dropped_banner_write_does_not_touch_flash(tmp_path):
    """`state.update()` fsyncs the file and the directory unconditionally, so a
    guard that only lived inside `mutate` burned a durable write every 30 s for
    as long as the condition held — while showing the user nothing. On a router
    that is flash wear for no benefit."""
    state, deps = _capture_deps(tmp_path)
    path = tmp_path / "state.json"

    from kitewrt.state import ApplyResult

    since = now_iso()

    def record(d):
        d.last_apply = ApplyResult(at=since, ok=True, msg="user apply")

    await state.update(record)
    before = path.stat().st_mtime_ns

    for _ in range(5):
        assert await deps.report_capture_lost(since=since) is False
    assert path.stat().st_mtime_ns == before, "wrote state.json for a banner it never showed"


async def test_a_future_timestamp_cannot_suppress_the_banner_forever(tmp_path):
    """OpenWrt has no RTC and `sysfixtime` restores the clock from a file
    mtime, so a persisted `last_apply.at` can legitimately be in the future.
    Comparing only against the tick start would then hide a genuinely lost
    capture permanently — which is the outage this reports."""
    state, deps = _capture_deps(tmp_path)

    from kitewrt.state import ApplyResult

    def record(d):
        d.last_apply = ApplyResult(at="2099-01-01T00:00:00Z", ok=True, msg="clock was wrong")

    await state.update(record)
    assert await deps.report_capture_lost(since=now_iso()) is True
    assert "NOT being proxied" in state.snapshot().last_error


async def test_an_apply_landing_just_after_now_is_not_clobbered(tmp_path):
    """`now` is sampled before `state.update()` takes the lock and fsyncs, so a
    real apply can legitimately record a timestamp one second later. Treating
    any future `at` as a wrong clock replaced the message the user was waiting
    for ("sing-box rejected the config…") with the generic capture banner."""
    from datetime import datetime, timedelta, timezone

    from kitewrt.dataplane import _may_overwrite

    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    since = (now - timedelta(seconds=5)).strftime(fmt)

    class D:
        applying = False
        last_apply = None

    d = D()
    d.last_apply = type("A", (), {"at": (now + timedelta(seconds=1)).strftime(fmt)})()
    assert _may_overwrite(d, since, now.strftime(fmt)) is False

    # Years ahead is a stuck RTC, not an in-flight apply.
    d.last_apply = type("A", (), {"at": "2099-01-01T00:00:00Z"})()
    assert _may_overwrite(d, since, now.strftime(fmt)) is True


async def test_reloads_are_serialised_against_each_other(tmp_path):
    """`/test` and `/auto-select` call `ensure_materialized` straight from the
    route — no `applying` flag, no queue — while the apply pipeline can be
    reloading too. Both write the same staging and last-good paths and restart
    the same process, so overlapping them can promote a half-written config and
    roll back to the wrong last-good.
    """
    overlap = {"max": 0, "now": 0}

    class SlowService(FakeService):
        async def restart(self, *, after=None):
            overlap["now"] += 1
            overlap["max"] = max(overlap["max"], overlap["now"])
            await asyncio.sleep(0.05)
            overlap["now"] -= 1
            return await super().restart(after=after)

    plane = SingBoxDataPlane(
        SlowService(), FakeClash(), config_path=tmp_path / "config.json", reselect_delay=0
    )
    cfg = build_config(_data(vpn_on=False))
    await asyncio.gather(
        plane._reload(cfg, "k1", "direct"),
        plane._reload(cfg, "k1", "direct"),
        plane._reload(cfg, "k1", "direct"),
    )
    assert overlap["max"] == 1, "reloads overlapped — they share config files on disk"
