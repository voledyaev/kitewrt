"""Tests for the sing-box runtime pieces: Clash API client + service manager.

Hermetic: Clash calls go through an httpx MockTransport; the service manager
runs a fake init script (temp executable), so nothing touches a real router or
iptables (the kill switch stays off by default).
"""

from __future__ import annotations

import stat
from pathlib import Path

import httpx
import pytest
from kitewrt.singbox.clash import ClashClient, ClashError
from kitewrt.singbox.service import SingBoxService, write_config

# --- Clash client -----------------------------------------------------------


def _clash(handler) -> ClashClient:
    transport = httpx.MockTransport(handler)
    return ClashClient(httpx.AsyncClient(transport=transport))


async def test_select_puts_name_in_body_and_accepts_204():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["method"] = req.method
        seen["url"] = str(req.url)
        seen["body"] = req.content
        return httpx.Response(204)

    await _clash(handler).select("select", "sub-1/host:443")
    assert seen["method"] == "PUT"
    assert seen["url"].endswith("/proxies/select")
    assert b"sub-1/host:443" in seen["body"]


async def test_select_raises_on_non_204():
    def handler(req):
        return httpx.Response(404, text="proxy not found")

    with pytest.raises(ClashError):
        await _clash(handler).select("select", "ghost")


async def test_select_raises_on_network_error():
    def handler(req):
        raise httpx.ConnectError("connection refused")

    with pytest.raises(ClashError):
        await _clash(handler).select("select", "x")


async def test_current_returns_now():
    def handler(req):
        return httpx.Response(200, json={"now": "sub-1/de:443", "all": ["sub-1/de:443", "direct"]})

    assert await _clash(handler).current("select") == "sub-1/de:443"


async def test_healthy_true_on_200_false_on_error():
    assert await _clash(lambda r: httpx.Response(200, json={"version": "1.13"})).healthy() is True

    def boom(req):
        raise httpx.ConnectError("down")

    assert await _clash(boom).healthy() is False


# --- service manager --------------------------------------------------------


def _fake_init(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "singbox"
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


def _svc(tmp_path: Path, *, init_body="exit 0", binary=True, **kw) -> SingBoxService:
    init = _fake_init(tmp_path, init_body)
    bin_path = tmp_path / "sing-box"
    if binary:
        bin_path.write_text("#!/bin/sh\n")
        bin_path.chmod(0o755)
    return SingBoxService(init_path=init, bin_path=bin_path, **kw)


def _listener(monkeypatch, present: bool) -> None:
    """Model whether the tproxy inbound came up.

    A start/restart now only reports success once something is listening, so a
    test that wants a successful one has to say so. Left implicit, these tests
    asserted that a fork counts as a start — which is exactly the false signal
    that let a crash-on-start config keep the LAN captured behind a dead
    listener, with the rollback and the watchdog's give-up valve both inert.
    """
    from kitewrt.singbox import service as svc_mod

    async def fake_wait(port, timeout_s, *, interval_s=0.5):
        return present

    monkeypatch.setattr(svc_mod, "_wait_for_listener", fake_wait)


async def test_skipped_when_binary_missing(tmp_path):
    svc = _svc(tmp_path, binary=False)
    assert not svc.installed()
    for action in (svc.start, svc.stop, svc.restart):
        ok, msg = await action()
        assert ok is True
        assert "skipped" in msg.lower()


async def test_restart_ok(tmp_path, monkeypatch):
    _listener(monkeypatch, True)
    svc = _svc(tmp_path, init_body="exit 0")
    ok, msg = await svc.restart()
    assert ok is True and msg == ""


async def test_restart_fails_when_the_listener_never_comes_back(tmp_path, monkeypatch):
    """The init script exits 0 the instant procd has forked sing-box — before
    the config is parsed. A document that passes `sing-box check` and then
    FATALs at runtime (a rule naming an undefined rule_set tag was the measured
    case) therefore reported a successful start, which disabled both safety
    nets at once: `_reload_locked` only restores `config.json.last-good` when
    the restart failed, and the watchdog resets its failure counter on a
    successful one, so the give-up valve that removes the capture could never
    trip. The LAN stayed captured behind a dead listener indefinitely."""
    _listener(monkeypatch, False)
    svc = _svc(tmp_path, init_body="exit 0")
    ok, msg = await svc.restart()
    assert ok is False
    assert "listening" in msg


async def test_restart_reports_nonzero(tmp_path):
    svc = _svc(tmp_path, init_body="exit 5")
    ok, msg = await svc.restart()
    assert ok is False and "exit 5" in msg


async def test_restart_times_out(tmp_path):
    svc = _svc(tmp_path, init_body="sleep 5", timeout_s=0.3)
    ok, msg = await svc.restart()
    assert ok is False and "timed out" in msg


async def test_service_no_longer_touches_the_killswitch():
    """The bracket is gone, and its removal was a fix rather than a cleanup.

    The kill switch inserts `FORWARD -o wan -j DROP`. Under TPROXY, captured
    packets are consumed in mangle/PREROUTING and delivered to a local socket,
    so they never reach FORWARD; sing-box's own egress is OUTPUT. The DROP
    could only ever have bitten what the divert deliberately RETURNs — RFC1918
    destinations, which don't leave via the WAN anyway. What protects the
    reload window now is the divert staying installed with no listener behind
    it, which drops captured traffic instead of leaking it.
    """
    import inspect

    from kitewrt.singbox import service as svc_mod

    assert "killswitch" not in inspect.getsource(svc_mod)


async def test_restart_still_reasserts_the_selector(tmp_path, monkeypatch):
    """A reload restores the selector from cache_file, which can be a stale
    `direct`; re-asserting before we report success is what stops a reload from
    quietly leaving the VPN pointed at direct."""
    _listener(monkeypatch, True)
    events: list[str] = []
    svc = _svc(tmp_path)

    async def after():
        events.append("select")

    ok, _ = await svc.restart(after=after)
    assert ok
    assert events == ["select"]


def test_write_config_atomic(tmp_path):
    path = tmp_path / "sub" / "config.json"
    write_config({"log": {"level": "warn"}}, path)
    import json

    assert json.loads(path.read_text())["log"]["level"] == "warn"
    # no leftover temp file
    assert not (path.parent / "config.json.tmp").exists()


# --- check_config + drop_cache ---------------------------------------------


def _svc_with_bin(tmp_path: Path, bin_body: str) -> SingBoxService:
    init = _fake_init(tmp_path, "exit 0")
    bin_path = tmp_path / "sing-box"
    bin_path.write_text("#!/bin/sh\n" + bin_body + "\n")
    bin_path.chmod(0o755)
    return SingBoxService(init_path=init, bin_path=bin_path)


async def test_check_config_passes_when_not_installed(tmp_path):
    # No binary to validate with (dev/CI) → treat as ok rather than block.
    svc = _svc(tmp_path, binary=False)
    ok, msg = await svc.check_config(tmp_path / "c.json")
    assert ok is True and msg == ""


async def test_check_config_ok_on_exit_zero(tmp_path):
    svc = _svc_with_bin(tmp_path, "exit 0")
    ok, _ = await svc.check_config(tmp_path / "c.json")
    assert ok is True


async def test_check_config_reports_reason_on_failure(tmp_path):
    # sing-box prints the offending field to stderr and exits non-zero.
    svc = _svc_with_bin(tmp_path, 'echo "decode config: bad rule at route.rules[2]" >&2; exit 1')
    ok, msg = await svc.check_config(tmp_path / "c.json")
    assert ok is False and "bad rule" in msg


async def test_drop_cache_removes_file_idempotently(tmp_path):
    cache = tmp_path / "cache.db"
    cache.write_bytes(b"corrupt")
    svc = _svc(tmp_path, cache_path=cache)
    await svc.drop_cache()
    assert not cache.exists()
    await svc.drop_cache()  # already gone → no error


# --- helpers ----------------------------------------------------------------


def _aret(value):
    async def f():
        return value

    return f


def _arec(events: list[str], label: str, ret=None):
    async def f(*_a, **_k):
        events.append(label)
        return ret

    return f


# --- TPROXY capture lifecycle ------------------------------------------------
#
# The ordering pinned here is what stops a repeat of the outage that motivated
# this design: divert rules were installed while sing-box was not actually
# listening, and TPROXY with no listener black-holes TCP (ICMP keeps working,
# so the router still pings and the LAN looks dead for no visible reason).


async def test_port_is_listening_parses_proc_net_tcp(tmp_path, monkeypatch):
    from kitewrt.singbox import service as svc

    # state 0A == LISTEN; local_address is hex host:port
    listening = tmp_path / "tcp"
    listening.write_text(
        "  sl  local_address rem_address   st\n"
        "   0: 00000000:1EDB 00000000:0000 0A\n"  # 0x1EDB == 7899, not ours
        "   1: 0100007F:1ED7 00000000:0000 0A\n"  # 0x1ED7 == 7895
    )
    monkeypatch.setattr(svc, "_PROC_TCP_PATHS", (str(listening),), raising=False)
    assert await svc._port_is_listening(7895) is True
    assert await svc._port_is_listening(7896) is False


async def test_port_not_listening_when_socket_is_not_in_listen_state(tmp_path, monkeypatch):
    from kitewrt.singbox import service as svc

    established = tmp_path / "tcp"
    established.write_text(
        "  sl  local_address rem_address   st\n   0: 0100007F:1ED7 0100007F:9999 01\n"
    )
    monkeypatch.setattr(svc, "_PROC_TCP_PATHS", (str(established),), raising=False)
    assert await svc._port_is_listening(7895) is False


async def test_capture_is_not_installed_when_the_listener_never_appears(monkeypatch):
    """The load-bearing safety property. A failed sing-box start must leave the
    LAN unproxied, never half-captured into a port nothing answers."""
    from kitewrt import divert
    from kitewrt.singbox import service as svc

    installed: list[str] = []

    async def never(_port, _timeout, **_kw):
        return False

    async def record(dev, **_kw):
        installed.append(dev)
        return True

    monkeypatch.setattr(svc, "_wait_for_listener", never)
    monkeypatch.setattr(divert, "install", record)

    s = svc.SingBoxService(capture_enabled=True)
    assert await s.ensure_capture() is False
    assert installed == []


async def test_capture_installs_once_the_listener_is_up(monkeypatch):
    from kitewrt import divert
    from kitewrt.singbox import service as svc

    installed: list[str] = []

    async def ready(_port, _timeout, **_kw):
        return True

    async def record(dev, **_kw):
        installed.append(dev)
        return True

    async def uplinks():
        return ["eth1"]

    monkeypatch.setattr(svc, "_wait_for_listener", ready)
    monkeypatch.setattr(svc, "detect_uplinks", uplinks)
    monkeypatch.setattr(divert, "install", record)

    s = svc.SingBoxService(capture_enabled=True)
    assert await s.ensure_capture() is True
    assert installed == [["eth1"]]


async def test_capture_refuses_when_the_wan_cannot_be_identified(monkeypatch):
    """An empty uplink list is not the answer "there is no WAN".

    It is the normal reading at boot on a PPPoE or slow-DHCP WAN (procd starts
    us at S95, the dial takes longer) and during every re-dial. Installing
    anyway does not merely skip the exclusion: `_matches` compares the chain's
    interface RETURNs against `{"lo", *uplinks}`, so a *correct* live chain
    reads as stale and is torn down and rebuilt without the uplink RETURN.
    Measured on a 5.4 kernel with the default route deleted — 14 rules with
    RETURNs for {br-lan, lo} became 13 with only {lo}, and install() returned
    True. The WAN's own return traffic is then TPROXY'd and the uplink dies.
    """
    from kitewrt import divert
    from kitewrt.singbox import service as svc

    installed: list[str] = []

    async def ready(_port, _timeout, **_kw):
        return True

    async def record(dev, **_kw):
        installed.append(dev)
        return True

    async def no_default_route():
        return []

    monkeypatch.setattr(svc, "_wait_for_listener", ready)
    monkeypatch.setattr(svc, "detect_uplinks", no_default_route)
    monkeypatch.setattr(divert, "install", record)

    s = svc.SingBoxService(capture_enabled=True)
    assert await s.ensure_capture() is False
    assert installed == []  # the live capture, whatever it is, was not touched


async def test_capture_is_disabled_by_default_so_tests_never_touch_netfilter(monkeypatch):
    from kitewrt import divert
    from kitewrt.singbox import service as svc

    called: list[str] = []

    async def boom(*_a, **_kw):
        called.append("install")
        return True

    monkeypatch.setattr(divert, "install", boom)
    assert await svc.SingBoxService().ensure_capture() is False
    assert called == []


# --- uplink detection -------------------------------------------------------
#
# We exclude uplinks and capture everything else, so the risk sits here: a WAN
# we fail to spot gets captured, and mangle/PREROUTING runs before reverse-NAT
# — its return packets carry the router's public address, escape the
# private-range RETURNs, and the uplink dies.


async def _uplinks(monkeypatch, v4: str, v6: str = "", lan: str = "") -> list[str]:
    from kitewrt.singbox import service as svc

    async def fake_capture(argv, timeout_s=0.0):
        # uci is asked separately for the LAN device; answering it with the
        # route dump (which the old single-branch fake did) makes every device
        # look like a LAN device.
        if argv and argv[0] == "uci":
            return (0, lan) if lan else (1, "")
        return (0, v6 if "-6" in argv else v4)

    monkeypatch.setattr(svc, "_run_capture", fake_capture)
    return await svc.detect_uplinks()


async def test_finds_the_default_route_device(monkeypatch):
    out = "default via 192.168.1.1 dev eth1 proto static src 192.168.1.76 metric 10\n"
    assert await _uplinks(monkeypatch, out) == ["eth1"]


async def test_finds_multiple_uplinks_without_duplicates(monkeypatch):
    v4 = (
        "default via 10.0.0.1 dev eth1 metric 10\n"
        "default via 10.1.0.1 dev wwan0 metric 20\n"
        "default via 10.0.0.1 dev eth1 metric 30\n"
    )
    assert await _uplinks(monkeypatch, v4) == ["eth1", "wwan0"]


async def test_includes_ipv6_uplinks(monkeypatch):
    v4 = "default via 10.0.0.1 dev eth1\n"
    v6 = "default from ::/0 via fe80::1 dev eth2 metric 512\n"
    assert await _uplinks(monkeypatch, v4, v6) == ["eth1", "eth2"]


async def test_loopback_is_never_an_uplink(monkeypatch):
    """`lo` is excluded from the capture by a dedicated chain rule, not by
    being listed here — but a `dev lo` default route must not slip in either."""
    assert await _uplinks(monkeypatch, "default dev lo\n") == []


async def test_no_default_route_means_no_exclusions(monkeypatch):
    """A router with no uplink yet still captures the LAN; nothing to let out."""
    assert await _uplinks(monkeypatch, "") == []


async def test_is_running_ignores_someone_elses_sing_box(tmp_path, monkeypatch):
    """`pidof sing-box` matches by name, so a *second* sing-box on the router
    satisfied it. Not hypothetical: a lab whose exit node was also sing-box made
    the watchdog believe kitewrt's own process was alive while it was not,
    costing a failed apply and a "capture could not be restored" banner. Anyone
    who leaves a stale instance after a manual experiment hits the same thing."""
    from kitewrt.singbox import service as svc_mod

    calls: list[list[str]] = []

    async def fake_run(argv, timeout_s):
        calls.append(list(argv))
        joined = " ".join(argv)
        if "kill -0" in joined:
            return 1, ""  # our pidfile names a process that is gone
        if svc_mod.SINGBOX_PIDFILE in joined:
            return 0, ""  # ...but the pidfile itself is there
        return 0, ""  # `pidof` would happily find the *other* sing-box

    monkeypatch.setattr(svc_mod, "_run", fake_run)
    assert await _svc(tmp_path).is_running() is False
    assert not any(c[0] == "pidof" for c in calls), (
        "with our own pidfile present, a foreign sing-box must not count"
    )


async def test_is_running_falls_back_to_pidof_without_a_pidfile(tmp_path, monkeypatch):
    """An install predating `procd_set_param pidfile`, or a sing-box started by
    hand, still deserves an answer — matching by name beats nothing there."""
    from kitewrt.singbox import service as svc_mod

    async def fake_run(argv, timeout_s):
        joined = " ".join(argv)
        if svc_mod.SINGBOX_PIDFILE in joined:
            return 1, ""  # no pidfile at all
        return 0, ""  # pidof finds one

    monkeypatch.setattr(svc_mod, "_run", fake_run)
    assert await _svc(tmp_path).is_running() is True


async def test_a_lan_device_is_never_treated_as_an_uplink(monkeypatch):
    """The worst shape this project has: silent, permanent and self-consistent.

    A default route via `br-lan` — which `option gateway` on the lan interface,
    a dumb-AP or router-behind-router setup, a single-NIC x86 box, a stale
    failover route or a downstream RA all produce — made the chain's first rule
    `-i br-lan -j RETURN`, excluding the ENTIRE LAN. Measured: 5,000 of 5,000
    packets left in the clear carrying the client's own source address while the
    API reported `capture: true`, `last_error` was empty, and the dashboard read
    "Everything leaving this LAN goes through the tunnel". It never healed
    either — `body_matches` compares the RETURNs against `{lo, *uplinks}`, and
    the uplink set *was* `{br-lan}`, so every tick agreed the chain was perfect.
    """
    out = "default via 192.168.1.99 dev br-lan proto static metric 10\n"
    assert await _uplinks(monkeypatch, out, lan="br-lan") == []


async def test_a_stale_lan_default_route_does_not_shadow_the_real_wan(monkeypatch):
    """The commoner variant: a real WAN plus a leftover LAN default route. The
    WAN must survive; only the LAN device is dropped."""
    out = (
        "default via 10.0.0.1 dev eth1 metric 10\ndefault via 192.168.1.99 dev br-lan metric 2000\n"
    )
    assert await _uplinks(monkeypatch, out, lan="br-lan") == ["eth1"]
