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
from kitewrt import killswitch
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


async def test_skipped_when_binary_missing(tmp_path):
    svc = _svc(tmp_path, binary=False)
    assert not svc.installed()
    for action in (svc.start, svc.stop, svc.restart):
        ok, msg = await action()
        assert ok is True
        assert "skipped" in msg.lower()


async def test_restart_ok(tmp_path):
    svc = _svc(tmp_path, init_body="exit 0")
    ok, msg = await svc.restart()
    assert ok is True and msg == ""


async def test_restart_reports_nonzero(tmp_path):
    svc = _svc(tmp_path, init_body="exit 5")
    ok, msg = await svc.restart()
    assert ok is False and "exit 5" in msg


async def test_restart_times_out(tmp_path):
    svc = _svc(tmp_path, init_body="sleep 5", timeout_s=0.3)
    ok, msg = await svc.restart()
    assert ok is False and "timed out" in msg


async def test_killswitch_off_by_default(tmp_path, monkeypatch):
    called = False

    async def tripwire():
        nonlocal called
        called = True
        return "eth3"

    monkeypatch.setattr(killswitch, "detect_wan", tripwire)
    svc = _svc(tmp_path)  # killswitch_enabled defaults False
    await svc.restart()
    assert called is False


async def test_restart_brackets_killswitch_when_enabled(tmp_path, monkeypatch):
    events: list[str] = []
    monkeypatch.setattr(killswitch, "detect_wan", _aret("eth3"))
    monkeypatch.setattr(killswitch, "engage", _arec(events, "engage", ret=True))
    monkeypatch.setattr(killswitch, "disengage", _arec(events, "disengage"))
    svc = _svc(tmp_path, killswitch_enabled=True)
    await svc.restart()
    assert events == ["engage", "disengage"]


async def test_restart_after_hook_runs_inside_killswitch_bracket(tmp_path, monkeypatch):
    # H1: the selector re-assertion must run between engage and disengage, so the
    # reload window never egresses unproxied while the DROP is lifted.
    events: list[str] = []
    monkeypatch.setattr(killswitch, "detect_wan", _aret("eth3"))
    monkeypatch.setattr(killswitch, "engage", _arec(events, "engage", ret=True))
    monkeypatch.setattr(killswitch, "disengage", _arec(events, "disengage"))
    svc = _svc(tmp_path, killswitch_enabled=True)

    async def after():
        events.append("select")

    await svc.restart(after=after)
    assert events == ["engage", "select", "disengage"]


async def test_stop_never_brackets_killswitch(tmp_path, monkeypatch):
    called = False

    async def tripwire():
        nonlocal called
        called = True
        return "eth3"

    monkeypatch.setattr(killswitch, "detect_wan", tripwire)
    svc = _svc(tmp_path, killswitch_enabled=True)
    await svc.stop()
    assert called is False


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
