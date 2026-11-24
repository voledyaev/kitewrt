"""Protect captured and local-proxy traffic before a listener can restore direct."""

import asyncio
import os
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from kitewrt import killswitch
from kitewrt.singbox import service


@pytest.fixture
def kernel(monkeypatch):
    rules = [["-j", "ACCEPT"]]
    calls = []

    async def capture(args):
        return 0, "\n".join("-A INPUT " + " ".join(rule) for rule in rules)

    async def change(args):
        calls.append(args)
        if args[:3] == ["-I", "INPUT", "1"]:
            rules.insert(0, args[3:])
            return 0
        if args[:2] == ["-D", "INPUT"] and args[2:] in rules:
            rules.remove(args[2:])
            return 0
        return 1

    monkeypatch.setattr(killswitch, "_lock", None)
    monkeypatch.setattr(killswitch, "_ipt", change)
    monkeypatch.setattr(killswitch, "_ipt_capture", capture)
    return rules, calls


async def test_guard_blocks_captured_and_loopback_proxy_before_accept(kernel):
    rules, calls = kernel
    assert await killswitch.prepare_reload(0x2023)
    assert rules[:2] == [killswitch._reload_rule(0x2023), killswitch._reload_proxy_rule()]
    count = len(calls)
    assert await killswitch.prepare_reload(0x2023)
    assert len(calls) == count
    assert await killswitch.release_reload(0x2023)
    assert rules == [["-j", "ACCEPT"]]


async def test_unknown_guard_spec_is_not_deleted_or_reported_ready(kernel):
    rules, _ = kernel
    wrong = killswitch._reload_rule(0x2023)
    wrong[wrong.index("--mark") + 1] = "0x2023/0xff"
    rules.insert(0, wrong)
    assert not await killswitch.release_reload(0x2023)
    assert rules[0] == wrong


async def test_exact_guard_cleanup_preserves_vendor_rule(kernel):
    rules, _ = kernel
    vendor = ["-m", "comment", "--comment", "vendor-policy", "-j", "DROP"]
    rules.insert(0, vendor)
    assert await killswitch.prepare_reload(0x2023)
    assert await killswitch.release_reload(0x2023)
    assert rules == [vendor, ["-j", "ACCEPT"]]


@pytest.fixture
def protected_service(monkeypatch, tmp_path):
    events = []

    async def prepare(*args):
        events.append("protect")
        return True

    async def release(*args):
        events.append("release")
        return True

    svc = service.SingBoxService(bin_path=tmp_path / "absent", capture_enabled=True)

    async def invoke(action):
        events.append(action)
        return True, ""

    monkeypatch.setattr(killswitch, "prepare_reload", prepare)
    monkeypatch.setattr(killswitch, "release_reload", release)
    monkeypatch.setattr(killswitch, "prepare_boot", prepare)
    monkeypatch.setattr(killswitch, "sweep", release)
    svc._invoke = invoke
    return svc, events


async def test_selector_confirmation_precedes_guard_release(protected_service):
    svc, events = protected_service

    async def confirm():
        events.append("confirmed")

    assert (await svc.restart(after=confirm))[0]
    assert events == ["protect", "restart", "confirmed"]
    # Only the controller can verify current intent + capture and release.


async def test_failed_confirmation_stops_listener_and_retains_guard(protected_service):
    svc, events = protected_service

    async def fail():
        raise RuntimeError("no selector")

    assert not (await svc.restart(after=fail))[0]
    assert events == ["protect", "restart", "stop"]


async def test_cancelled_confirmation_keeps_persistent_guard(protected_service):
    svc, events = protected_service

    async def cancel():
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await svc.restart(after=cancel)
    assert events == ["protect", "restart"]


async def test_off_fallback_turning_on_during_teardown_retains_forward_guard(protected_service):
    svc, events = protected_service
    allow = True

    async def remove():
        nonlocal allow
        events.append("uncapture")
        allow = False
        return True

    svc.remove_capture = remove
    ok, message = await svc.stop(may_release=lambda: allow)
    assert not ok and "intent changed" in message
    assert events == ["protect", "uncapture", "stop"]


@pytest.mark.parametrize("guard_ok", [True, False])
def test_procd_launcher_cannot_exec_binary_before_guard(tmp_path, guard_ok):
    root = Path(__file__).resolve().parent.parent
    marker = tmp_path / "prepared"
    python = tmp_path / "python"
    python.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit {0 if guard_ok else 1}\n")
    python.chmod(0o755)
    binary = tmp_path / "binary"
    binary.write_text(f"#!/bin/sh\n[ -f '{marker}' ] || exit 99\necho launched-$1-$2-$3\n")
    binary.chmod(0o755)
    source = (
        (root / "kitewrt/guard.sh")
        .read_text()
        .replace("/usr/lib/kitewrt/python/bin/python3", str(python))
    )
    launcher = tmp_path / "guard.sh"
    launcher.write_text(source)
    result = subprocess.run(
        ["sh", str(launcher), "--launch-singbox", str(binary), "/synthetic/config.json"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert marker.exists()
    assert (result.returncode == 0) is guard_ok
    assert ("launched-run--c-/synthetic/config.json" in result.stdout) is guard_ok


def test_init_uses_guarded_exec_for_every_procd_respawn():
    root = Path(__file__).resolve().parent.parent
    init = (root / "installer/resources/singbox.init").read_text()
    assert (
        'procd_set_param command /bin/sh /usr/lib/kitewrt/kitewrt/guard.sh --launch-singbox "$BIN" "$CONFIG"'
        in init
    )


async def test_readiness_lock_serializes_an_independent_launcher(tmp_path):
    from kitewrt import killswitch

    marker = tmp_path / "launched"
    script = "import fcntl, pathlib, sys; f=open(sys.argv[1], 'a'); fcntl.flock(f, fcntl.LOCK_EX); pathlib.Path(sys.argv[2]).touch()"
    import sys

    # Nested cleanup must not deadlock on its own flock descriptor.
    async with killswitch.readiness_lock(), killswitch.readiness_lock():
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", script, str(killswitch.RELOAD_LOCK_PATH), str(marker)
        )
        await asyncio.sleep(0.1)
        assert not marker.exists()
    assert await asyncio.wait_for(proc.wait(), 3) == 0
    assert marker.exists()


def test_launcher_supports_firmware_python_when_managed_runtime_is_absent(tmp_path):
    root = Path(__file__).resolve().parent.parent
    fallback = tmp_path / "firmware-python"
    fallback.write_text("#!/bin/sh\nexit 0\n")
    fallback.chmod(0o755)
    script = (
        (root / "kitewrt/guard.sh")
        .read_text()
        .replace("/usr/lib/kitewrt/python/bin/python3", str(tmp_path / "absent"))
        .replace("/usr/bin/python3", str(fallback))
    )
    launcher = tmp_path / "guard.sh"
    launcher.write_text(script)
    result = subprocess.run(
        ["sh", str(launcher), "--launch-singbox", "/bin/echo", "synthetic.json"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "run -c synthetic.json"


async def test_failed_candidate_stop_keeps_capture_and_both_guards(protected_service):
    svc, events = protected_service
    svc.remove_capture = AsyncMock()
    assert (await svc.stop_protected())[0]
    assert events == ["protect", "protect", "stop"]
    svc.remove_capture.assert_not_awaited()


async def test_failed_capture_teardown_never_stops_listener_or_reports_direct(
    protected_service, monkeypatch
):
    svc, events = protected_service
    from kitewrt import divert

    monkeypatch.setattr(divert, "remove", AsyncMock(return_value=False))
    ok, message = await svc.stop(may_release=lambda: True)
    assert not ok and "capture teardown failed" in message
    assert events == ["protect"]
