"""The shell-only recovery path must handle staged capture and retained boot DROP."""

import subprocess

import pytest

from tests.test_guard import GUARD, Rig, _cgi, _exe


def test_staging_capture_is_not_mistaken_for_an_uncaptured_router(tmp_path):
    rig = Rig(tmp_path, vpn_on=True, recover_ok=False)
    _exe(
        tmp_path / "bin" / "iptables",
        f'echo "iptables $*" >> {rig.log}\n'
        'case "$*" in *"-S PREROUTING"*) echo "-A PREROUTING -j kitewrt_tproxy_next";; esac',
    )
    try:
        calls = rig.run(ticks=3)
        assert "kitewrt restart" in calls
        assert "held offline" in rig.event()
        assert (tmp_path / "page" / "index.html").exists()
    finally:
        rig.cleanup()


def test_emergency_vpn_off_clears_retained_boot_drop(tmp_path):
    rig = Rig(tmp_path, vpn_on=True, recover_ok=False)
    try:
        out = _cgi(rig, REQUEST_METHOD="POST", HTTP_ORIGIN="http://192.168.8.1:8088")
        assert "internet works without it" in out.stdout
        calls = rig.log.read_text()
        assert "-D FORWARD -m comment --comment kitewrt-boot-killswitch -j DROP" in calls
        assert "singbox stop" in calls
        assert '"vpn_on": false' in rig.state.read_text()
    finally:
        rig.cleanup()


def test_release_only_deletes_canonical_owned_legacy_guard(tmp_path):
    rig = Rig(tmp_path, vpn_on=False, recover_ok=False)
    _exe(
        tmp_path / "bin" / "iptables",
        f'echo "iptables $*" >> {rig.log}\n'
        'case "$*" in\n'
        '*"-S FORWARD"*)\n'
        "echo '-A FORWARD -o eth9 -m comment --comment kitewrt-killswitch -j DROP'\n"
        "echo '-A FORWARD -o eth8 -m comment --comment vendor-policy -j DROP'\n"
        "echo '-A FORWARD -o eth7 -m comment --comment kitewrt-killswitch -j ACCEPT'\n"
        ";; esac",
    )
    subprocess.run(["sh", str(GUARD), "--release"], env=rig.env, check=True, timeout=5)
    calls = rig.log.read_text()
    assert "-D FORWARD -o eth9 -m comment --comment kitewrt-killswitch -j DROP" in calls
    assert "-D FORWARD -o eth8" not in calls
    assert "-D FORWARD -o eth7" not in calls


@pytest.mark.parametrize("listener", [False, True])
def test_retained_boot_guard_without_capture_still_gets_emergency_recovery(tmp_path, listener):
    rig = Rig(tmp_path, vpn_on=True, recover_ok=False)
    _exe(
        tmp_path / "bin" / "iptables",
        f'echo "iptables $*" >> {rig.log}\n'
        'case "$*" in *"-S FORWARD"*) '
        "echo '-A FORWARD -m comment --comment kitewrt-boot-killswitch -j DROP';; esac",
    )
    if listener:
        (tmp_path / "proc" / "tcp").write_text("  0: 00000000:1ED7 00000000:0000 0A\n")
    try:
        calls = rig.run(ticks=3)
        assert "kitewrt restart" in calls
        assert (tmp_path / "page" / "index.html").exists()
        assert "held offline" in rig.event()
    finally:
        rig.cleanup()


def test_emergency_off_write_failure_retains_protection(tmp_path):
    rig = Rig(tmp_path, vpn_on=True, recover_ok=False)
    _exe(tmp_path / "bin" / "sed", "exit 1")
    try:
        out = _cgi(rig, REQUEST_METHOD="POST", HTTP_ORIGIN="http://192.168.8.1:8088")
        assert "500 Internal Server Error" in out.stdout
        assert "remains protected" in out.stdout
        assert "singbox stop" not in rig.log.read_text()
        assert '"vpn_on": true' in rig.state.read_text()
        assert not rig.state.with_suffix(".json.guard").exists()
    finally:
        rig.cleanup()
