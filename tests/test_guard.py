"""kitewrt/guard.sh — the shell watchdog for a dead daemon.

Run for real against fake commands (iptables, curl, init scripts, uhttpd,
start-stop-daemon) on PATH: the previous version of this file only pinned
constants, and the red-team review found the guard released a VPN-on LAN to
the ISP — behaviour no constant check could see.
"""

from __future__ import annotations

import contextlib
import os
import re
import signal
import stat
import subprocess
from pathlib import Path

import pytest
from kitewrt import divert

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "kitewrt" / "guard.sh"


def _var(name: str) -> str:
    m = re.search(rf"^{name}=(\S+)$", GUARD.read_text(), re.M)
    assert m, name
    return m.group(1)


def test_guard_names_the_real_chain_and_port():
    assert _var("CHAIN") == divert.CHAIN
    assert f"{divert.CHAIN}_next" == divert.STAGING_CHAIN  # the script flushes ${CHAIN}_next
    assert int(_var("PORT_HEX"), 16) == divert.TPROXY_PORT


def test_guard_is_valid_posix_sh():
    subprocess.run(["sh", "-n", str(GUARD)], check=True)


def test_init_script_runs_the_guard_from_where_the_installer_puts_it():
    init = (ROOT / "installer" / "resources" / "kitewrt-guard.init").read_text()
    assert "/usr/lib/kitewrt/kitewrt/guard.sh" in init
    # Not an instance of the daemon's service: `kitewrt restart` (the guard's
    # own recovery) restarts every instance, which killed the guard mid-run.
    daemon_init = (ROOT / "installer" / "resources" / "kitewrt.init").read_text()
    assert "guard.sh" not in daemon_init


# --- behaviour ---------------------------------------------------------------


def _exe(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class Rig:
    def __init__(self, tmp: Path, *, vpn_on: bool, recover_ok: bool):
        self.tmp = tmp
        self.log = tmp / "calls.log"
        self.alive = tmp / "daemon-alive"  # present = /api/health answers
        bin_ = tmp / "bin"
        init = tmp / "init.d"
        procnet = tmp / "proc"
        for d in (bin_, init, procnet):
            d.mkdir()
        (procnet / "tcp").write_text("  sl  local_address rem_address   st\n")
        (procnet / "tcp6").write_text("  sl  local_address rem_address   st\n")
        self.state = tmp / "state.json"
        flag = "true" if vpn_on else "false"
        self.state.write_text(f'{{\n  "version": 4,\n  "vpn_on": {flag}\n}}\n')
        log = self.log
        _exe(
            bin_ / "iptables",
            f'echo "iptables $*" >> {log}\n'
            'case "$*" in *"-S PREROUTING"*) echo "-A PREROUTING -j kitewrt_tproxy";; esac',
        )
        _exe(bin_ / "curl", f"[ -e {self.alive} ]")
        _exe(bin_ / "logger", f'echo "logger $*" >> {log}')
        _exe(bin_ / "uhttpd", "exit 0")
        _exe(
            bin_ / "start-stop-daemon",
            f'echo "ssd $*" >> {log}\n'
            'while [ $# -gt 0 ]; do [ "$1" = -p ] && pf=$2; shift; done\n'
            'sleep 300 & echo $! > "$pf"',
        )
        _exe(init / "singbox", f'echo "singbox $1" >> {log}')
        _exe(
            init / "kitewrt",
            f'echo "kitewrt $1" >> {log}\n' + (f"touch {self.alive}" if recover_ok else ""),
        )
        self.env = {
            **os.environ,
            "PATH": f"{bin_}:{os.environ['PATH']}",
            "KITEWRT_GUARD_STATE": str(self.state),
            "KITEWRT_GUARD_EVENT": str(tmp / "guard-event"),
            "KITEWRT_GUARD_PAGE": str(tmp / "page"),
            "KITEWRT_GUARD_PAGE_PID": str(tmp / "page.pid"),
            "KITEWRT_GUARD_INIT": str(init),
            "KITEWRT_GUARD_PROCNET": str(procnet),
            "KITEWRT_GUARD_INTERVAL": "0",
            "KITEWRT_GUARD_RECOVER_SLEEP": "0",
        }

    def run(self, ticks: int) -> str:
        env = {**self.env, "KITEWRT_GUARD_MAX_TICKS": str(ticks)}
        subprocess.run(["sh", str(GUARD)], env=env, check=True, timeout=60)
        return self.log.read_text() if self.log.exists() else ""

    def event(self) -> str:
        p = self.tmp / "guard-event"
        return p.read_text() if p.exists() else ""

    def cleanup(self) -> None:
        pf = self.tmp / "page.pid"
        if pf.exists():
            with contextlib.suppress(ValueError, ProcessLookupError):
                os.kill(int(pf.read_text().strip()), signal.SIGTERM)


@pytest.fixture
def rig(tmp_path):
    rigs: list[Rig] = []

    def make(**kw) -> Rig:
        r = Rig(tmp_path, **kw)
        rigs.append(r)
        return r

    yield make
    for r in rigs:
        r.cleanup()


def test_vpn_on_and_unrecoverable_holds_the_lan_offline_and_shows_the_page(rig):
    """The red-team P1: this used to flush the capture — a VPN-on LAN went out
    to the ISP in the clear. Now it stays dark and the page offers VPN off."""
    r = rig(vpn_on=True, recover_ok=False)
    calls = r.run(ticks=3)
    assert "kitewrt restart" in calls  # tried to bring it back first
    assert "-F kitewrt_tproxy" not in calls  # NOT released
    assert "ssd" in calls and "uhttpd" in calls  # emergency page started
    assert "held offline" in r.event()
    page = (r.tmp / "page" / "index.html").read_text()
    assert "Turn the VPN off" in page


def test_vpn_off_and_unrecoverable_releases_the_lan(rig):
    r = rig(vpn_on=False, recover_ok=False)
    calls = r.run(ticks=3)
    assert "kitewrt restart" in calls
    assert "-F kitewrt_tproxy" in calls
    assert "singbox stop" in calls
    assert "ssd" not in calls
    assert "released" in r.event()


def test_a_daemon_that_comes_back_is_left_to_handle_the_rest(rig):
    r = rig(vpn_on=True, recover_ok=True)
    calls = r.run(ticks=3)
    assert "kitewrt restart" in calls
    assert "-F kitewrt_tproxy" not in calls and "ssd" not in calls
    assert "guard restarted it" in r.event()


def test_two_strikes_do_nothing(rig):
    r = rig(vpn_on=True, recover_ok=False)
    calls = r.run(ticks=2)
    assert "kitewrt restart" not in calls


def _cgi(r: Rig, **env) -> subprocess.CompletedProcess:
    r.run(ticks=3)  # brings the page (and its CGI) up
    cgi = r.tmp / "page" / "cgi-bin" / "vpn-off"
    return subprocess.run(
        ["sh", str(cgi)],
        env={**r.env, "HTTP_HOST": "192.168.8.1:8088", **env},
        capture_output=True,
        text=True,
        check=True,
    )


def test_the_page_button_turns_the_vpn_off_and_releases_the_lan(rig):
    r = rig(vpn_on=True, recover_ok=False)
    out = _cgi(r, REQUEST_METHOD="POST", HTTP_ORIGIN="http://192.168.8.1:8088")
    assert "internet works without it" in out.stdout
    assert '"vpn_on": false' in r.state.read_text()
    assert oct(r.state.stat().st_mode & 0o777) == "0o600"  # credentials file
    calls = r.log.read_text()
    assert "-F kitewrt_tproxy" in calls and "singbox stop" in calls
    assert "turned off from the guard page" in r.event()


@pytest.mark.parametrize(
    "env",
    [
        {"REQUEST_METHOD": "GET"},
        {"REQUEST_METHOD": "POST", "HTTP_ORIGIN": "https://evil.example"},
    ],
)
def test_the_page_button_refuses_gets_and_other_sites(rig, env):
    r = rig(vpn_on=True, recover_ok=False)
    out = _cgi(r, **env)
    assert "Status: 40" in out.stdout
    assert '"vpn_on": true' in r.state.read_text()


def test_sing_box_back_but_daemon_dead_does_not_claim_the_lan_is_offline(rig, tmp_path):
    """After the restart attempt sing-box listens again (the LAN works) while
    the daemon stays down: no emergency page, no release."""
    r = rig(vpn_on=True, recover_ok=False)
    tcp = tmp_path / "proc" / "tcp"
    init = tmp_path / "init.d" / "singbox"
    # The singbox init "restart" brings the tproxy listener back.
    init.write_text(
        "#!/bin/sh\n"
        f'echo "singbox $1" >> {r.log}\n'
        f'[ "$1" = restart ] && echo "  0: 00000000:1ED7 00000000:0000 0A" >> {tcp}\n'
    )
    calls = r.run(ticks=3)
    assert "singbox restart" in calls
    assert "ssd" not in calls and "-F kitewrt_tproxy" not in calls
    assert "carrying the LAN" in r.event()
