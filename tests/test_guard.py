"""kitewrt/guard.sh — the shell watchdog for a dead daemon.

It hard-codes the capture's chain name and the tproxy port (it must work with
no Python at all), so pin both against the module that owns them.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from kitewrt import divert

GUARD = Path(__file__).resolve().parent.parent / "kitewrt" / "guard.sh"


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
    init = (
        Path(__file__).resolve().parent.parent / "installer" / "resources" / "kitewrt.init"
    ).read_text()
    # deploy_source uploads kitewrt/ to /usr/lib/kitewrt/kitewrt
    assert "/usr/lib/kitewrt/kitewrt/guard.sh" in init
