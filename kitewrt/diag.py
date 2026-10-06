"""Diagnostic snapshots, written when the data plane fails.

The outage this exists for left nothing behind: the router's log is a 512 KB
ring in RAM, and a firmware update (or any reboot) took it before anyone
looked. `state.json` survived, but by then it read `last_apply.ok: true` with an
empty error. The root cause was eventually reproduced on purpose — it could not
be read off the router.

So when the watchdog raises a fault, or the data plane gives up and runs the
LAN direct, the evidence is copied to `<base>/diag/` — on flash, and under
`/etc/kitewrt` so the installer's keep.d entry carries it across a sysupgrade.
Only the last few are kept; they are small, and written once per episode, not
per tick.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

KEEP = 5

# Read-only commands. Each is allowed to fail (a missing tool just leaves its
# section empty). No secrets: sing-box's config is listed, never printed.
_SCRIPT = r"""
section() { printf '\n===== %s =====\n' "$1"; }
section date; date; cat /proc/uptime
section "sing-box log"; logread -e sing-box 2>&1 | tail -n 150
section "kitewrt log"; logread -e kitewrtd 2>&1 | tail -n 150
section "procd"; logread -e procd 2>&1 | grep -i sing | tail -n 20
section "processes"; ps 2>&1 | grep -E 'sing-box|kitewrt|python' | grep -v grep
section "tproxy listener (port 7895 = 1ED7)"; grep -i ':1ED7 ' /proc/net/tcp /proc/net/tcp6
section "mangle"; iptables -w 5 -t mangle -S 2>&1 | grep -v -- '-A kitewrt_bypass'
section "ip rule"; ip rule 2>&1
section "sing-box files"; ls -la --full-time /etc/sing-box/ 2>&1 || ls -la /etc/sing-box/
section "rule-sets"; ls -la /etc/kitewrt/data/rulesets/ 2>&1
section "routes"; ip route 2>&1
section "conntrack"; cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max 2>&1
section "memory"; free 2>&1
"""


def diag_dir(base: str | Path) -> Path:
    return Path(base) / "diag"


async def snapshot(directory: str | Path, reason: str, *, timeout_s: float = 20.0) -> Path | None:
    """Write one snapshot; prune to the newest KEEP. Never raises."""
    try:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        proc = await asyncio.create_subprocess_exec(
            "sh",
            "-c",
            _SCRIPT,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            out = b"(snapshot timed out)\n"
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        path = d / f"{stamp}.txt"
        header = f"kitewrt diagnostic snapshot\nreason: {reason}\n".encode()
        path.write_bytes(header + (out or b""))
        os.chmod(path, 0o600)
        _prune(d)
        logger.warning("diagnostic snapshot written: %s (%s)", path, reason)
        return path
    except Exception:
        logger.warning("diagnostic snapshot failed", exc_info=True)
        return None


def _prune(d: Path) -> None:
    snaps = sorted(d.glob("*.txt"))
    for old in snaps[:-KEEP]:
        with contextlib.suppress(OSError):
            old.unlink()
