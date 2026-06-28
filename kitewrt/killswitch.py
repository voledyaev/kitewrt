"""Fail-closed firewall guard for the sing-box restart window.

When sing-box restarts (structural config change, watchdog recovery) the tun
device goes down and its auto_route policy routes disappear, then come back
once the process is up again. In that gap — typically a couple of seconds —
forwarded LAN→WAN traffic that *should* be captured into the tun is no longer
intercepted, so it falls through to the direct route and leaks to the ISP
(real IP exposed, proxied destinations bypassed, traffic unencrypted).

A sing-box *crash* is already fail-closed: strict_route means the captured
traffic has no working tunnel to take, so it's dropped. The leak is specific
to the auto_route rules being torn down on a clean restart. So we bracket every
restart with a FORWARD DROP on the WAN interface: during the gap all forwarded
internet egress is blocked instead of leaking.

When sing-box is up this DROP is inert — captured packets enter the tun before
the FORWARD egress path (sing-box's own outbound re-injects them via OUTPUT,
not FORWARD), so the rule only ever bites during the restart window.

Rules are tagged with a comment so a leftover from a SIGKILL'd daemon (whose
`finally` never ran) can be swept on the next startup.

Note this DROP is the one netfilter-resident piece of the data plane: sing-box's
auto_route/strict_route capture is policy routing (`ip rule`, iproute2), which a
firewall reload can't touch. This `iptables` DROP lives in the same legacy table
fw3 manages, so an OpenWrt `firewall reload` landing inside the brief restart
window it brackets could lift it early — a narrow, transient race (the common
WAN-flap / DHCP-renew reloads are unlikely to coincide with a restart, and the
steady state is covered by strict_route).
"""

from __future__ import annotations

import asyncio
import logging
import subprocess

logger = logging.getLogger(__name__)

COMMENT = "kitewrt-killswitch"


async def _ipt(args: list[str], timeout: float = 5.0) -> int:
    """Run `iptables <args>` with stdio discarded; return exit code (-1 on
    missing binary / timeout). Never raises."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "iptables",
            # Bare -w (wait for the xtables lock); this iptables-legacy rejects
            # the `-w <secs>` form, so no timeout value.
            "-w",
            *args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError):
        return -1
    try:
        return await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1


async def detect_wan() -> str | None:
    """Return the default-route egress interface (e.g. 'eth3'), or None.

    None when there's no default route (nothing to leak to anyway) or `ip`
    is unavailable (non-router host) — callers then skip the guard.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "ip",
            "route",
            "show",
            "default",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError):
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return None
    return _parse_default_dev(out.decode("utf-8", "replace"))


def _parse_default_dev(text: str) -> str | None:
    """Extract the egress `dev` from `ip route show default` output. Warns on
    multiple default routes (multi-WAN / an on-router VPN) — the guard covers
    only the first dev, so a misdetected WAN shouldn't be silent. Pure +
    testable."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) > 1:
        logger.warning(
            "multiple default routes (%d); kill switch guards only the first: %s",
            len(lines),
            " | ".join(lines),
        )
    toks = text.split()
    if "dev" in toks:
        i = toks.index("dev")
        if i + 1 < len(toks):
            return toks[i + 1]
    return None


def _insert_args(wan: str) -> list[str]:
    # Position 1: ahead of fw3's `ACCEPT ESTABLISHED,RELATED` (which sits near
    # the top of FORWARD), so in-flight connections are blocked too — a partial
    # kill switch that lets established flows leak is no kill switch.
    return ["-I", "FORWARD", "1", "-o", wan, "-j", "DROP", "-m", "comment", "--comment", COMMENT]


def _delete_args(wan: str) -> list[str]:
    return ["-D", "FORWARD", "-o", wan, "-j", "DROP", "-m", "comment", "--comment", COMMENT]


# Reentrancy depth. The boot reconcile (lifespan) can bracket a structural
# reload, whose service._guarded engages again — refcount so the DROP is
# inserted once at the outermost engage and removed only when the outermost
# disengages. A nested disengage must NOT lift the guard early.
#
# The apply pipeline is serialized, but the watchdog recovery restart and the
# boot reconcile run as *independent* coroutines concurrent with it — so two
# brackets really can engage/disengage at the same time. `_lock` makes each
# engage/disengage atomic (check-depth → mutate iptables → set depth), which is
# what keeps the refcount honest: without it, two coroutines could both observe
# depth==0, both insert a DROP, and the first disengage would lift the guard
# while the second restart window is still open (a real-IP leak window).
_engaged_depth = 0
_lock = asyncio.Lock()


async def engage(wan: str) -> bool:
    """Insert the fail-closed DROP (reentrant). Returns True when the DROP is in
    place — freshly inserted, or already held by an outer engage."""
    global _engaged_depth
    async with _lock:
        if _engaged_depth > 0:
            _engaged_depth += 1  # nested under an outer bracket; already dropping
            return True
        if await _ipt(_insert_args(wan)) == 0:
            _engaged_depth = 1
            logger.info("killswitch engaged on %s", wan)
            return True
        logger.warning("killswitch engage failed on %s", wan)
        return False


async def disengage(wan: str) -> None:
    """Lift the DROP — but only when the outermost bracket exits. Removes every
    copy, in case more than one slipped in."""
    global _engaged_depth
    async with _lock:
        if _engaged_depth > 1:
            _engaged_depth -= 1  # an outer bracket still wants the guard
            return
        _engaged_depth = 0
        await _delete_all(wan)


async def _delete_all(wan: str) -> None:
    """Remove every copy of the DROP. Caller holds `_lock`.

    iptables `-D` exit codes: 0 = a copy was deleted (loop again, there may be
    more); >0 = "no such rule" → all copies are gone, we're done; <0 = our
    sentinel for a timeout / xtables-lock contention / missing binary. We must
    NOT treat <0 as "done" — a single transient timeout on the first delete
    would otherwise strand the DROP and block all forwarded egress until the
    next daemon restart. So retry a bounded number of times on <0.
    """
    transient = 0
    for _ in range(16):
        rc = await _ipt(_delete_args(wan))
        if rc == 0:
            continue
        if rc < 0:
            transient += 1
            if transient >= 4:
                logger.warning(
                    "killswitch disengage: iptables delete kept failing on %s; "
                    "a leftover DROP may persist (swept on next startup)",
                    wan,
                )
                break
            continue
        break  # rc > 0: no matching rule left


async def sweep() -> None:
    """Best-effort cleanup of a leftover rule on daemon startup.

    Covers the SIGKILL case where `disengage`'s `finally` never ran and a
    DROP was left blocking all egress.
    """
    global _engaged_depth
    async with _lock:
        _engaged_depth = 0  # fresh process — clear any stale in-memory depth
        wan = await detect_wan()
        if wan:
            await _delete_all(wan)
