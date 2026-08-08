"""Fail-closed FORWARD DROP for the window before the LAN capture exists.

Narrower than it used to be. Under the old `tun` inbound this bracketed every
sing-box restart, because a restart tore down the tun's auto_route policy routes and
forwarded traffic would fall through to the WAN in the gap.

With TPROXY that window is gone: the divert stays installed across a restart,
and with no listener behind it the kernel drops captured traffic rather than
leaking it. Captured packets are consumed in mangle/PREROUTING and delivered
to a local socket, so they never traverse FORWARD at all — a `FORWARD -o wan
-j DROP` cannot touch them.

What remains is the boot window. procd starts sing-box (START=90) and then the
daemon (START=95); the divert only goes in when the first apply runs. Until
then the LAN forwards normally, and that is the gap this covers — see
`_boot_reconcile` in kitewrt.api, its only caller.

`sweep()` also clears a DROP stranded by a SIGKILL'd daemon (the `finally`
never ran), so we never boot with egress silently blocked.
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
            # Bare -w: wait for the xtables lock, with no seconds argument.
            #
            # This once claimed the binary "rejects the `-w <secs>` form", which
            # contradicted `divert._IPT` running `iptables -w 5` on that same
            # binary. **Settled by measurement**: iptables v1.8.7 (legacy) on
            # both the lab router and the Flint 2 accepts `-w` and `-w 5`
            # alike, rc=0 for each. The old claim was simply false.
            #
            # The bare form stays anyway, and now deliberately. It is already
            # bounded — `_ipt` wraps the process in a 5 s `wait_for` and kills
            # it — so the two forms differ only in who gives up first and with
            # which code. What is NOT worth trading away is the failure
            # direction: the caller that matters here is `disengage`, running in
            # a `finally` to lift a FORWARD DROP, and an early `rc=4` there
            # leaves the LAN black-holed. Waiting is the safe way to be wrong.
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


async def _ipt_capture(args: list[str], timeout: float = 5.0) -> tuple[int, str]:
    """`iptables <args>` returning (exit code, stdout). -1 on a missing binary
    or a timeout, with empty output — so "could not read" is distinguishable
    from "read, and it was empty"."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "iptables",
            "-w",
            *args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError):
        return -1, ""
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, ""
    return proc.returncode or 0, out.decode(errors="replace")


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


# Reentrancy depth: the DROP is inserted once at the outermost engage and
# removed only when the outermost disengages, so a nested disengage cannot lift
# the guard early.
#
# The nesting this was written for is gone — `service._guarded` used to engage
# around every restart and no longer does (see the rationale in service.py for
# why the bracket was removed), leaving `_boot_reconcile` as the only caller, so
# in practice the depth is now only ever 0 or 1. Kept rather than deleted
# because `_lock` is doing the load-bearing work either way: it makes each
# engage/disengage atomic (check depth → mutate iptables → set depth), and
# without that two coroutines could both observe depth==0, both insert a DROP,
# and the first disengage would lift the guard while the second window is still
# open — a real-IP leak. Re-adding a second bracket must not silently reintroduce
# that, and the refcount is what makes it safe to.
_engaged_depth = 0
# Created lazily inside the running loop, NOT at import: on Python 3.9 (the
# OpenWrt 21.02 floor) `asyncio.Lock()` binds to the event loop at construction
# time, so building it at import — when no loop is running — would bind it to the
# wrong loop and raise "bound to a different event loop" the first time the
# daemon's loop acquires it. (3.10+ binds lazily, which masked this locally.)
_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    """The engage/disengage mutex, created on first use within the running loop."""
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


async def engage(wan: str) -> bool:
    """Insert the fail-closed DROP (reentrant). Returns True when the DROP is in
    place — freshly inserted, or already held by an outer engage."""
    global _engaged_depth
    async with _get_lock():
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
    async with _get_lock():
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

    Finds the rule by its **comment**, not by the current WAN device. Keying
    the delete on `detect_wan()` made this a no-op in the two states it exists
    for: no default route yet — the normal reading at S95 on a PPPoE or
    slow-DHCP WAN, which is exactly when the previous boot's DROP is still
    there — and a WAN that has since changed name (failover, `wan` →
    `pppoe-wan`, mwan3), where it deletes a rule that does not exist and
    reports success. Measured on a 5.4 kernel: a DROP stranded on `eth0` while
    the default route was `br-lan` survived four consecutive sweeps.

    The DROP sits at FORWARD position 1, ahead of fw3's ESTABLISHED,RELATED
    accept, so a stranded one blocks *all* forwarded LAN egress — silently,
    across daemon restarts, with the dashboard green.
    """
    global _engaged_depth
    async with _get_lock():
        _engaged_depth = 0  # fresh process — clear any stale in-memory depth
        for _ in range(16):
            rc, dump = await _ipt_capture(["-t", "filter", "-S", "FORWARD"])
            if rc != 0:
                # Could not read the chain (xtables lock held past our wait).
                # Say so rather than reporting a clean sweep: a stranded DROP
                # blocks the whole LAN and the caller is about to engage a new
                # one on top.
                logger.warning("killswitch sweep: could not read FORWARD; leftovers may persist")
                return
            stale = [
                ln for ln in dump.splitlines() if COMMENT in ln and ln.startswith("-A FORWARD")
            ]
            if not stale:
                return
            logger.warning("killswitch sweep: removing %d stranded DROP(s)", len(stale))
            delete = ["-t", "filter", *stale[0].replace("-A ", "-D ", 1).split()]
            if await _ipt(delete) != 0:
                logger.warning("killswitch sweep: delete failed; a leftover DROP may persist")
                return
