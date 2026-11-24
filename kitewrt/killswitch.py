"""Owned fail-closed guards for boot, restart and verified readiness.

The FORWARD guard protects ordinary forwarding while capture is absent, including
clock waiting and daemon shutdown. The INPUT guards block both TPROXY-marked
packets and the daemon's loopback HTTP proxy while a listener can restore an
unconfirmed cached selector. The procd launcher uses the same rules on respawn.
Readiness cleanup shares a file lock with that independent launch process.
Explicit VPN-off remains the recovery escape hatch; cancellation retains guards.
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import shlex
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

from kitewrt.process import OutputLimitError, communicate, wait_process

logger = logging.getLogger(__name__)

COMMENT = "kitewrt-killswitch"
BOOT_COMMENT = "kitewrt-boot-killswitch"
RELOAD_COMMENT = "kitewrt-reload-killswitch"
RELOAD_PROXY_COMMENT = "kitewrt-reload-local-proxy"


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
        return await wait_process(proc, proc.wait(), timeout)
    except (asyncio.TimeoutError, OutputLimitError):
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
        out, _ = await wait_process(proc, communicate(proc), timeout)
    except (asyncio.TimeoutError, OutputLimitError):
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
        out, _ = await wait_process(proc, communicate(proc), 5.0)
    except (asyncio.TimeoutError, OutputLimitError):
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


def _boot_rule() -> list[str]:
    # All forwarded IPv4, including a WAN that has not obtained a route yet.
    # INPUT (the emergency UI) and OUTPUT (NTP/DNS) remain available.
    return ["-m", "comment", "--comment", BOOT_COMMENT, "-j", "DROP"]


async def prepare_boot() -> bool:
    """Protect first, without sweeping any leftover DROP or LAN capture.

    Retain old guards until successful readiness or explicit VPN-off. A slow
    DHCP/PPPoE WAN and multi-WAN failover cannot evade this route-independent
    boot rule. Identical old copies are harmless and cleaned by sweep().
    """
    async with _get_lock():
        rc, dump = await _ipt_capture(["-t", "filter", "-S", "FORWARD"])
        first = next((line for line in dump.splitlines() if line.startswith("-A FORWARD ")), "")
        if rc == 0 and shlex.split(first)[2:] == _boot_rule():
            return True
        if await _ipt(["-I", "FORWARD", "1", *_boot_rule()]) != 0:
            logger.error("boot protection could not be installed; preserving existing capture")
            return False
        rc, dump = await _ipt_capture(["-t", "filter", "-S", "FORWARD"])
        first = next((line for line in dump.splitlines() if line.startswith("-A FORWARD ")), "")
        verified = rc == 0 and shlex.split(first)[2:] == _boot_rule()
        if not verified:
            logger.error("boot protection could not be verified; preserving existing capture")
        return verified


def _owned_guard(line: str) -> list[str] | None:
    try:
        spec = shlex.split(line)
    except ValueError:
        return None
    if spec[:2] != ["-A", "FORWARD"]:
        return None
    for i, token in enumerate(spec[:-1]):
        if token == "--comment" and spec[i + 1] in {COMMENT, BOOT_COMMENT}:
            return spec
    return None


async def sweep() -> bool:
    """Remove owned guards for explicit VPN-off or verified boot readiness.

    Return True only after a readback confirms that no owned guard remains.
    Callers retry False; startup must establish replacement protection before
    clearing stale capture, rather than unconditionally invoking this cleanup.

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
                return False
            stale = [spec for ln in dump.splitlines() if (spec := _owned_guard(ln)) is not None]
            if not stale:
                return True
            logger.warning("killswitch sweep: removing %d stranded DROP(s)", len(stale))
            delete = ["-t", "filter", "-D", *stale[0][1:]]
            if await _ipt(delete) != 0:
                logger.warning("killswitch sweep: delete failed; a leftover DROP may persist")
                return False

        logger.warning("killswitch sweep: too many stale guards; retry required")
        return False


RELOAD_LOCK_PATH = Path("/var/run/kitewrt-reload.lock")
_reload_mutex: asyncio.Lock | None = None
_reload_owner: asyncio.Task | None = None


@asynccontextmanager
async def readiness_lock():
    """Serialize readiness cleanup with the independent procd launch process.

    Held for verification/cleanup only, NEVER while waiting for a new listener:
    its launcher needs this lock before it can bind. Reentrant only in this task;
    a child task must acquire its own turn. The file carries no configuration.
    """
    global _reload_mutex, _reload_owner
    task = asyncio.current_task()
    if task is not None and _reload_owner is task:
        yield
        return
    if _reload_mutex is None:
        _reload_mutex = asyncio.Lock()
    async with _reload_mutex:
        fd = os.open(RELOAD_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            deadline = asyncio.get_running_loop().time() + 90.0
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if asyncio.get_running_loop().time() >= deadline:
                        raise TimeoutError("proxy readiness lock remained busy") from None
                    await asyncio.sleep(0.05)
            _reload_owner = task
            try:
                yield
            finally:
                _reload_owner = None
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _reload_rule(mark: int) -> list[str]:
    """Captured packets traverse INPUT even when a cached direct selector binds."""
    return [
        "-m",
        "mark",
        "--mark",
        hex(mark),
        "-m",
        "comment",
        "--comment",
        RELOAD_COMMENT,
        "-j",
        "DROP",
    ]


def _reload_proxy_rule() -> list[str]:
    return [
        "-i",
        "lo",
        "-p",
        "tcp",
        "-m",
        "tcp",
        "--dport",
        "7896",
        "-m",
        "comment",
        "--comment",
        RELOAD_PROXY_COMMENT,
        "-j",
        "DROP",
    ]


def _exact_reload(spec: list[str], mark: int) -> bool:
    value = list(spec)
    try:
        i = value.index("--mark") + 1
        number, _, mask = value[i].partition("/")
        if int(number, 0) != mark or (mask and int(mask, 0) != 0xFFFFFFFF):
            return False
        value[i] = hex(mark)
    except (ValueError, IndexError):
        return False
    return value == _reload_rule(mark)


def _input_specs(dump: str) -> list[list[str]]:
    specs = []
    for line in dump.splitlines():
        try:
            fields = shlex.split(line)
        except ValueError:
            continue
        if fields[:2] == ["-A", "INPUT"]:
            specs.append(fields[2:])
    return specs


async def prepare_reload(mark: int) -> bool:
    """Block captured INPUT before any listener may restore a stale selector."""
    async with readiness_lock(), _get_lock():
        rc, dump = await _ipt_capture(["-t", "filter", "-S", "INPUT"])
        specs = _input_specs(dump)
        if (
            rc == 0
            and len(specs) >= 2
            and _exact_reload(specs[0], mark)
            and specs[1] == _reload_proxy_rule()
        ):
            return True
        if await _ipt(["-I", "INPUT", "1", *_reload_proxy_rule()]) != 0:
            return False
        if await _ipt(["-I", "INPUT", "1", *_reload_rule(mark)]) != 0:
            return False
        rc, dump = await _ipt_capture(["-t", "filter", "-S", "INPUT"])
        specs = _input_specs(dump)
        return (
            rc == 0
            and len(specs) >= 2
            and _exact_reload(specs[0], mark)
            and specs[1] == _reload_proxy_rule()
        )


async def release_reload(mark: int) -> bool:
    """Release only our exact guards; failed cleanup must never report ready."""
    async with readiness_lock(), _get_lock():
        for _ in range(32):
            rc, dump = await _ipt_capture(["-t", "filter", "-S", "INPUT"])
            if rc != 0:
                return False
            specs = _input_specs(dump)
            owned = [
                spec for spec in specs if RELOAD_COMMENT in spec or RELOAD_PROXY_COMMENT in spec
            ]
            if not owned:
                return True
            if any(
                not _exact_reload(spec, mark) and spec != _reload_proxy_rule() for spec in owned
            ):
                logger.error("reload protection has an unexpected specification; preserving it")
                return False
            if await _ipt(["-D", "INPUT", *owned[0]]) != 0:
                return False
        return False
