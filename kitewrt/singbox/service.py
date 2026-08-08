"""sing-box process control + config writing.

sing-box is supervised by its procd init script (/etc/init.d/singbox); kitewrt
writes config.json and start/stop/restarts the service.

**We own the LAN capture now.** Under the old `tun` inbound, auto_route
installed the policy routes for us; with a `tproxy` inbound the kernel needs to
be told which packets to hand over, and that is `kitewrt.divert`. Two ordering
rules follow, and both matter:

1. **Install the divert only after sing-box is confirmed listening.** TPROXY
   with no listening socket does not fall through — it black-holes TCP while
   ICMP keeps working, i.e. "the internet died but the router still pings".
   This took down a live router during development, because the rules went in
   after the proxy had silently failed to start.
2. **Leave the divert installed across a restart.** During the reload window
   there is no listener, so captured traffic is dropped rather than leaking to
   the ISP. That is the fail-closed property `strict_route` used to give us,
   for free — which is why restart() needs no kill-switch bracket any more.

Server switching and on/off are live Clash API calls (no restart). This service
is touched only for structural reloads (servers/rules/DNS).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import subprocess
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any

from kitewrt import divert

logger = logging.getLogger(__name__)

SINGBOX_BIN = "/usr/bin/sing-box"
SINGBOX_INIT = "/etc/init.d/singbox"
SINGBOX_PIDFILE = "/var/run/sing-box.pid"
SINGBOX_CONFIG = "/etc/sing-box/config.json"
# sing-box's persisted cache (remote rule-sets + fakeip map + selector choice).
# Mirrors config.CACHE_FILE; kept as a literal here to avoid an import cycle.
SINGBOX_CACHE = "/etc/sing-box/cache.db"

# Where we look for the tproxy listener. A tuple so tests can point it at a
# fixture instead of the real procfs.
_PROC_TCP_PATHS = ("/proc/net/tcp", "/proc/net/tcp6")

# A reload restarts the process (re-reads config, rebinds the inbounds,
# reconnects) — give it room before assuming it hung.
DEFAULT_TIMEOUT_S = 60.0


def write_config(cfg: dict[str, Any], path: str | Path = SINGBOX_CONFIG) -> None:
    """Durably write the generated sing-box config to disk (tmp → fsync →
    rename → dir fsync).

    The config carries VLESS credentials and is the data plane's source of
    truth; an unclean power-off (unplugging the router) must not leave a
    zero-length config that crash-loops sing-box on the next boot. fsync makes
    the bytes and the rename durable, not just crash-atomic.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(cfg, indent=2).encode()
    tmp = p.with_suffix(p.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        # Loop os.write: a single call may write fewer bytes than asked (e.g. a
        # partial write before ENOSPC), and fsync+rename of a truncated config
        # would crash-loop sing-box on the next boot.
        mv = memoryview(raw)
        while mv:
            mv = mv[os.write(fd, mv) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, p)
    try:
        dir_fd = os.open(p.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


class SingBoxService:
    """sing-box lifecycle via its init script, async-friendly."""

    def __init__(
        self,
        init_path: str | Path = SINGBOX_INIT,
        bin_path: str | Path = SINGBOX_BIN,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        *,
        cache_path: str | Path = SINGBOX_CACHE,
        capture_enabled: bool = False,
        listener_timeout_s: float = 15.0,
    ):
        self._init = Path(init_path)
        self._bin = Path(bin_path)
        self._cache = Path(cache_path)
        self._timeout = timeout_s
        # Off by default so unit tests (fake init script) never touch real
        # iptables; production enables it in the lifespan.
        self._capture_enabled = capture_enabled
        self._listener_timeout_s = listener_timeout_s
        self._bypass: list[str] = []

    def installed(self) -> bool:
        """True when the sing-box binary exists as a regular file."""
        return self._bin.is_file()

    async def check_config(self, path: str | Path) -> tuple[bool, str]:
        """Validate a config with `sing-box check -c <path>` before we promote
        it over the running one. Returns (ok, reason). A one-shot command that
        exits (no daemon fork), so unlike restart we can safely capture stderr
        for the actual rejection reason. With no binary (dev/CI) it's a no-op
        pass — the daemon can't validate what it can't run."""
        if not self.installed():
            return True, ""
        code, out = await _run_capture([str(self._bin), "check", "-c", str(path)], timeout_s=20.0)
        if code == 0:
            return True, ""
        return False, " ".join(out.split())[:300] or f"sing-box check exit {code}"

    async def drop_cache(self) -> None:
        """Delete sing-box's cache.db. It's derived data (remote rule-sets +
        fakeip map + selector), so dropping it just forces a re-download — but a
        *corrupt* cache.db (e.g. an unclean power-off mid-write) can wedge
        startup, and clearing it turns that brick into a self-heal. Best-effort."""
        with contextlib.suppress(OSError):
            self._cache.unlink()

    async def start(self) -> tuple[bool, str]:
        ok, msg = await self._guarded("start")
        if ok:
            await self.ensure_capture()
        return ok, msg

    async def stop(self) -> tuple[bool, str]:
        # Capture comes down FIRST. Leaving it up with no listener would
        # black-hole the LAN (TPROXY does not fall through), and an intentional
        # stop means "VPN off, egress direct" — not "no egress".
        #
        # This ordering is also why the runtime data plane must never call this
        # (see test_dataplane_never_stops_singbox): dropping the capture strands
        # the fake IPs sing-box already handed out, for up to their 600 s TTL.
        await self.remove_capture()
        return await self._invoke("stop")

    def set_bypass(self, nets: Sequence[str]) -> None:
        """CIDRs that must skip the capture — see kitewrt.divert.BYPASS_SET.
        Held here so `ensure_capture()` (called from the apply path and every
        watchdog tick) always rebuilds the set from current state."""
        self._bypass = list(nets)

    async def capture_state(self) -> bool | None:
        """Whether the LAN capture is live — True / False / **None** for
        "could not tell".

        The off-state apply path needs this to spot the black-hole hybrid
        (process up, capture gone), and its response is to recycle sing-box.
        That makes an unknown read dangerous: `iptables -w 5` exits 4 while
        another writer holds the xtables lock, so someone else's fw3 reload
        would otherwise cost a restart. Only a definite False may act. Kept on
        the service rather than reaching for `divert` directly so the data
        plane depends only on what was injected into it.
        """
        return await divert.installed_state()

    async def ensure_capture(self) -> bool:
        """Install the LAN divert, but only once sing-box is actually accepting
        connections on the tproxy port.

        Returns False without touching netfilter if the listener never appears
        — the LAN then keeps working unproxied, which is a far better failure
        than a silent black hole.
        """
        if not self._capture_enabled:
            return False
        if not await _wait_for_listener(divert.TPROXY_PORT, self._listener_timeout_s):
            logger.error(
                "sing-box is not listening on tproxy port %d; leaving the LAN "
                "capture off rather than black-holing traffic",
                divert.TPROXY_PORT,
            )
            return False
        # Uplinks are excluded from the capture; everything else is caught, so
        # a network we failed to enumerate is captured rather than silently
        # bypassed. A WAN we fail to detect *would* be captured and would kill
        # the uplink — so this reads the routing table, not interface names.
        uplinks = await detect_uplinks()
        if not uplinks:
            # No default route: we cannot tell which device is the WAN, and an
            # empty list is not the same answer as "there is no WAN".
            #
            # Installing anyway does not merely skip the exclusion. `_matches`
            # compares the chain's interface RETURNs against `{"lo", *uplinks}`,
            # so with an empty list a *correct* live chain reads as stale — the
            # install path then tears a working capture down and rebuilds it
            # without the uplink RETURN. Measured on a 5.4 kernel with the
            # default route deleted: detect_uplinks() -> [], _matches against a
            # good chain -> False, install([]) -> True, and the chain went from
            # 14 rules with RETURNs for {br-lan, lo} to 13 with only {lo}.
            # When the WAN comes back its return traffic carries the router's
            # own address, escapes the private-range RETURNs and is TPROXY'd:
            # the uplink dies until something re-derives it.
            #
            # This is the *normal* state at boot on a PPPoE or slow-DHCP WAN
            # (procd starts us at S95, the dial takes longer) and during every
            # re-dial. So leave the capture exactly as it is and report the
            # failure; the watchdog retries every 30 s.
            logger.error(
                "no default route: cannot tell which device is the WAN; "
                "leaving the LAN capture untouched rather than capturing the uplink"
            )
            return False
        return await divert.install(uplinks, bypass_nets=self._bypass, port=divert.TPROXY_PORT)

    async def remove_capture(self) -> None:
        if self._capture_enabled:
            await divert.remove(port=divert.TPROXY_PORT)

    async def restart(
        self, *, after: Callable[[], Awaitable[None]] | None = None
    ) -> tuple[bool, str]:
        """Restart sing-box. `after`, if given, runs once the restart has
        succeeded *and* the tproxy listener is back, before this returns — used
        to re-assert the selector, so success is never reported while sing-box
        is still on whatever it restored from cache_file (possibly `direct`).
        There is no kill-switch bracket around this; see `_guarded`.

        The divert is deliberately left in place for the whole restart: with no
        listener, captured traffic is dropped, so the window is fail-closed
        without any extra machinery.

        It deliberately does NOT install the capture. `apply()` owns that, and
        it knows the VPN state; restart() does not. `ensure_materialized`
        reaches here with the VPN *off* (subscription test / auto-select), and
        installing a capture there put the LAN behind a proxy the user had
        switched off — with the watchdog skipping its checks, which is how a
        crash-looping sing-box could black-hole the LAN unattended.
        """
        return await self._guarded("restart", after=after)

    async def is_running(self) -> bool:
        """Whether **our** sing-box is up — not whether any sing-box is.

        `pidof sing-box` matches by name, so a second one on the router
        satisfies it. That is not hypothetical: a lab whose exit node was also
        sing-box made the watchdog believe kitewrt's own process was alive while
        it was not, which cost a failed apply and a "capture could not be
        restored" banner. Anyone running a second instance — or leaving a stale
        one after a manual experiment — hits the same thing.

        Checked against the pidfile procd maintains for *our* init script, and
        confirmed the pid is actually alive; `pidof` stays as the fallback for a
        router where the pidfile is missing (an older install, or sing-box
        started by hand), where matching by name is still better than nothing.
        """
        # One shell command because `_run` discards stdout by design (piping it
        # would make `wait()` hang on the long-lived daemon that inherits our
        # fds), so the answer has to come back as an exit code.
        code, _ = await _run(
            ["sh", "-c", f'[ -s {SINGBOX_PIDFILE} ] && kill -0 "$(cat {SINGBOX_PIDFILE})"'],
            timeout_s=5.0,
        )
        if code == 0:
            return True
        # No pidfile at all → fall back to matching by name. An install predating
        # the `procd_set_param pidfile` line, or a sing-box someone started by
        # hand, still deserves an answer; a *stale* pidfile is handled above,
        # because `kill -0` on a dead pid fails.
        exists, _ = await _run(["sh", "-c", f"[ -s {SINGBOX_PIDFILE} ]"], timeout_s=5.0)
        if exists == 0:
            return False  # our pidfile is there and its process is gone
        code, _ = await _run(["pidof", "sing-box"], timeout_s=5.0)
        return code == 0

    async def _guarded(
        self, action: str, *, after: Callable[[], Awaitable[None]] | None = None
    ) -> tuple[bool, str]:
        """Run a start/restart, re-asserting the selector afterwards.

        There is no kill-switch bracket any more, and removing it was a fix
        rather than a simplification. The switch inserts `FORWARD -o wan -j
        DROP`; with TPROXY, captured packets are consumed in mangle/PREROUTING
        and delivered to a local socket, so they never reach FORWARD at all,
        and sing-box's own egress is OUTPUT. It could therefore only ever have
        dropped traffic the divert deliberately RETURNs — RFC1918 destinations,
        which don't egress the WAN anyway. Two iptables round-trips for no
        protection, plus the risk its own module documents of a concurrent fw3
        reload stranding the DROP.

        What actually protects the reload window now is the divert staying
        installed: with no listener behind it, captured traffic is dropped.

        `after` (the selector re-assertion) still runs on success, so a reload
        that restored a stale `direct` from cache_file is corrected before we
        report success.

        **Success means the listener came back, not that procd forked.** The
        init script exits 0 the instant procd has forked sing-box, which is
        before the config is even parsed — so a config that passes `sing-box
        check` and then FATALs at runtime was reported as a successful start.
        Measured with a rules document naming an undefined rule_set tag: the
        process died, `_reload_locked` got `ok=True` and therefore never rolled
        back to `config.json.last-good`, and the watchdog's restart also
        returned True so its failure counter reset and the `_GIVE_UP_AFTER`
        valve — the thing that removes the capture when sing-box will not come
        back — could never trip. The LAN stayed captured behind a dead listener
        indefinitely. Both safety nets were keyed on a signal that cannot
        observe the failure; this is the one place to fix that, and it covers
        every runtime start failure, not just the one that was found.
        """
        ok, msg = await self._invoke(action)
        if not ok:
            return ok, msg
        # `installed()` False means `_invoke` skipped the call entirely (tests,
        # a config-only write); there is no process to wait for.
        if self.installed() and not await _wait_for_listener(
            divert.TPROXY_PORT, self._listener_timeout_s
        ):
            return False, (
                f"sing-box {action} returned success but nothing is listening on "
                f"tproxy port {divert.TPROXY_PORT} — the process failed after procd forked it"
            )
        if after is not None:
            await after()
        return True, msg

    async def _invoke(self, action: str) -> tuple[bool, str]:
        if not self.installed():
            return True, "sing-box not installed; skipped (config still written)"
        code, err = await _run([str(self._init), action], timeout_s=self._timeout)
        if err:
            return False, err
        if code != 0:
            return False, f"sing-box {action} exit {code}"
        return True, ""


async def _wait_for_listener(port: int, timeout_s: float, *, interval_s: float = 0.5) -> bool:
    """Poll until something is listening on `port`, or give up.

    sing-box's init script returns as soon as procd has forked it, which is
    well before the inbound is bound. Installing the divert on that optimistic
    signal is what black-holed a live router: the rules went in, the listener
    never arrived, and every LAN TCP connection vanished while ICMP kept
    working. So we look for the socket itself.
    """
    deadline = asyncio.get_running_loop().time() + timeout_s
    while True:
        if await _port_is_listening(port):
            return True
        if asyncio.get_running_loop().time() >= deadline:
            return False
        await asyncio.sleep(interval_s)


async def _port_is_listening(port: int) -> bool:
    """True if a TCP listener is bound to `port` (any address).

    Reads /proc/net/tcp{,6} rather than shelling out: `netstat`/`ss` are not
    both guaranteed on OpenWrt, and this is on the startup path.
    """
    want = f"{port:04X}"
    for path in _PROC_TCP_PATHS:
        try:
            with open(path) as fh:
                next(fh, None)  # header
                for line in fh:
                    cols = line.split()
                    # local_address is host:port in hex; state 0A == LISTEN
                    if len(cols) > 3 and cols[3] == "0A" and cols[1].endswith(":" + want):
                        return True
        except OSError:
            continue
    return False


async def detect_uplinks() -> list[str]:
    """The WAN-side devices to keep OUT of the capture.

    We exclude rather than enumerate LANs. Enumerating means any network the
    list misses egresses direct while the UI reports the VPN as on — and
    nothing notices, because iptables accepts `-i` for an interface that does
    not even exist. Excluding means an unknown new bridge gets captured, which
    is the safe direction and matches what `auto_route` did.

    That inverts the risk onto *this* function: a WAN we miss gets captured,
    and mangle/PREROUTING runs before reverse-NAT, so its return packets carry
    the router's public address, escape the private-range RETURNs, and get
    TPROXY'd — the uplink dies. So this asks the routing table which devices
    actually carry default routes, rather than guessing from section names.
    Name heuristics were the previous attempt and they failed both ways: they
    hooked `network.internet` and `network.iptv`, and they silently dropped
    `lan_usb` and `lan_wisp_bridge` because those contain "usb" and "wisp".
    """
    devices: list[str] = []
    for argv in (
        ["ip", "-4", "route", "show", "default"],
        ["ip", "-6", "route", "show", "default"],
    ):
        _, out = await _run_capture(argv, timeout_s=5.0)
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                dev = parts[parts.index("dev") + 1]
                if dev and dev != "lo" and dev not in devices:
                    devices.append(dev)

    # ...and then refuse to call a LAN device an uplink, however the routing
    # table describes it. This is the one way the exclude-don't-enumerate design
    # can fail catastrophically, and it was measured doing so: with a default
    # route via `br-lan` — which `option gateway` on the lan interface, a
    # dumb-AP or router-behind-router setup, a single-NIC x86 box, a stale
    # failover route or a downstream RA all produce — the chain's first rule
    # became `-i br-lan -j RETURN` and the ENTIRE LAN was excluded. 5,000 of
    # 5,000 packets left in the clear carrying the client's own address, while
    # the API reported `capture: true`, `last_error` was empty and the dashboard
    # read "Everything leaving this LAN goes through the tunnel".
    #
    # It also never healed: `body_matches` compares the interface RETURNs
    # against `{lo, *uplinks}`, and since the uplink set *was* `{br-lan}` every
    # tick agreed the chain was perfect. A silent, permanent, self-consistent
    # failure — the worst shape this project has.
    lan = await _lan_devices()
    kept = [d for d in devices if d not in lan]
    if len(kept) != len(devices):
        logger.warning(
            "divert: ignoring default route(s) via LAN device(s) %s — a LAN "
            "device excluded from the capture would leave the whole network "
            "unproxied",
            ", ".join(sorted(set(devices) - set(kept))),
        )
    # An empty result is NOT silently permissive: `ensure_capture` refuses to
    # install at all when it has no uplinks, so the single-NIC case (LAN and WAN
    # on one device, which cannot be both captured and excluded) ends in a loud
    # refusal with the LAN working unproxied, rather than a capture that
    # excludes everything and claims to be protecting it.
    return kept


async def _lan_devices() -> set[str]:
    """Devices that carry LAN clients, per uci. Best effort by design.

    uci is asked rather than the routing table because "is this where clients
    live" is a configuration question, not a routing one. `network.lan.device`
    is the 22.03+ spelling and `.ifname` the 21.02 one; both are read, and a
    bridge answers with the bridge name (`br-lan`), which is exactly what the
    default route names.

    Deliberately NOT a name heuristic: matching on "lan" is what the previous
    version of the uplink detector did, and it failed both ways — it hooked
    `network.internet` and silently dropped `lan_usb`. This asks for one
    specific configured value instead. A router that names its client network
    something else keeps the old behaviour, which is the pre-existing risk, not
    a new one.
    """
    devices: set[str] = set()
    for opt in ("device", "ifname"):
        code, out = await _run_capture(["uci", "-q", "get", f"network.lan.{opt}"], timeout_s=5.0)
        if code == 0:
            devices.update(out.split())
    return devices


async def _run_capture(argv: list[str], timeout_s: float) -> tuple[int, str]:
    """Like `_run` but captures stdout+stderr — safe ONLY for one-shot commands
    that exit (e.g. `sing-box check`), never for the daemon-forking init script
    (whose forked child would keep the pipe open and hang communicate())."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except FileNotFoundError as exc:
        return -1, str(exc)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, f"timed out after {timeout_s:g}s"
    return proc.returncode or 0, (out or b"").decode(errors="replace")


async def _run(argv: list[str], timeout_s: float) -> tuple[int, str]:
    """Run `argv` with stdio fully discarded; return (exit_code, err_message).

    The init script forks sing-box, which inherits our fds — piping them
    would make proc.wait() block forever on the long-lived daemon. DEVNULL
    breaks the inheritance chain. Diagnostics are lost; leak protection wins.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        return -1, str(exc)
    try:
        code = await asyncio.wait_for(proc.wait(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, f"timed out after {timeout_s:g}s"
    return code, ""
