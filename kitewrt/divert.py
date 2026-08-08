"""LAN→sing-box capture: the netfilter + policy-routing plumbing for TPROXY.

This is what `tun` + `auto_route` used to do for us. sing-box installed the
capture itself when the inbound was a tun; with a `tproxy` inbound the kernel
hands sing-box an already-established socket instead of raw packets, and
*someone* has to tell netfilter which packets to hand over. That someone is us.

**Why we moved off tun.** Measured in a controlled lab (OpenWrt 21.02, same
kernel as the target router; iperf3, client→router→server, two runs each):

    plain kernel forwarding      5.98 / 6.42 Gb/s     100%
    tun stack=mixed              185  / 187  Mb/s       3%
    tun stack=gvisor + mtu9000   1.10 / 1.17 Gb/s      18%
    tproxy                       3.54 / 3.34 Gb/s      56%

Same sing-box binary, same outbound, same traffic — only the inbound differs.
A tun hands up raw IP packets, so the proxy must run a TCP stack in userspace
(one fd, one reader goroutine, gvisor's state machine). TPROXY lets the kernel
own TCP and hands over a socket, which is ~3x cheaper here.

**What this does NOT recover.** Anything the proxy terminates locally leaves
netfilter's `forward` chain, so hardware flow offload (MediaTek PPE and
friends) can never bind it — that is true of tun, tproxy and redirect alike.
Traffic you want offloaded must not reach the proxy at all — i.e. it has to
RETURN out of this chain before the TPROXY rules. That is what `BYPASS_SET`
below is for, driven by `bypass_address` in the rules document; see
docs/rules-format.md. The tun-era `route_exclude_address_set` expressed the
same intent by expanding a geo set into one kernel route per prefix — 21,619
of them on a real router, which took it down — and no longer exists.

## Ordering is load-bearing

**Install the rules only after sing-box is confirmed listening, and remove them
before it stops.** TPROXY with no listening socket does not fall through — it
black-holes TCP while leaving ICMP working, which looks exactly like "the
internet broke but the router still pings". This is not hypothetical: it took
down a live router during development because the rules went in after the
proxy had silently failed to start.

The same property is why the rules deliberately *stay* installed across a
sing-box restart: during the reload window the divert has no listener, so
captured traffic is dropped rather than leaking to the ISP. The restart window
is fail-closed for free, which is what `strict_route` used to give us.

Consequence to be aware of: if sing-box dies and does not come back, the LAN
stays dark until the rules are removed. `sweep()` on daemon startup clears a
set left behind by a SIGKILL'd daemon.

## A rebuild never uncaptures the LAN

Changing the capture — a new uplink, an edited `bypass_address`, an fw3 reload
that wiped our rules — does not touch the live chain. The replacement is built
in `STAGING_CHAIN` and the hook is repointed in one atomic table commit; see
that constant for the packet counts that made this necessary. The old
tear-down-then-rebuild released ~1.6 s of the LAN's real addresses to the ISP
every time.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import tempfile
import time
from collections.abc import Sequence

logger = logging.getLogger(__name__)

# install() and remove() rewrite the same chain, and the daemon runs the apply
# pipeline, the watchdog and the boot reconcile as independent coroutines. Two
# concurrent installs destroy each other: A flushes, B flushes, A creates the
# chain, B's create fails, B rolls back by deleting the chain A is still
# populating — and both end up reporting failure with no capture in place.
# Built lazily because on python 3.9 an asyncio.Lock binds to the running loop
# at construction time, and this module is imported before the loop exists.
_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


# What we last loaded into the bypass ipset, so an unchanged list isn't rebuilt
# on every 30s watchdog tick — a 15,000-network reload is ~360ms of forks and
# kernel work. Cleared by remove()/sweep(), which destroy the set: after that
# the cache would claim contents the kernel no longer has.
_loaded_bypass: tuple[str, ...] | None = None

# Whether `-m set` works here (see _supports_bypass). Only a *yes* is cached: a
# kernel doesn't lose a module, but the one person who installs kmod-ipt-ipset
# is the one who just read the warning telling them to, and caching the "no"
# would make them restart the daemon to be believed.
_bypass_supported: bool | None = None

# A bypass list the kernel refused (over `_SET_MAXELEM`, or a stale `0.0.0.0/0`
# from before the parser rejected it). Remembered so the *next* install decides
# `bypass=False` before consulting `_matches` — otherwise it asks about a chain
# we never installed, mismatches forever, and rebuilds the capture every tick
# with a ~0.9s unproxied window each time. Cleared when the list changes or a
# load succeeds, so a corrected list is retried immediately.
_bypass_rejected: tuple[str, ...] | None = None

# Monotonic time of that rejection. The memo is retried on a timer rather than
# never (every remaining cause is transient) and rather than every tick (a
# failed retry that flipped `bypass` back on would mismatch `_matches` and tear
# a working capture down for nothing).
_bypass_rejected_at: float = 0.0
_BYPASS_RETRY_S = 300.0

# Set by a forced teardown, i.e. the shutdown path — the only teardown that can
# run while an install holds the lock. Every other `remove()` takes the lock, so
# it cannot interleave at all.
#
# This replaced a generation counter that did the same job worse: a counter can
# only say "a teardown happened during *my* run", and "my run" depends on where
# the straggler sampled it — which is how it ended up covering the second half
# of the install and not the first. Every teardown the counter could detect also
# raised this latch, so it was doing nothing the latch does not, and it needed a
# `bump=False` exemption at nine call sites to avoid tripping on the install's
# own teardown. A latch is also strictly stronger: it still holds in the window
# between the check and the `-A PREROUTING` itself.
#
# One-way on purpose. The process is exiting; there is nothing to unfreeze.
_frozen = False

# Whether the in-progress install has already hooked its staging chain — i.e.
# whether the LAN is behind the *new* capture yet. Guarded by the same lock as
# the install itself, so a plain module global is enough. Read by install()'s
# blanket handler to tell the two halves of a swap apart: before the hook the
# old capture is still entirely in charge and the staging chain is scaffolding
# to throw away; after it, the new capture is live and correct and the only
# thing outstanding is retiring the old chain, which is safe to finish.
_staging_hooked = False

# The degraded list we last warned about, so a permanently-degraded router
# doesn't emit ~2,880 identical syslog lines a day.
_warned_bypass: tuple[str, ...] | None = None


def _monotonic() -> float:
    return time.monotonic()


def _forget_bypass_warning() -> None:
    global _warned_bypass
    _warned_bypass = None


def _warn_bypass_degraded(want: tuple[str, ...]) -> None:
    global _warned_bypass
    if want == _warned_bypass:
        return
    _warned_bypass = want
    logger.warning(
        "divert: bypass unavailable; %d networks will be proxied rather than sent direct",
        len(want),
    )


# The port sing-box's tproxy inbound listens on. Nothing else on the router
# should claim it.
TPROXY_PORT = 7895

# Packets accepted by the TPROXY target are marked with this, and the mark is
# what steers them into the local route table below. 0x2023 is arbitrary but
# distinctive — it must not collide with fw3/mwan3 marks.
TPROXY_MARK = 0x2023

# Route table holding the single `local default` route. TPROXY needs the
# packet to be delivered locally while keeping its original destination, and a
# `local` route in a mark-selected table is the standard way to say that.
ROUTE_TABLE = 2023

# Our own mangle chain, so install/remove is a single jump plus a flush and we
# never have to reason about other people's rules.
CHAIN = "kitewrt_tproxy"

# Where a rebuild is assembled before it takes over. The capture used to be
# rebuilt *in place* — tear down, repopulate, re-hook — which leaves the LAN
# unproxied for as long as ~14 sequential iptables fork/execs take on an A53.
#
# Measured on a 5.4 kernel under a continuous ~1950 pps from a LAN client, with
# escapes counted by a rule in filter/FORWARD and corroborated packet-for-packet
# at the far-end sink. That FORWARD count is exact, and was checked rather than
# assumed: with a correct capture up, 12 s of traffic gave 0 there while 14,000
# packets crossed — captured packets are delivered locally and never traverse
# FORWARD.
#
#     rebuild in place, 8639-net bypass    2060-2280 packets   1.06-1.17 s
#     build here, then repoint the hook            0 packets          0
#
# Over 12 controlled rebuilds the old strategy lost 25,946 of the 33,495 packets
# offered — **77.5%** — every one of which the sink saw arrive still carrying
# the LAN client's own source address. Over 72 rebuilds of the new one: zero.
#
# (An earlier harness put the old strategy at 3070-3463 packets / 1.54-1.73 s.
# The numbers above come from the larger sample and supersede it; the direction
# and the conclusion are the same.)
#
# This is not the common path — an ordinary apply returns early at `_matches`
# and does not rebuild at all — but every `firewall restart`, uplink change and
# `bypass_address` edit hits it.
STAGING_CHAIN = f"{CHAIN}_next"

# ipset of destinations that skip the proxy entirely. One `-m set` match is one
# `hash:net` lookup whose cost does not grow with the entry count (measured flat
# from 8,639 to 50,000), which is what makes a country-sized list usable: the
# tun-era equivalent expanded a geo rule-set into one kernel route per prefix —
# 21,619 of them on a real router, which took the router down. 15,000 nets here
# cost ~340 KB and a single rule.
#
# It is NOT O(1), though — the cost scales with the number of *distinct prefix
# lengths* in the set, measured on a 5.4 kernel at ~710 ns fixed plus ~66 ns per
# length, so 14 lengths cost 1,635 ns for a non-member against 790 ns for one
# length. Every proxied packet pays the full scan; a bypassed one stops early.
# On real GSO-aggregated TCP the whole effect is +4.5% router CPU per gigabyte
# versus a plain CIDR match.
#
# This is the ONLY way to keep traffic on the hardware fast path. A route rule
# with `outbound: direct` still drags the packet through sing-box; it just
# skips the proxy server. Anything the proxy terminates locally leaves
# netfilter's `forward` chain and can never be bound by the flow offload.
BYPASS_SET = "kitewrt_bypass"

# How many networks the bypass accepts. Well under hash:net's 262144 default
# ceiling, and deliberately so: loading is synchronous inside the divert lock,
# and a 250k list measures ~7s on this class of hardware — 14s when a retry
# probe reloads it. The documented use case is a country list (~15,000), so
# 65536 is 4x headroom at ~1s. `rules.py` rejects a longer one at parse time,
# where the user can still see why.
BYPASS_MAX_NETWORKS = 65536
_SET_MAXELEM = BYPASS_MAX_NETWORKS

# Throwaway names used by _supports_bypass(). Named constants because sweep()
# has to clear them too: a probe chain left behind by a lost xtables lock used
# to make every later probe answer "no ipset support", permanently.
PROBE_SET = f"{BYPASS_SET}_probe"
PROBE_CHAIN = f"{CHAIN}_probe"

# Destinations that must never be diverted. Loopback and link-local are
# obvious; the private ranges keep LAN-to-LAN traffic (and the router's own web
# UI) on the kernel path, where it is both correct and faster.
#
# 198.18.0.0/15 is deliberately ABSENT: that is the fake-IP range, and those
# connections *must* reach sing-box so it can map the synthetic address back to
# the domain. Excluding it silently breaks every proxied name.
_RESERVED = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


async def _run(argv: list[str], timeout: float = 5.0) -> tuple[int, str]:
    """Run a command, returning (exit code, stderr). -1 on timeout/OSError, so
    a missing binary or a wedged call reads as failure rather than raising."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return -1, str(exc)
    try:
        _, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "timeout"
    return proc.returncode or 0, (err or b"").decode(errors="replace").strip()


async def _capture(argv: list[str], timeout: float = 10.0) -> str | None:
    """Run a command and return its stdout, or **None** if it did not run.

    None, not "". Encoding a failure as an empty string is the single error
    convention that has produced a P0 twice: `_remove_locked` read a failed
    `iptables -S` as "there are no hooks" and reported a successful teardown
    over a fully live capture, and the fix for *that* read a failed dump as
    "the chain does not exist" and did it again. The two calls fail together,
    because both take the xtables lock — so an fw3 reload or mwan3 event makes
    them both look like a clean kernel. Every caller now has to say what it
    means by "unknown".

    The timeout has to exceed the `-w 5` lock wait below it. If it doesn't,
    lock contention reads as unknown — which `_matches` treats as "not
    installed" and answers by rebuilding a working capture, a leak window for
    no reason.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError as exc:
        logger.warning("divert: could not run %s (%s)", argv[0], exc)
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        logger.warning("divert: %s timed out after %ss", " ".join(argv), timeout)
        return None
    if proc.returncode:
        logger.warning("divert: %s exited %d", " ".join(argv), proc.returncode)
        return None
    return (out or b"").decode(errors="replace")


# `-w` makes iptables wait for the xtables lock instead of failing with rc=4.
# Without it any concurrent user of the lock — the kill switch's own delete
# loop, or an fw3 reload on a DHCP renew — makes one of our ~14 calls fail,
# which rolls the whole install back and leaves the LAN uncaptured. The kill
# switch already does this; the capture must too.
_IPT = ("iptables", "-w", "5")

# Exit codes meaning "the command did not run", as opposed to "the rule was
# rejected". 4 is iptables' resource/lock error — what a `-w 5` wait returns
# when another writer is still holding /var/run/xtables.lock — and -1 is our
# own sentinel for a timeout or a missing binary. Callers that would act
# destructively on a "no" must check for these first.
_IPT_UNAVAILABLE = frozenset({4, -1})


async def _ipt(args: list[str], timeout: float = 10.0) -> int:
    code, _ = await _run([*_IPT, *args], timeout=timeout)
    return code


async def _ip(args: list[str], timeout: float = 5.0) -> int:
    code, _ = await _run(["ip", *args], timeout=timeout)
    return code


# Captured packets are delivered *locally*, so they traverse filter/INPUT —
# not FORWARD, where forwarded LAN traffic used to go. Measured: 19 packets in
# an INPUT probe vs 0 in a FORWARD probe. That has three consequences on a
# stock OpenWrt firewall, and one rule fixes all of them:
#
#   * fw3's `syn_flood` chain sits ahead of the zone dispatch and DROPs beyond
#     ~25 new connections/sec. Every LAN client's connection setup now counts
#     against that single router-wide budget; one page load opening 30 sockets
#     can trip it. Under the tun inbound these packets never reached the chain.
#   * A zone with `input REJECT` — the stock guest/IoT config — rejects the
#     captured traffic outright, breaking exactly the networks we set out to
#     cover. Verified on a real kernel.
#   * Everything else in INPUT is per-packet work we don't need.
#
# The TPROXY target's mark survives into INPUT (verified), so accepting on it
# short-circuits all of it. It is specific: only packets our own divert marked.
_INPUT_ACCEPT_COMMENT = "kitewrt-tproxy-accept"


def _input_accept_rule(mark: int) -> list[str]:
    return [
        "-m",
        "mark",
        "--mark",
        hex(mark),
        "-m",
        "comment",
        "--comment",
        _INPUT_ACCEPT_COMMENT,
        "-j",
        "ACCEPT",
    ]


def _tproxy_rule(
    proto: str, port: int, mark: int, *, dport: str | None = None, chain: str = CHAIN
) -> list[str]:
    rule = ["-A", chain, "-p", proto]
    if dport is not None:
        rule += ["--dport", dport]
    return [*rule, "-j", "TPROXY", "--on-port", str(port), "--tproxy-mark", hex(mark)]


def _bypass_rule(chain: str = CHAIN) -> list[str]:
    return ["-A", chain, "-m", "set", "--match-set", BYPASS_SET, "dst", "-j", "RETURN"]


def _chain_rules(
    port: int,
    mark: int,
    uplinks: Sequence[str] = (),
    *,
    bypass: bool = False,
    chain: str = CHAIN,
) -> list[list[str]]:
    """The body of our mangle chain.

    The hook is unconditional — PREROUTING with no `-i` — and this chain
    decides what to let go. That is the opposite of enumerating LAN devices,
    and deliberately so: `auto_route` captured by policy routing, which is
    interface-agnostic, so a guest SSID or a VLAN added later was covered
    automatically. Enumerating means every network the list misses egresses
    direct while the UI reports the VPN as on, and nothing notices — iptables
    even accepts `-i` for an interface that doesn't exist. Excluding instead
    means an unknown new bridge is captured, which is the safe direction.

    Order is load-bearing, twice over:

    1. **Loopback first.** Router-origin traffic takes OUTPUT and is not
       captured, but loopback packets *do* traverse PREROUTING with `iif=lo`.
       Without this, the router's own DNS to 127.0.0.1 would be TPROXY'd into
       sing-box and answered with a fake IP — breaking opkg and ntpd, and
       looping, because sing-box's own `dns-local` resolves via
       /etc/resolv.conf, i.e. back through here.
    2. **Uplinks next.** mangle/PREROUTING runs before reverse-NAT, so a WAN's
       return packets still carry the router's *public* address as
       destination. Not private, so no RETURN below would catch them, and the
       uplink would die.
    3. **DNS before the private-range escapes.** LAN clients are handed the
       router as their resolver by DHCP, so their queries go to a private IP
       (192.168.x.1:53). If the RETURNs ran first every query would fall
       through to dnsmasq and out to the ISP — no fake-IP, no DNS over the
       proxy, nothing in the logs.

    Everything else that isn't headed somewhere reserved goes to TPROXY, TCP
    and UDP alike — UDP carries QUIC/HTTP3, and dropping it would quietly
    downgrade or break HTTP/3 sites.

    **And then a terminating DROP**, because TPROXY only exists for TCP and
    UDP. Without it every other IP protocol fell off the end of the chain and
    was forwarded in the clear while the UI said the VPN was on. Measured on a
    real kernel with a packet sniffer on the WAN, `vpn_on=True`, capture
    healthy: ICMP echo, GRE (47), ESP (50), 6in4 (41) and SCTP (132) all
    reached the far side carrying the LAN client's traffic. That exposes the
    destinations to the ISP, lets `traceroute` from a LAN client map the real
    path instead of the tunnel, and lets a client-run IPsec/6in4/GRE tunnel
    bypass the VPN completely. A tun inbound captured all IP protocols; this
    was a silent regression from that.

    The DROP sits last, so everything the chain already decided to let go —
    loopback, the uplinks, reserved destinations and the `bypass_address` set —
    is unaffected. Pinging a bypassed address still works; pinging a *proxied*
    one now fails, which is the honest answer, since nothing here can carry it
    through the tunnel.
    """
    rules: list[list[str]] = [["-A", chain, "-i", "lo", "-j", "RETURN"]]
    rules += [["-A", chain, "-i", dev, "-j", "RETURN"] for dev in uplinks]
    for proto in ("tcp", "udp"):
        rules.append(_tproxy_rule(proto, port, mark, dport="53", chain=chain))
    rules += [["-A", chain, "-d", net, "-j", "RETURN"] for net in _RESERVED]
    if bypass:
        # After the DNS divert on purpose. Queries still go to sing-box, so a
        # bypassed domain gets a real address from `dns-direct` rather than a
        # fake IP — a fake IP would be captured on the next packet and the
        # bypass would achieve nothing.
        rules.append(_bypass_rule(chain))
    for proto in ("tcp", "udp"):
        rules.append(_tproxy_rule(proto, port, mark, chain=chain))
    # Fail closed on everything TPROXY cannot carry. See the docstring.
    rules.append(["-A", chain, "-j", "DROP"])
    return rules


async def _supports_bypass() -> bool | None:
    """Can this router actually do `-m set --match-set`? Probed once, for real.

    `command -v ipset` is the wrong question: the userspace tool and the
    `xt_set` match come from different packages, and a router routinely has
    one without the other. Only adding the rule proves it — which is why we do
    exactly that, against a throwaway set and chain, rather than inferring.
    """
    global _bypass_supported
    if _bypass_supported:
        return True  # a kernel does not lose a module; only cache the yes

    ok = False
    if (await _run(["ipset", "create", PROBE_SET, "hash:net", "family", "inet", "-exist"]))[0] == 0:
        # `-N` fails if the chain is already there — from a probe whose cleanup
        # lost the xtables lock, or a SIGKILL mid-probe. Bailing on that let one
        # leaked chain answer "no ipset here" forever, on a box where ipset
        # works perfectly, and `sweep()` didn't clear it either. Append into
        # whatever exists instead; the flush below empties it either way.
        await _ipt(["-t", "mangle", "-N", PROBE_CHAIN])
        probe_rule = ["-t", "mangle", "-A", PROBE_CHAIN]
        probe_rule += ["-m", "set", "--match-set", PROBE_SET, "dst", "-j", "RETURN"]
        rc = await _ipt(probe_rule)
        await _ipt(["-t", "mangle", "-F", PROBE_CHAIN])
        await _ipt(["-t", "mangle", "-X", PROBE_CHAIN])
        await _run(["ipset", "destroy", PROBE_SET])
        if rc in _IPT_UNAVAILABLE:
            # The probe could not run — `iptables -w 5` exits 4 while another
            # writer holds the xtables lock, and -1 is our sentinel for a
            # timeout or a missing binary. That is not "this kernel has no
            # xt_set". Reading it as one flips `bypass` off, which mismatches
            # the live chain and rebuilds the capture WITHOUT the bypass rule —
            # measured: 15 rules / 1 --match-set became 14 / 0, 0.54 s
            # uncaptured, install() returned True. The correction on the next
            # tick costs a second teardown. Say "don't know" instead; the
            # caller leaves the capture alone.
            logger.warning("divert: could not probe ipset support (xtables lock?)")
            return None
        ok = rc == 0

    # A "no" is deliberately NOT cached: the one person who installs
    # kmod-ipt-ipset is the one who just read the warning telling them to, and
    # caching would make them restart the daemon to be believed. Re-probing
    # costs four forks, and only while degraded.
    _bypass_supported = ok
    return ok


async def _load_bypass_set(nets: Sequence[str]) -> bool:
    """(Re)build the bypass ipset from `nets`, atomically.

    Built into a temp set and swapped in, so the live set is never empty or
    half-populated while packets are being matched against it — a country list
    takes a moment to load, and a partial set means traffic that should stay on
    the fast path gets proxied instead.

    Fed through `ipset restore` rather than one `ipset add` per entry: 15,000
    forks would take minutes on a router CPU. Via a file rather than stdin,
    because `ipset restore` aborts on the first bad line and exits without
    draining its input — so a rejected script leaves a `BrokenPipeError` in an
    asyncio-internal future that nothing retrieves, and the real reason (which
    is on stderr) gets buried under its traceback. A file has no writer to
    break, and `-f` reports errors identically.
    """
    tmp = f"{BYPASS_SET}_tmp"
    path = ""
    try:
        # The fd is closed immediately and the file reopened by path in the
        # worker. Handing the fd to the executor instead leaks it whenever the
        # future is cancelled before the worker runs — measured 29 leaked fds
        # from 30 cancelled loads. mkstemp already created it 0600.
        fd, path = tempfile.mkstemp(prefix="kitewrt-ipset-", suffix=".restore")
        os.close(fd)
        await asyncio.get_event_loop().run_in_executor(None, _write_script, path, nets, tmp)
        code, err = await _run(["ipset", "restore", "-f", path], timeout=60.0)
    except OSError as exc:
        # /tmp is tmpfs on OpenWrt and filling it is routine. This used to
        # escape install() entirely — *after* the teardown had already removed
        # the previous capture — leaving the LAN unproxied with no banner,
        # because the watchdog's blanket handler doesn't report capture loss.
        logger.error("divert: could not stage the bypass set (%s)", exc)
        code, err = -1, str(exc)
    finally:
        if path:
            with contextlib.suppress(OSError):
                os.unlink(path)

    if code != 0:
        logger.error("divert: could not load the bypass set (%s)", err[:200])
        # `ipset restore` aborts before its own `destroy`, stranding the temp
        # set — 7.3 MB of kernel memory for an over-capacity list, held until
        # the next remove().
        await _run(["ipset", "destroy", tmp])
        return False
    logger.info("divert: bypass set holds %d networks", len(nets))
    return True


def _write_script(path: str, nets: Sequence[str], tmp: str) -> None:
    """Build *and* write the restore script off the event loop.

    Only the `open()`/`write()` used to run here; the script itself was still
    assembled on the loop — one f-string per network plus a `"\\n".join` over
    the lot, which is where the time actually goes. Measured stall of the event
    loop, from the caller's side: 9.6 ms at 0 networks, 37.9 ms at 8,639,
    **203.5 ms at 50,000**. A 200 ms stall drops four metrics frames and shows
    up as a visibly stalled dashboard.

    Streamed line by line rather than joined, so the few-MB script never exists
    as a single string in the first place.
    """
    with open(path, "w") as fh:
        fh.write(f"create {tmp} hash:net family inet maxelem {_SET_MAXELEM} -exist\n")
        fh.write(f"flush {tmp}\n")
        for n in nets:
            fh.write(f"add {tmp} {n}\n")
        fh.write(f"create {BYPASS_SET} hash:net family inet maxelem {_SET_MAXELEM} -exist\n")
        fh.write(f"swap {tmp} {BYPASS_SET}\n")
        fh.write(f"destroy {tmp}\n")


async def installed_state() -> bool | None:
    """Whether a PREROUTING jump into our chain is present — or **None** when
    we could not find out.

    Reads the ruleset rather than asking `-C`: like `-D`, `-C` matches on the
    *whole* rule spec, so a partial spec answers "no" for a capture that is
    fully installed — the same trap that made teardown silently fail, verified
    on a real kernel. (The original spec carried `-i <lan device>`; the hook is
    unconditional now, but matching the whole spec is still the rule, and the
    chain's own rules certainly do carry matches.)

    Kept separate from `is_installed()` because the two questions have very
    different costs of being wrong. "Is there a capture worth supervising?" can
    safely read unknown as no. "Should I recycle the sing-box process?" cannot:
    `iptables -w 5` exits 4 when another writer holds the xtables lock past the
    wait, and a plain *list* is enough to hit it — measured on a real kernel, a
    12 s lock hold makes this report False over a fully live capture. Collapsing
    that to False costs a needless sing-box restart, and because the capture
    stays up across one, that is a LAN blackout caused by someone else's fw3
    reload.
    """
    dump = await _capture([*_IPT, "-t", "mangle", "-S", "PREROUTING"])
    if dump is None:
        return None
    return bool(parse_hooks(dump))


async def is_installed() -> bool:
    """True if a PREROUTING jump into our chain is present.

    Unknown reads as "not installed": this caller uses it to decide whether
    sing-box is worth supervising, and erring toward "no capture" only costs a
    redundant teardown, while erring the other way makes the watchdog guard
    something that may not be there. Callers that would *act destructively* on
    a False must use `installed_state()` and ignore None instead.
    """
    return await installed_state() is True


async def install(
    uplinks: Sequence[str] = (),
    *,
    bypass_nets: Sequence[str] = (),
    port: int = TPROXY_PORT,
    mark: int = TPROXY_MARK,
) -> bool:
    """Install the capture. Returns False (and leaves nothing behind) on failure.

    Caller MUST have confirmed sing-box is listening on `port` first — see the
    module docstring.

    `uplinks` are the WAN-side devices to let through untouched — see
    `_chain_rules` for why hooking one would kill the uplink. Everything else
    arriving on any interface is captured; router-origin traffic takes OUTPUT
    and is never seen here, so the daemon reaches the proxy through sing-box's
    loopback proxy inbound instead, which is explicit rather than accidental.

    Never raises. Every caller treats this as a bool, and the watchdog's
    blanket exception handler does *not* report a lost capture — so an
    exception escaping here reads as "some tick failed" while the LAN sits
    unproxied behind a green dashboard.
    """
    async with _get_lock():
        try:
            return await _install_locked(uplinks, bypass_nets, port, mark)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("divert: install failed unexpectedly")
            # INSIDE the lock. The handler used to sit outside `async with`,
            # which had already exited by the time it ran — so the rollback's
            # `_remove_locked` (which takes no lock, by contract) executed
            # concurrently with the next queued install. Traced on a real
            # kernel: the rollback's `-F`/`ip rule del` interleaved with the
            # other install's build, leaving a 5-rule chain, a live hook and no
            # fwmark route, with `install()` returning True. That is precisely
            # the corruption the lock's own comment says it exists to prevent.
            #
            # Never a full teardown. Nothing is torn down before the swap any
            # more, so at the moment of an exception one of the two captures is
            # always live and whole: before the hook it is the old one (throw
            # the scaffolding away), after it the new one (finish retiring the
            # old chain). Rolling back with `_remove_locked` here would turn a
            # transient error — a `RuntimeError: can't start new thread` from
            # the executor on a memory-starved router is the realistic one —
            # into an unproxied LAN, which is precisely what the pre-hitless
            # version did.
            with contextlib.suppress(Exception):
                if _staging_hooked:
                    await _finish_swap()
                else:
                    await _discard_staging()
            return False


async def _install_locked(
    uplinks: Sequence[str], bypass_nets: Sequence[str], port: int, mark: int
) -> bool:
    global _loaded_bypass, _bypass_rejected, _bypass_rejected_at

    global _staging_hooked
    _staging_hooked = False

    if _frozen:
        logger.warning("divert: capture is frozen (shutting down); refusing to install")
        return False

    want = tuple(bypass_nets)
    # Decided up front, never mid-function: `_matches` has to be asked about
    # the chain we are actually going to install. Ask about the other one and
    # it mismatches forever, so every apply and every 30s tick tears a working
    # capture down and rebuilds it — measured at ~0.9s of fail-OPEN, unproxied
    # LAN per tick, with install() returning True and the dashboard green.
    #
    # Degrading rather than failing is deliberate: a router without xt_set, or
    # a list the kernel won't take, loses the optimisation and keeps the VPN.
    # Failing would take the whole LAN offline over a performance feature,
    # which is neither what the docs nor the installer promise.
    supported = await _supports_bypass() if want else False
    if supported is None:
        logger.warning("divert: cannot tell whether ipset is usable; leaving the capture untouched")
        return False
    bypass = bool(want) and supported
    if bypass and want == _bypass_rejected:
        # A load of this exact list failed before. Every cause that can still
        # reach here is transient — a momentarily full /tmp, an `ipset` timeout
        # — because `0.0.0.0/0` and an over-capacity list are rejected at parse
        # time. So retry, but on a timer: probe the load *before* committing to
        # `bypass=True`, because a failed probe that flipped it on would
        # mismatch `_matches` and tear the capture down for nothing.
        if _monotonic() - _bypass_rejected_at < _BYPASS_RETRY_S:
            bypass = False
        elif await _load_bypass_set(want):
            _bypass_rejected = None
        else:
            _bypass_rejected_at = _monotonic()
            bypass = False
    if want and not bypass:
        _warn_bypass_degraded(want)

    load_failed = False
    live = await _matches(uplinks, port, mark, bypass=bypass)
    if live is None:
        # Could not read the live ruleset. Do NOT tear down: the rebuild needs
        # the same lock we just failed to get, so it would fail too and we would
        # have destroyed a working capture to replace it with nothing. Leave
        # whatever is live alone and report failure — the watchdog retries every
        # 30 s, by which time the other writer is long gone. A false alarm here
        # is much cheaper than the silent unproxied LAN the alternative produced.
        logger.warning(
            "divert: could not read the live ruleset (xtables lock held?); "
            "leaving the capture untouched"
        )
        return False
    if live:
        # Already exactly right. Re-installing would tear a working capture
        # down and rebuild it — a real leak window on every structural apply,
        # since ~14 sequential iptables fork/execs is not instant on an A53.
        # Only the set contents can have drifted, and reloading 15,000 nets
        # costs ~360ms, so skip that too unless the list actually changed.
        if not bypass or want == _loaded_bypass:
            return True
        if await _load_bypass_set(want):
            _loaded_bypass = want
            return True
        # Fall through to a rebuild. Returning True here would leave the rule
        # in place over a set holding the *previous* list — so addresses the
        # user just removed from `bypass_address` keep bypassing the proxy,
        # reported as success. One rebuild drops the rule; then it settles.
        bypass, load_failed = False, True

    # ---- from here on we are rebuilding, and the old capture stays live ----

    # A staging chain from a swap that did not finish has to be dealt with
    # before we can reuse the name; if it is still hooked it *is* the live
    # capture, and `_reclaim_staging` completes the swap rather than deleting
    # it. A False means we could not establish that it is safe to touch.
    if not await _reclaim_staging():
        return False

    # Before the chain, not after — the opposite of the old order, and for the
    # opposite reason. `ipset swap` replaces the set's contents under its own
    # name, so the *live* chain's `-m set` rule keeps matching throughout and
    # there is no window; the old code had to load afterwards only because its
    # teardown had just destroyed the set out from under the rule naming it.
    if bypass and not await _load_bypass_set(want):
        logger.warning(
            "divert: bypass set could not be loaded; installing the capture "
            "without it (%d networks will be proxied rather than sent direct)",
            len(want),
        )
        bypass, load_failed = False, True

    # Only on a load failure, never on missing xt_set — `_supports_bypass`
    # deliberately re-probes its "no", and memoising here would defeat that for
    # the user who just installed the module the warning told them to.
    if load_failed:
        _bypass_rejected, _bypass_rejected_at = want, _monotonic()
    _loaded_bypass = want if bypass else None
    if bypass:
        # Recovered: forget that we warned, so a *later* degrade of the same
        # list is reported instead of silently swallowed by the throttle.
        _forget_bypass_warning()

    # The policy-routing half is the one failure that must NOT leave the old
    # capture standing. Without the ip rule, or with it pointing at an empty
    # table, a hooked chain becomes a black hole: measured on a 5.4 kernel with
    # the hook live and the rule deleted, 0 packets escaped and 0 reached the
    # far end — `ip_forward()` drops any skb with `skb->sk` set, and the TPROXY
    # target sets it. (This comment used to claim the opposite, that the LAN
    # "egresses in the clear". It does not, and the correction matters because
    # this is the only failure path that still tears a live capture down.) The
    # teardown is still the right answer — a black-holed LAN is an outage — but
    # it is an outage, not a leak. Everything below this point can fail safely,
    # because a stale-but-whole capture still proxies.
    if not await _ensure_ip_rule(mark):
        logger.error("divert: could not add ip rule for mark %s", hex(mark))
        await _remove_locked(port=port, mark=mark)
        return False
    if (
        await _ip(["route", "replace", "local", "default", "dev", "lo", "table", str(ROUTE_TABLE)])
        != 0
    ):
        logger.error("divert: could not add local route to table %d", ROUTE_TABLE)
        await _remove_locked(port=port, mark=mark)
        return False

    # `-N` fails when the chain already exists — from a swap that died between
    # creating it and hooking it, or an `-X` that lost the xtables lock. Bailing
    # on that turned every later install into a hard failure, so flush into
    # whatever is there instead; the rules below are appended to an empty chain
    # either way. `_supports_bypass` does the same for the probe chain.
    if (
        await _ipt(["-t", "mangle", "-N", STAGING_CHAIN]) != 0
        and await _ipt(["-t", "mangle", "-F", STAGING_CHAIN]) != 0
    ):
        logger.error("divert: could not create or flush mangle chain %s", STAGING_CHAIN)
        return False
    for rule in _chain_rules(port, mark, uplinks, bypass=bypass, chain=STAGING_CHAIN):
        if await _ipt(["-t", "mangle", *rule]) != 0:
            logger.error("divert: could not add rule %s", " ".join(rule))
            await _discard_staging()
            return False

    if not await _ensure_input_accept(mark):
        logger.error("divert: could not add the INPUT accept for captured traffic")
        await _discard_staging()
        return False

    # Re-checked immediately before the hook. The shutdown teardown forces past
    # the lock on a deadline, so it can land at any await above this line;
    # hooking now would point the LAN at a chain that is about to lose its
    # listener — the exact black-hole that teardown exists to prevent.
    if _frozen:
        logger.warning("divert: capture was frozen mid-install; not hooking")
        await _discard_staging()
        return False

    # **Appended, not inserted at the head.** Two things depend on it. The
    # position is the one the capture has always had, behind whatever else
    # lives in mangle/PREROUTING (fw3's mssfix, mwan3's marking) — inserting at
    # 1 would silently reorder us ahead of them. And appending puts the new hook
    # *after* the old one, so the old chain sees every packet first. The
    # handover is the single `-D` below, and iptables-legacy commits a whole
    # table in one setsockopt, so there is no instant in which neither chain is
    # in charge.
    #
    # The window with both hooked is **fail-closed, not inert** — an earlier
    # version of this comment claimed the staging chain was unreachable, and
    # that is measurably false. Widening the window to 13 s under load put
    # 7,620 packets (~600 pps) through the staging chain's counters. What holds
    # is the direction: only packets the old chain *RETURNs* walk on to this
    # hook, so the staging chain can capture more but can never release
    # something the old chain captured. The proxied flow contributed 0 of those
    # 7,620, because the old chain's TPROXY had already terminated it.
    #
    # The one behavioural consequence: for those ~1-2 s a packet gets the new
    # policy early where the new policy is stricter (shrinking the uplink list
    # captures that uplink slightly before the `-D`). The opposite direction —
    # getting the *looser* policy early — cannot happen.
    if await _ipt(["-t", "mangle", "-A", "PREROUTING", "-j", STAGING_CHAIN]) != 0:
        logger.error("divert: could not hook PREROUTING")
        await _discard_staging()
        return False
    _staging_hooked = True

    if not await _finish_swap():
        return False

    logger.info(
        "divert: capture installed (tproxy :%d, uplinks excluded: %s)",
        port,
        ", ".join(uplinks) or "none",
    )
    return True


async def _finish_swap() -> bool:
    """Hand the LAN over from the old chain to the staging chain, then take its
    name. Returns immediately when no swap is in flight.

    The `-D` is the handover and the only moment that matters: before it the
    old chain sees every packet first, after it the staging chain does. Both
    are complete captures, so no packet is ever seen by neither. (The window is
    fail-closed rather than inert; see the `-A PREROUTING` comment above for
    the counters.)

    Renaming rather than alternating between two names keeps `_matches`,
    `installed_state` and the docs looking at one chain. `iptables -E` rewrites
    the jump in PREROUTING along with the chain, the chain's own rule lines and
    its reference count, and it preserves the packet counters — verified on
    iptables v1.8.7 (legacy), the build OpenWrt 21.02 ships and the target
    router runs.
    """
    global _staging_hooked
    # Nothing staged means nothing to hand over — and without this guard the
    # rest of the function is a full teardown, not a no-op: it deletes the live
    # `-j CHAIN` hook, flushes and deletes the live chain, then fails the
    # rename because there is nothing to rename. Measured, one such call cost
    # 4,180 escaped packets over 2.2 s and left the LAN uncaptured.
    #
    # Decided from OUR OWN bookkeeping, not from the kernel. The first version
    # of this guard asked the kernel whether a staging hook was present, which
    # cannot tell "no swap is in flight" apart from "the hook I installed 20 ms
    # ago was removed under me" — and answered the second case with `return
    # True`. Measured on a real kernel: an `/etc/init.d/firewall restart`
    # landing in that window (median 20.7 ms wide, one fork/exec) produced
    # 10,213 escaped packets counted in filter/FORWARD, 10,333 of them arriving
    # at the far end still carrying the client's address, while `install()`
    # returned True and the dashboard read CAPTURED. `_staging_hooked` knows the
    # difference and always did.
    if not _staging_hooked:
        return True

    dump = await _capture([*_IPT, "-t", "mangle", "-S", "PREROUTING"])
    if dump is None:
        # We cannot see which hooks exist, so we cannot retire the old one.
        # Both are hooked and the old one is in charge: stale, but a whole
        # working capture, and nothing leaks. The watchdog retries in 30 s.
        logger.error("divert: could not read PREROUTING to retire the previous chain")
        return False

    if not any(spec[-1] == STAGING_CHAIN for spec in parse_hooks(dump)):
        # We hooked it, and it is gone. Somebody flushed mangle/PREROUTING
        # between the hook and here — a firewall reload is the routine cause —
        # so the LAN is uncaptured *right now*. Reporting success would tell the
        # apply pipeline, the banner and the dashboard that the user's own
        # action worked while their traffic is in the clear.
        logger.error(
            "divert: the staged capture was removed before it could take over "
            "(a firewall reload?); the LAN is NOT captured"
        )
        _staging_hooked = False
        return False

    for spec in parse_hooks(dump):
        if spec[-1] != CHAIN:
            continue
        if await _ipt(["-t", "mangle", "-D", "PREROUTING", *spec]) != 0:
            logger.warning("divert: could not retire the old hook %s", " ".join(spec))

    # Flush before delete, and after the `-D` attempts above: a hook we failed
    # to remove is made inert by the flush, at which point the packet falls
    # through to the staging hook that follows it. That is the same reasoning
    # `_remove_locked` documents, and it is why a partially failed retirement
    # still cannot leak.
    await _ipt(["-t", "mangle", "-F", CHAIN])
    await _ipt(["-t", "mangle", "-X", CHAIN])

    if await _ipt(["-t", "mangle", "-E", STAGING_CHAIN, CHAIN]) != 0:
        # The name is still taken, which means `-X` could not remove the old
        # chain — something outside our parsing still references it. Traffic is
        # fine (the staging chain is hooked and whole); what breaks is only that
        # `_matches` will not recognise the hook, so every tick rebuilds. Each
        # rebuild is now hitless, so that costs CPU rather than plaintext, and
        # `_reclaim_staging` will keep completing the swap.
        logger.error("divert: could not rename %s to %s", STAGING_CHAIN, CHAIN)
        return False
    # No swap is in flight any more, so `install()`'s blanket handler must not
    # try to finish one. Left True, a later exception would call this again
    # against a staging chain that no longer exists.
    _staging_hooked = False
    return True


async def _reclaim_staging() -> bool:
    """Make the staging chain name safe to build into. False = do not touch it.

    The dangerous case is a staging chain that is still *hooked*: a crash or a
    lost xtables lock between the hook swap and the rename leaves the live
    capture sitting under the staging name. Flushing it to reuse the name would
    put the LAN in the clear for the length of the rebuild — reintroducing
    exactly the leak this design closes. Finish the swap instead; on success the
    name is free because the chain has been renamed away.
    """
    dump = await _capture([*_IPT, "-t", "mangle", "-S", "PREROUTING"])
    if dump is None:
        logger.warning("divert: could not read PREROUTING; not touching the staging chain")
        return False
    if any(spec[-1] == STAGING_CHAIN for spec in parse_hooks(dump)):
        logger.warning("divert: found an unfinished capture swap; completing it")
        # A previous run staged it, so say so: `_finish_swap` decides from this
        # flag rather than from the kernel, precisely because the kernel cannot
        # distinguish "never staged" from "staged and then wiped".
        global _staging_hooked
        _staging_hooked = True
        return await _finish_swap()
    await _ipt(["-t", "mangle", "-F", STAGING_CHAIN])
    await _ipt(["-t", "mangle", "-X", STAGING_CHAIN])
    return True


async def _discard_staging() -> None:
    """Throw away a staging chain that never took over. Unhooks first, in case
    we failed *after* hooking it — deleting a hooked chain is refused, and the
    caller that reaches here has already decided the swap is off."""
    await _ipt(["-t", "mangle", "-D", "PREROUTING", "-j", STAGING_CHAIN])
    await _ipt(["-t", "mangle", "-F", STAGING_CHAIN])
    await _ipt(["-t", "mangle", "-X", STAGING_CHAIN])


async def _ensure_ip_rule(mark: int) -> bool:
    """Add the fwmark rule unless it is already there.

    `ip rule add` is not idempotent — it stacks a second identical rule every
    time — and the rebuild no longer runs a teardown that used to delete the
    previous one first.

    An unreadable `ip rule show` falls through to adding. A duplicate is inert
    (the rules are identical, so whichever matches first does the same thing);
    a missing rule black-holes or, worse, silently releases every captured
    packet. `_matches` read the same output successfully moments ago, so this
    is a freak case, and it is the right way to be wrong.
    """
    rules = await _capture(["ip", "rule", "show"])
    if rules is not None and any(
        f"fwmark {hex(mark)}" in ln and f"lookup {ROUTE_TABLE}" in ln for ln in rules.splitlines()
    ):
        return True
    return await _ip(["rule", "add", "fwmark", hex(mark), "lookup", str(ROUTE_TABLE)]) == 0


async def _ensure_input_accept(mark: int) -> bool:
    """Put our accept at the head of filter/INPUT, unless it is already there.

    Being *present* is not enough — behind fw3's syn_flood or a zone's REJECT
    it never runs, which is the whole reason it exists. In the common rebuild
    the rule is already first and this is a single read with no write at all.

    **Insert first, then delete the strays by index.** Deleting first looks
    natural — `-D` removes the first match, so inserting first and deleting by
    spec would remove the copy we just placed — and it is wrong, because this
    rule belongs to the capture that is *still live*. Measured: with the insert
    failing (xtables lock), the delete had already run, so a rebuild that
    reported failure left the running capture without its accept, and the whole
    guest zone — stock `input REJECT` — went dark: 40/40 TCP connects refused
    from a guest client while the LAN zone kept working. Nothing restored it
    until the next successful install. Deleting by index instead means the head
    of INPUT is only ever added to.

    An unreadable INPUT returns False rather than inserting blind. Inserting
    was measurably unbounded — one duplicate per contended install, forever,
    invisible because `_matches` only inspects the first rule and
    `_remove_locked` deletes at most four.
    """
    rule = _input_accept_rule(mark)
    dump = await _capture([*_IPT, "-t", "filter", "-S", "INPUT"])
    if dump is None:
        logger.warning("divert: could not read filter/INPUT; leaving it alone")
        return False
    body = [ln for ln in dump.splitlines() if ln.startswith("-A INPUT")]
    if body and _INPUT_ACCEPT_COMMENT in body[0]:
        return True
    # 1-based positions of the copies that are in the wrong place, captured
    # before the insert shifts everything down by one.
    strays = [i + 1 for i, ln in enumerate(body) if _INPUT_ACCEPT_COMMENT in ln]
    if await _ipt(["-t", "filter", "-I", "INPUT", "1", *rule]) != 0:
        return False
    # Descending, so each delete leaves the positions below it untouched.
    for pos in sorted(strays, reverse=True):
        await _ipt(["-t", "filter", "-D", "INPUT", str(pos + 1)])
    return True


async def _matches(
    uplinks: Sequence[str], port: int, mark: int, *, bypass: bool = False
) -> bool | None:
    """True if the whole capture is live and correct — every piece of it.

    Checking this cheaply is harder than it looks, and getting it wrong is
    dangerous in both directions: a false "yes" leaves a broken capture in
    place forever (the watchdog "heals" it by doing nothing), a false "no"
    tears down and rebuilds a working capture on every tick, opening a real
    leak window each time.

    A textual diff of the chain body is not an option: iptables does not
    round-trip our own specs. `-p tcp --dport 53` comes back as
    `-p tcp -m tcp --dport 53`, `--tproxy-mark 0x2023` as
    `0x2023/0xffffffff`, and an `--on-ip 0.0.0.0` is injected. So we check the
    load-bearing facts instead, each of which is enough on its own to break
    the capture:

      * the PREROUTING hooks are exactly our devices,
      * the chain has our rule count and every TPROXY rule names our port and
        mark (a wrong port sends the LAN to a dead socket),
      * DNS is diverted before the private-range escapes (otherwise queries
        leak to the ISP's resolver — the one failure with no visible symptom),
      * the fwmark ip rule and its route table exist (delete just the ip rule
        and the LAN black-holes while the iptables side still looks perfect).

    Returns **None** when the live ruleset could not be read at all — almost
    always another writer holding the xtables lock past our `-w 5`, which makes
    even a plain `-S` exit 4. That is not "does not match": answering False
    there sent the caller into a teardown-and-rebuild that needs the very same
    lock, so it failed too. Measured on a 5.4 kernel from a fully correct
    capture, with the lock held 12 s: 7.9 s of unproxied LAN, and one run ended
    with hook, chain and ip rule all gone while `install()` still returned True.
    """
    prerouting = await _capture([*_IPT, "-t", "mangle", "-S", "PREROUTING"])
    if prerouting is None:
        return None
    hooks = parse_hooks(prerouting)
    if len(hooks) != 1 or hooks[0] != ["-j", CHAIN]:
        return False

    chain = await _capture([*_IPT, "-t", "mangle", "-S", CHAIN])
    if chain is None:
        return None
    body = [ln for ln in chain.splitlines() if ln.startswith(f"-A {CHAIN}")]
    if not body_matches(body, uplinks, port, mark, bypass=bypass):
        return False

    # The policy-routing half. Without it the TPROXY target marks packets that
    # nothing routes locally, and the LAN goes dark with the chain intact.
    # The rule must point at OUR table: one aimed at an empty table reads as
    # present while the LAN black-holes, which is the failure this check exists
    # for. `ip rule show` prints "from all fwmark 0x2023 lookup 2023".
    rules = await _capture(["ip", "rule", "show"])
    if rules is None:
        return None
    if not any(
        f"fwmark {hex(mark)}" in ln and f"lookup {ROUTE_TABLE}" in ln for ln in rules.splitlines()
    ):
        return False
    table = await _capture(["ip", "route", "show", "table", str(ROUTE_TABLE)])
    if table is None:
        return None
    if "local default" not in table:
        return False
    # The INPUT accept has to be FIRST, not merely present: behind syn_flood or
    # a zone's REJECT it does nothing, and the whole point is to pre-empt them.
    filter_input = await _capture([*_IPT, "-t", "filter", "-S", "INPUT"])
    if filter_input is None:
        return None
    input_rules = [ln for ln in filter_input.splitlines() if ln.startswith("-A INPUT")]
    return bool(input_rules) and _INPUT_ACCEPT_COMMENT in input_rules[0]


def body_matches(
    body: Sequence[str],
    uplinks: Sequence[str],
    port: int,
    mark: int,
    *,
    bypass: bool,
) -> bool:
    """Does `iptables -S <CHAIN>` describe the chain we would install?

    Split out of `_matches` so it can be tested against the exact lines the
    kernel renders for `_chain_rules` — the ordering check below was silently
    inverted for two releases precisely because nothing could exercise it
    without a live kernel.
    """
    if len(body) != len(_chain_rules(port, mark, uplinks, bypass=bypass)):
        return False

    # Loopback and every uplink must be let through — see _chain_rules for what
    # goes wrong otherwise (router DNS answered with a fake IP; dead uplink).
    excluded = [ln for ln in body if "-j RETURN" in ln and " -i " in ln]
    if {ln.split(" -i ")[1].split()[0] for ln in excluded} != {"lo", *uplinks}:
        return False

    tproxy = [ln for ln in body if "-j TPROXY" in ln]
    if not tproxy or not all(f"--on-port {port}" in ln and hex(mark) in ln for ln in tproxy):
        return False

    if bypass and not any(f"--match-set {BYPASS_SET} " in ln for ln in body):
        return False

    # The terminal DROP, by inspection rather than by counting. The rule count
    # above is the only thing that stood between a chain and this check, and it
    # collides: a 16-rule chain built WITH the bypass and missing its DROP has
    # exactly the length of a correct 15-rule chain built WITHOUT one. Measured
    # through such a chain — `body_matches(bypass=False)` returned True and
    # `install()` reported success — ICMP, GRE (47) and ESP (50) all reached the
    # far side carrying the LAN client's traffic, and a stale `--match-set`
    # RETURN kept sending a bypass list the user had already removed straight
    # out. Nothing but a daemon restart's `sweep()` would have cleared it.
    if not body or not body[-1].endswith("-j DROP"):
        return False
    # The other half of that collision: a chain carrying a bypass rule we did
    # not ask for is not the chain we would install, whatever its length.
    if not bypass and any(f"--match-set {BYPASS_SET} " in ln for ln in body):
        return False

    # The escapes must be the ranges we chose, not merely the right *number* of
    # them. A count-only check accepts a chain that RETURNs 198.18.0.0/15 in
    # place of 0.0.0.0/8 — the fake-IP range, whose exclusion breaks every
    # proxied name while everything else keeps working.
    escaped = {ln.split(" -d ")[1].split()[0] for ln in body if " -d " in ln and "RETURN" in ln}
    if {_norm_cidr(n) for n in escaped} != {_norm_cidr(n) for n in _RESERVED}:
        return False

    # Ordering, not just presence: the DNS divert has to precede the escapes.
    # Scoped to the *destination* RETURNs — the reserved ranges. The interface
    # RETURNs (lo, uplinks) are deliberately first and must not count here, or
    # this reads False for a perfect chain and every tick rebuilds the capture.
    first_dns = next((i for i, ln in enumerate(body) if "--dport 53" in ln), None)
    if first_dns is None:
        return False
    first_escape = next(
        (i for i, ln in enumerate(body) if " -d " in ln and ln.endswith("-j RETURN")), None
    )
    if first_escape is not None and first_dns > first_escape:
        return False

    # And the interface escapes must come *before* the DNS divert, which the
    # `-d`-scoped check above deliberately can't see. `-i lo` landing after it
    # is the router-DNS loop: queries to 127.0.0.1 get TPROXY'd, answered with
    # a fake IP, and sing-box's own `dns-local` resolves straight back in here.
    last_iface = max(
        (i for i, ln in enumerate(body) if " -i " in ln and ln.endswith("-j RETURN")), default=None
    )
    return last_iface is None or last_iface < first_dns


def _norm_cidr(net: str) -> str:
    """Strip a redundant `/32` so either rendering compares equal.

    Applied to *both* sides rather than guessing which one the kernel uses.
    An earlier version guessed, and guessed wrong: it assumed iptables-legacy
    prints a /32 bare, when 1.8.7 on OpenWrt 21.02 prints `-d 8.8.8.8/32` (and
    so does nft). Inert while `_RESERVED` holds no /32 — but this helper exists
    to *prevent* rebuild-every-tick, and getting it backwards would cause it
    the moment someone adds one.
    """
    return net[:-3] if net.endswith("/32") else net


def parse_hooks(prerouting_dump: str) -> list[list[str]]:
    """Extract our PREROUTING jumps from `iptables -t mangle -S PREROUTING`.

    Returned as argv suffixes ready to hand to `-D` — i.e. the rule's own spec
    with the leading `-A` swapped out by the caller.

    We can't just delete `-j CHAIN`: iptables matches `-D` on the *whole* rule
    spec, so deleting with a partial one silently fails and leaves the capture
    live after a "successful" teardown — traffic keeps being sent to a port
    nothing listens on. Found the hard way. (The spec that first bit us carried
    `-i <lan device>`; the hook is unconditional now, but the delete is still
    driven from the live spec rather than a guess.)

    Hooks into `STAGING_CHAIN` count too, because between the swap and the
    rename that chain *is* the capture. Missing them would let `remove()` report
    a clean teardown over a fully live capture and `installed_state()` answer
    "nothing installed" while the LAN is being diverted — the same class of bug
    the paragraph above is about. Callers that care which chain a hook points at
    read `spec[-1]`.
    """
    hooks: list[list[str]] = []
    for line in prerouting_dump.splitlines():
        parts = line.split()
        if (
            parts[:2] == ["-A", "PREROUTING"]
            and parts[-2:-1] == ["-j"]
            and parts[-1] in (CHAIN, STAGING_CHAIN)
        ):
            hooks.append(parts[2:])
    return hooks


async def remove(
    *, port: int = TPROXY_PORT, mark: int = TPROXY_MARK, force_after_s: float | None = None
) -> bool:
    """Tear the capture down. Safe to call when nothing is installed. Returns
    whether the LAN is definitely no longer captured.

    Takes the same lock `install()` does. Without it, `stop()`, the watchdog's
    give-up path and the lifespan teardown could each flush the chain — and
    reset the bypass cache — underneath a running install: the installer's next
    `-A` lands in a chain that was just `-X`'d, and it can re-add the
    PREROUTING hook afterwards, pointing the LAN at a chain that no longer
    exists.

    `force_after_s` gives up on the lock and tears down anyway. It defaults to
    None — waiting — because on every live path (`stop()`, the watchdog's
    give-up) that race is real and losing it black-holes the LAN. **Only the
    lifespan teardown passes a bound**, and only because it runs after the
    apply pipeline and watchdog have already stopped, so nothing legitimate can
    still hold the lock; there, a wedged install must not outlast procd's
    STOP=5 and leave the LAN behind a capture whose listener vanishes at
    STOP=10.
    """
    if force_after_s is None:
        async with _get_lock():
            return await _remove_locked(port=port, mark=mark)

    global _frozen
    # Only the shutdown path forces, and after it nothing may hook again — the
    # generation counter cannot express that on its own, because "during my
    # run" depends on where the straggler sampled it.
    _frozen = True
    try:
        await asyncio.wait_for(_get_lock().acquire(), timeout=force_after_s)
    except asyncio.TimeoutError:
        logger.warning("divert: lock still held after %ss; removing anyway", force_after_s)
        return await _bounded_remove(port, mark, force_after_s)
    try:
        return await _bounded_remove(port, mark, force_after_s)
    finally:
        _get_lock().release()


async def _bounded_remove(port: int, mark: int, budget_s: float) -> bool:
    """`_remove_locked` with a deadline on the *body*, not just the lock.

    `force_after_s` used to bound only `lock.acquire()`; the body then made ~11
    iptables calls at `-w 5` plus ipset and ip calls, measured at 35s under
    xtables-lock contention — well past the shutdown allowance it was supposed
    to fit inside. Timing out means the LAN may still be captured, which is
    exactly what the False return is for.
    """
    try:
        return await asyncio.wait_for(_remove_locked(port=port, mark=mark), timeout=budget_s)
    except asyncio.TimeoutError:
        logger.error("divert: teardown did not finish within %ss", budget_s)
        return False


async def _remove_locked(*, port: int = TPROXY_PORT, mark: int = TPROXY_MARK) -> bool:
    """`remove()`'s body, for callers already holding the lock. True if the LAN
    is definitely no longer captured.

    **Flush the chain first.** The old order deleted the PREROUTING jumps
    first, which reads as the safer sequence and isn't: back then `_capture`
    returned `""` on *any* failure and `parse_hooks("")` is `[]` — so under
    xtables-lock contention (an fw3 reload, mwan3) the hook
    was silently never deleted while `remove()` returned success. (`_capture`
    returns None now, for exactly that reason — see its docstring — and the
    branch below distinguishes it. The flush-first order is kept regardless:
    it makes a surviving hook inert whatever the read did.) Emptying the
    chain is a single call and makes a surviving hook inert: packets enter,
    match nothing, fall through to the normal path. Reproduced on a real
    kernel, where the daemon exited leaving hook + 4 live TPROXY rules and no
    fwmark route — a hard black hole with nothing left to sweep it.

    Every step's return code is now checked and reported. A teardown that
    cannot say it failed makes every deadline above it decoration.
    """
    global _loaded_bypass
    _loaded_bypass = None

    # 1. Neuter the capture. Everything below is tidying.
    #
    # Both chains, because a rebuild that died between hooking its staging
    # chain and renaming it leaves the live capture under the staging name.
    # Flushing only CHAIN there would report a successful teardown over a fully
    # live capture — the exact failure the docstring above is about.
    ok = True
    dump: str | None = None
    for chain in (CHAIN, STAGING_CHAIN):
        if await _ipt(["-t", "mangle", "-F", chain]) == 0:
            continue
        # A chain that simply isn't there is success. `-N <chain>` is the
        # declaration line, matched exactly — a substring test on the bare name
        # also matches `kitewrt_tproxy_probe` and `kitewrt_tproxy_next`, which
        # made a clean teardown report failure whenever one had leaked.
        if dump is None:
            dump = await _capture([*_IPT, "-t", "mangle", "-S"])
        if dump is None or f"-N {chain}\n" in dump + "\n":
            logger.error("divert: could not flush %s; the LAN may still be captured", chain)
            ok = False

    # 2. Unhook. Failing here is survivable now that the chains are empty.
    dump = await _capture([*_IPT, "-t", "mangle", "-S", "PREROUTING"])
    if dump is None:
        # We do not know whether a hook is there. Try the specs we install
        # anyway, and do not claim success — the whole point of returning a
        # bool is that the caller can say so.
        await _ipt(["-t", "mangle", "-D", "PREROUTING", "-j", CHAIN])
        await _ipt(["-t", "mangle", "-D", "PREROUTING", "-j", STAGING_CHAIN])
        logger.error("divert: could not read PREROUTING; a hook may still be installed")
        ok = False
    else:
        for spec in parse_hooks(dump):
            if await _ipt(["-t", "mangle", "-D", "PREROUTING", *spec]) != 0:
                logger.warning("divert: could not delete the PREROUTING hook %s", " ".join(spec))
                ok = False

    # Retry a transient failure (-1) rather than read it as "none left", which
    # is what killswitch._delete_all learned to do the hard way — but bound the
    # retries, because 4 x 10s of a persistently failing call is most of the
    # shutdown budget spent on the least important step.
    transient = 0
    for _ in range(4):
        rc = await _ipt(["-t", "filter", "-D", "INPUT", *_input_accept_rule(mark)])
        if rc > 0 and rc not in _IPT_UNAVAILABLE:
            break  # iptables says "no such rule": we are done
        # rc 4 is the xtables lock, not an answer — the module defines
        # `_IPT_UNAVAILABLE` for exactly this and this loop was not using it, so
        # a contended teardown silently left the accept behind and said nothing.
        if rc < 0 or rc in _IPT_UNAVAILABLE:
            transient += 1
            if transient >= 2:
                logger.warning("divert: gave up deleting the INPUT accept")
                break
    await _ipt(["-t", "mangle", "-X", CHAIN])
    await _ipt(["-t", "mangle", "-X", STAGING_CHAIN])
    await _run(["ipset", "destroy", BYPASS_SET])
    await _run(["ipset", "destroy", f"{BYPASS_SET}_tmp"])
    # Probe leftovers: a chain left behind by a probe that lost the xtables
    # lock made every later probe answer "no ipset support" on a box where it
    # works, and nothing else ever cleared it.
    await _ipt(["-t", "mangle", "-F", PROBE_CHAIN])
    await _ipt(["-t", "mangle", "-X", PROBE_CHAIN])
    await _run(["ipset", "destroy", PROBE_SET])

    # ONLY when the netfilter half actually came down. `ip` does not take the
    # xtables lock, so under sustained contention every `iptables` call above
    # can fail while these two succeed — and that combination is the worst
    # state this module can produce: a live hook into a fully armed chain with
    # nothing to route the marked packets. Measured with the lock held through a
    # 60 s `remove()`: hook present, 16 rules, 4 TPROXY targets, `iprules=0`,
    # table 2023 empty, 205,159 of 338,100 packets dropped, traceroute dead —
    # and `installed_state()` still True, because it reads the hook alone. On
    # the shutdown path there is no daemon left to heal it.
    #
    # Leaving them in place when the teardown failed is strictly better: the
    # capture stays whole and working until the next attempt.
    if ok:
        await _ip(["rule", "del", "fwmark", hex(mark), "lookup", str(ROUTE_TABLE)])
        await _ip(["route", "flush", "table", str(ROUTE_TABLE)])
    else:
        logger.error(
            "divert: teardown failed; leaving the fwmark rule and table %d in place "
            "so the surviving capture keeps working rather than black-holing",
            ROUTE_TABLE,
        )
    return ok


async def sweep() -> None:
    """Clear a capture left behind by a daemon that died without cleaning up.

    Called on startup. Without this, a SIGKILL'd daemon leaves rules pointing
    at a port nothing listens on — which black-holes the LAN until someone
    intervenes.
    """
    if await is_installed():
        logger.warning("divert: found a stale capture at startup; removing it")
    if not await remove():
        logger.error("divert: could not clear the stale capture; the LAN may be black-holed")
