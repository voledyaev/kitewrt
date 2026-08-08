"""Install / uninstall steps for kitewrt on OpenWrt.

Each function is one logical operation against the router; flows.py calls them
in a fixed order. The router is a normal Linux box — opkg for packages, procd
init scripts, fw3 for the firewall — so there's no Entware bootstrap, no USB
drive, and no reboot.

Data plane = sing-box with a `tproxy` inbound. The kernel hands sing-box an
already-established socket rather than raw packets, and the daemon installs the
netfilter capture itself at runtime (see kitewrt/divert.py) — so there is no
fw3 zone here, only the MSS clamp and the two IPv6 blocks. The installer
fetches the sing-box binary, deploys the daemon + its python deps, writes the
procd init scripts and those fw3 rules, then starts the daemon; kitewrt
generates config.json and drives sing-box via the Clash API at runtime.
"""

from __future__ import annotations

import asyncio
import contextlib
import tempfile
from pathlib import Path

from installer.parsers import goarch_from_uname, is_openwrt
from installer.ssh import Router, SSHError
from installer.ui import fail, info, ok, warn

# --- Constants ------------------------------------------------------------

REMOTE_APP = "/usr/lib/kitewrt"  # package source + vendored deps
REMOTE_VENDOR = "/usr/lib/kitewrt/vendor"
REMOTE_DATA = "/etc/kitewrt/data"
KITEWRT_INIT = "/etc/init.d/kitewrt"
# OpenWrt's documented "carry this across a sysupgrade" hook. Only the config
# dir: see install_sysupgrade_keep.
SYSUPGRADE_KEEP_PATH = "/lib/upgrade/keep.d/kitewrt"
SYSUPGRADE_KEEP_BODY = b"/etc/kitewrt\n"
# Runtime netfilter objects the *daemon* creates (kitewrt.divert /
# kitewrt.killswitch). Mirrored here because uninstall has to be able to clean
# up on a router whose daemon is dead — see remove_capture. Keep in sync.
_CAPTURE_CHAIN = "kitewrt_tproxy"
_BYPASS_SET = "kitewrt_bypass"
_INPUT_ACCEPT_COMMENT = "kitewrt-tproxy-accept"
_KILLSWITCH_COMMENT = "kitewrt-killswitch"
_TPROXY_MARK = "0x2023"
_ROUTE_TABLE = "2023"


def divert_mark() -> int:
    """The fwmark the daemon uses, read from the daemon so the pre-flight
    cannot probe a different one than runtime installs."""
    from kitewrt import divert

    return divert.TPROXY_MARK


# 8088, not 8080 — GL.iNet's uhttpd already binds 8080.
WEB_UI_PORT = 8088

SINGBOX_DIR = "/etc/sing-box"
SINGBOX_CONFIG = "/etc/sing-box/config.json"
SINGBOX_BIN = "/usr/bin/sing-box"
SINGBOX_INIT = "/etc/init.d/singbox"

# sing-box official Go release. The plain `linux-<goarch>` asset used here IS
# glibc-linked, so on a musl-only OpenWrt it needs a loader shim to start (see
# ensure_loader_shim). The release does also publish `-musl` and `-glibc`
# variants (it has for many versions — this comment used to claim it didn't),
# and the musl one would make the shim unnecessary; swapping assets changes how
# the data plane binary is linked, so it wants its own proving run, not a
# drive-by during a version bump.
#
# 1.13.16 verified end-to-end on an aarch64 OpenWrt 24.10 lab router: fresh
# download + sha256 + install, tproxy capture up, and a LAN client's requests
# observed arriving at a separate exit node. 1.13.13 is the last pin proven on
# the Flint 2 itself.
SINGBOX_VERSION = "1.13.16"
SINGBOX_URL_TMPL = (
    "https://github.com/SagerNet/sing-box/releases/download/"
    "v{ver}/sing-box-{ver}-linux-{goarch}.tar.gz"
)
# Pinned SHA256 of each official release tarball — the binary runs as root and
# IS the data plane, and the download path is assumed hostile (the offline mode
# exists because the ISP blocks GitHub), so verify before trusting it. Arches
# without a pinned hash are installed with a warning rather than blocked.
SINGBOX_SHA256 = {
    "arm64": "d587fb00bdc3c044227f35d15d154f271bc75108475091eda2542e4b82bb2949",
    "amd64": "e37c312859dfa84cba148f41072ff6369f08361ae91d622dc1fd3aab49611a8d",
    "armv7": "f1883794944a8f60b228bff19e51575f7739e0a75d4ed17dd936365171db5368",
}


# uv, used on the router to install the python deps. Pinned, checksummed, and
# fetched the same way sing-box is — including the offline artifacts escape
# hatch, because the ISP that blocks GitHub blocks it for both.
#
# Why not pip: OpenWrt 21.02 ships pip 22.0.4 (2022). Beyond age, the important
# difference is what gets installed. pip was given version *ranges*
# (`fastapi>=0.110,<1`) and resolved them on the router at install time, so a
# router provisioned six months after a release ran a dependency tree CI had
# never seen. uv installs from `uv.lock` — the exact versions the test matrix
# ran against — and verifies every wheel against the hashes recorded alongside
# them in `resources/requirements.txt`. (No count here on purpose: it moves with
# every pin, and the number this comment used to give was out by 379.) It also
# removes the `python3-pip` opkg package (5.4 MB installed) from the
# requirements, and one more feed that has to be reachable.
UV_VERSION = "0.12.3"
UV_TARGETS = {
    "arm64": "aarch64-unknown-linux-musl",
    "amd64": "x86_64-unknown-linux-musl",
    "armv7": "armv7-unknown-linux-musleabihf",
}
UV_SHA256 = {
    "aarch64-unknown-linux-musl": (
        "fa513fca1eb2913334c944fe9adbdd410274a1cbe8dd05d03699a9eb85311d4e"
    ),
    "x86_64-unknown-linux-musl": (
        "0643b9fb8c9fb27458e709ce6ff939695013c41975ff7b02d3f3b138d8d4bdb3"
    ),
    "armv7-unknown-linux-musleabihf": (
        "771c35fc4de5ea1e115ddab3147439498f30572be38fa2ff5c2dabb2258faa90"
    ),
}
UV_URL_TMPL = "https://github.com/astral-sh/uv/releases/download/{ver}/{asset}"


# The exported lock, generated by `uv export` and checked in. Shipped rather
# than generated at install time so the installer needs no uv on the machine
# running it; CI fails if it drifts from uv.lock.
REQUIREMENTS_PATH = Path(__file__).resolve().parent / "resources" / "requirements.txt"


def export_locked_requirements() -> bytes:
    """The pinned, hashed requirements the router installs from."""
    try:
        return REQUIREMENTS_PATH.read_bytes()
    except OSError as exc:
        fail(
            f"missing {REQUIREMENTS_PATH} — regenerate with `uv export -o {REQUIREMENTS_PATH}`: {exc}"
        )
        raise  # unreachable; fail() exits


def uv_artifact_name(goarch: str) -> str | None:
    """The uv release tarball for this CPU, or None for an unsupported arch."""
    target = UV_TARGETS.get(goarch)
    return f"uv-{target}.tar.gz" if target else None


# --- Offline artifacts ----------------------------------------------------
# Some ISPs block GitHub (and occasionally PyPI) from the router's WAN, which
# breaks the on-router download of sing-box, uv and the wheels. As an escape
# hatch the installer first looks in an *artifacts dir* for pre-placed files
# downloaded on a machine that CAN reach them; if found, they're uploaded +
# installed offline. Nothing is auto-bundled — the user drops the exact files
# (see installer/artifacts/README.md) and the installer just checks for them.


def default_artifacts_dir() -> Path:
    """Where install_* looks for pre-placed download artifacts. Resolved next to
    the installer package so it's the same folder regardless of the caller's
    CWD; overridable with `--artifacts-dir`."""
    return Path(__file__).resolve().parent / "artifacts"


def singbox_artifact_name(version: str, goarch: str) -> str:
    """The exact sing-box GitHub release tarball name for this version/arch —
    also the filename to drop in the artifacts dir for an offline install."""
    return f"sing-box-{version}-linux-{goarch}.tar.gz"


def find_local_artifact(artifacts_dir: Path | str | None, name: str) -> Path | None:
    """`artifacts_dir/name` if it exists as a file, else None."""
    if artifacts_dir is None:
        return None
    p = Path(artifacts_dir) / name
    return p if p.is_file() else None


def find_local_wheels(artifacts_dir: Path | str | None) -> list[Path]:
    """Wheel files under `artifacts_dir/wheels` (for an offline dependency install),
    sorted; empty when the dir is absent. The user fills this with `pip download`
    output matching their router's python/arch (so it stays correct across the
    py3.9 / py3.10 split between OpenWrt releases)."""
    if artifacts_dir is None:
        return []
    wheel_dir = Path(artifacts_dir) / "wheels"
    if not wheel_dir.is_dir():
        return []
    return sorted(wheel_dir.glob("*.whl"))


# kitewrt ships NO geo data / block-lists. Any geo split is supplied by the
# user as `type: remote` rule-sets, which sing-box downloads + caches itself.

# The Python dependency list lives in `resources/requirements.txt`, hashed and
# pinned to exact versions. A `PIP_PACKAGES` tuple of version *ranges* used to
# sit here; it stopped being installed when the installer moved to uv, but it
# stayed readable, and the README's "what happens, in order" table was copied
# from it — so the docs described a pip install of a hand-listed package set
# long after the code had stopped doing that. Removed rather than corrected:
# a second, unused answer to "what does this install" is how that happened.

# fw3 named uci sections (idempotent: re-running overwrites the same names
# rather than stacking anonymous duplicates).
_FW_ZONE = "kitewrt_singbox"
_FW_FWD = "kitewrt_lan2singbox"
_FW_MSS = "kitewrt_mss_clamp"
_FW_BLOCK_UI = "kitewrt_block_wan_ui"
_FW_ALLOW_V6_LOCAL = "kitewrt_allow_ipv6_local"
_FW_BLOCK_V6 = "kitewrt_block_ipv6_egress"
_FW_BLOCK_V6_DNS = "kitewrt_block_ipv6_dns"

# Every fw3 section kitewrt has ever created, including retired ones. Uninstall
# deletes exactly this list — derived rather than hand-written a second time,
# because it *was* hand-written and `_FW_BLOCK_V6_DNS` never got added: an
# uninstalled router kept REJECTing its LAN's IPv6 DNS forever, with nothing
# left on the box to say why. Retired names stay so an old install still cleans.
_FW_ALL_SECTIONS = (
    _FW_ZONE,
    _FW_FWD,
    _FW_MSS,
    _FW_BLOCK_UI,
    _FW_ALLOW_V6_LOCAL,
    _FW_BLOCK_V6,
    _FW_BLOCK_V6_DNS,
)

# Router-origin MSS clamp. The wan zone clamps *forwarded* LAN traffic, but the
# daemon's OWN HTTPS (subscription / rules / DoH bootstrap / exit-IP) on the raw
# WAN is not — and on a PMTU-limited upstream (double-NAT / PPPoE) that
# black-holes on large packets (TLS hangs, ping+DNS still work). Proven real on
# the Flint 2. Shipped as a firewall include so it re-applies on every reload +
# reboot; idempotent (delete-then-add); detects the WAN at run time.
# It is a shell-script include, and this comment used to say fw4 (22.03+) does
# not run those, so the clamp silently degraded on an nftables router. That is
# **measured false**, twice and independently: on stock 22.03.6 the rule came
# straight back into mangle/POSTROUTING after a flush + reload, and on 24.10.0 a
# marker script confirmed fw4 executes the include with and without `reload`.
# firewall4 runs `config include` scripts. See docs/openwrt-notes.md.
MSS_CLAMP_PATH = "/etc/kitewrt/mss-clamp.sh"
# `-w 5` on every call, and the delete loops. Without it the include was a
# coin toss under contention, measured three ways on a live router: with the
# xtables lock held it added nothing at all and still exited 0, so a
# PMTU-limited uplink black-holed the router's own HTTPS with no signal; when
# the `-D` lost the lock and the `-A` won, POSTROUTING went 1 -> 2 rules and
# stayed there; and since `-D` names the *currently* detected WAN, a device
# change orphans the old rule, which was still counting packets long after the
# default route had moved. The loop deletes every copy rather than one.
_MSS_CLAMP_SCRIPT = b"""#!/bin/sh
# kitewrt: clamp router-origin TCP MSS to PMTU on the WAN (see installer notes).
WAN=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
[ -z "$WAN" ] && exit 0
RULE="-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
# Every stale copy, on every device we ever clamped - not just the current one.
iptables -w 5 -t mangle -S POSTROUTING 2>/dev/null \
  | grep -- "--clamp-mss-to-pmtu" \
  | sed 's/^-A /-D /' \
  | while read -r spec; do iptables -w 5 -t mangle $spec 2>/dev/null; done
iptables -w 5 -t mangle -A POSTROUTING -o "$WAN" $RULE || \
  logger -t kitewrt "mss-clamp: could not install the clamp on $WAN"
exit 0
"""


# --- Pre-flight ----------------------------------------------------------


async def preflight_openwrt(router: Router) -> None:
    rc, out, _ = await router.run("cat /etc/os-release 2>/dev/null", timeout=15.0)
    if rc != 0 or not is_openwrt(out):
        # Some builds only ship the older file.
        rc2, out2, _ = await router.run("cat /etc/openwrt_release 2>/dev/null", timeout=15.0)
        if rc2 != 0 or not is_openwrt(out2):
            fail(
                "this doesn't look like an OpenWrt router (no OpenWrt in "
                "/etc/os-release).\n  kitewrt targets OpenWrt 21.02+ "
                "(incl. GL.iNet firmware)."
            )
    rc, _, _ = await router.run("command -v opkg", timeout=10.0)
    if rc != 0:
        fail("opkg not found — kitewrt needs an OpenWrt router with opkg.")
    ok("OpenWrt detected (opkg present)")


async def detect_arch(router: Router) -> str:
    """Return the sing-box release GOARCH for this router's CPU."""
    _, out, _ = await router.run("uname -m", check=True, timeout=10.0)
    return goarch_from_uname(out)


# python3 (~30 MB) + the daemon's deps (~25 MB) + the sing-box binary (~54 MB
# extracted) need ~140 MB of writable space; a full overlay fails mid-extract
# with a cryptic opkg/pip error, so check first.
MIN_OVERLAY_MB = 140


async def ensure_tools(router: Router) -> None:
    """curl + sha256sum are load-bearing — the daemon-health check and the
    binary checksum — and were previously only present on the *download* path,
    so an offline-artifact install could false-fail (no curl) or install an
    unverified binary (no sha256sum). Ensure both up front. If they can't be
    installed we assume the router has no usable package feed — an unpredictable
    setup we won't pretend to configure (kitewrt assumes *some* working
    internet)."""
    for tool, pkg in (("curl", "curl"), ("sha256sum", "coreutils-sha256sum")):
        rc, _, _ = await router.run(f"command -v {tool}", timeout=10.0)
        if rc == 0:
            continue
        info(f"installing {tool}")
        await router.opkg_update()
        await router.run(f"opkg install {pkg}", check=False, timeout=180.0)
        rc, _, _ = await router.run(f"command -v {tool}", timeout=10.0)
        if rc != 0:
            fail(
                f"{tool} is required but couldn't be installed (opkg feed unreachable?). "
                "kitewrt needs a router with a working package feed."
            )
    ok("curl + sha256sum present")


async def preflight_space(router: Router) -> None:
    """Fail early when the writable overlay is too small for python3 + deps.
    Best-effort: if free space can't be read, proceed and let opkg surface any
    real problem rather than blocking on a parse miss."""
    for path in ("/overlay", "/"):
        _, out, _ = await router.run(
            f"df -Pk {path} 2>/dev/null | awk 'NR==2{{print $4}}'", timeout=10.0
        )
        free = out.strip()
        if free.isdigit():
            free_mb = int(free) // 1024
            if free_mb < MIN_OVERLAY_MB:
                fail(
                    f"only ~{free_mb} MB free on {path}; python3 + the daemon's deps need "
                    f"~{MIN_OVERLAY_MB} MB. Free up space (or use a device with a roomier "
                    "overlay) and retry."
                )
            ok(f"disk space OK (~{free_mb} MB free on {path})")
            return


async def ensure_tproxy(router: Router) -> None:
    """Make sure the kernel can actually do TPROXY, and fail loudly if it can't.

    This is the LAN capture. Without the `TPROXY` target and the `socket`
    match, `kitewrt.divert` installs nothing and every LAN client egresses
    unproxied while the UI cheerfully reports the VPN as on — a silent failure
    of the one property this tool exists to provide. So this is a hard stop,
    not a warning.

    We test the target rather than trusting `opkg list-installed`: the modules
    can be built into the kernel (no package), and a package can be installed
    whose module won't load.
    """
    # Probe only what the daemon actually emits. An earlier version also
    # required the `socket` match and refused routers that had TPROXY but not
    # iptables-mod-socket — kitewrt never uses that match (the TPROXY target
    # does its own socket lookup), so the requirement was invented.
    probe = (
        "iptables -w 5 -t mangle -N kitewrt_probe 2>/dev/null; "
        "iptables -w 5 -t mangle -A kitewrt_probe -p tcp -j TPROXY "
        "--on-port 7895 --tproxy-mark 0x1 >/dev/null 2>&1; rc=$?; "
        "iptables -w 5 -t mangle -F kitewrt_probe 2>/dev/null; "
        "iptables -w 5 -t mangle -X kitewrt_probe 2>/dev/null; "
        "[ $rc -eq 0 ]"
    )
    rc, _, _ = await router.run(probe, timeout=20.0)
    if rc == 0:
        ok("TPROXY available (LAN capture)")
        return

    info("installing iptables-mod-tproxy (LAN capture)")
    await router.opkg_update()
    await router.run("opkg install iptables-mod-tproxy", check=False, timeout=300.0)
    rc, _, _ = await router.run(probe, timeout=20.0)
    if rc != 0:
        fail(
            "this kernel can't do TPROXY (the iptables TPROXY target is "
            "missing).\n  kitewrt captures LAN traffic with TPROXY, so without "
            "it nothing would be proxied — refusing to install a VPN that "
            "silently wouldn't tunnel.\n  Try: opkg install iptables-mod-tproxy"
        )
    ok("TPROXY available (LAN capture)")


async def ensure_iproute2(router: Router) -> None:
    """Make sure `ip rule` accepts our route-table ID, and fail loudly if not.

    busybox provides an `ip` applet that looks complete and is not: its table
    IDs are capped at 255, and `kitewrt.divert` needs table 2023.

    Verified on stock OpenWrt 21.02.7:

        # ip rule add fwmark 0x2023 lookup 2023
        ip: invalid argument '2023' to 'table ID'

    Without the ip rule the TPROXY target marks packets that nothing routes
    locally, so the capture cannot install at all. The install otherwise
    succeeds end to end -- pre-flight green, daemon healthy, UI working -- and
    then the VPN switch fails with "LAN capture was lost and could not be
    restored". Every non-GL.iNet router hit this; GL.iNet firmware happens to
    ship full iproute2, which is why it went unnoticed.

    Probed by actually adding the rule, for the same reason `ensure_tproxy`
    probes the target: package lists lie in both directions.
    """
    probe = (
        f"ip rule add fwmark {hex(divert_mark())} lookup {_ROUTE_TABLE} >/dev/null 2>&1; rc=$?; "
        f"ip rule del fwmark {hex(divert_mark())} lookup {_ROUTE_TABLE} >/dev/null 2>&1; "
        "[ $rc -eq 0 ]"
    )
    rc, _, _ = await router.run(probe, timeout=20.0)
    if rc == 0:
        ok("iproute2 available (policy routing)")
        return

    info("installing ip-full (busybox `ip` caps route-table IDs at 255)")
    await router.opkg_update()
    await router.run("opkg install ip-full", check=False, timeout=300.0)
    rc, _, _ = await router.run(probe, timeout=20.0)
    if rc != 0:
        fail(
            f"`ip rule ... lookup {_ROUTE_TABLE}` is rejected on this router.\n"
            "  busybox's built-in `ip` caps table IDs at 255; the LAN capture "
            "needs a policy-routing rule into table "
            f"{_ROUTE_TABLE}.\n  Without it nothing would be proxied — refusing "
            "to install a VPN that silently wouldn't tunnel.\n"
            "  Try: opkg update && opkg install ip-full"
        )
    ok("iproute2 available (policy routing)")


async def ensure_ipset(router: Router) -> None:
    """Install ipset if missing. Best-effort, unlike TPROXY.

    Only the `bypass_address` feature needs it, and that is opt-in — without
    ipset the capture still works, everything is just proxied. So a router that
    can't have it gets a warning rather than a refused install.

    It matters where it is used, though: the bypass is what keeps traffic on
    the hardware fast path, and a country-sized list has to be one O(1) set
    match. The tun-era alternative expanded the same list into a kernel route
    per prefix — 21,619 of them on a real router, which took it down.
    """
    # Probe the `-m set` match, not `command -v ipset`. The userspace tool and
    # the xt_set kernel match come from different packages, and a router
    # routinely has one without the other — which reported "✓ ipset present"
    # on a box where the bypass rule could never be added.
    probe = (
        "ipset create kitewrt_probe hash:net family inet 2>/dev/null; "
        "iptables -w 5 -t mangle -N kitewrt_setprobe 2>/dev/null; "
        "iptables -w 5 -t mangle -A kitewrt_setprobe -m set --match-set "
        "kitewrt_probe dst -j RETURN >/dev/null 2>&1; rc=$?; "
        "iptables -w 5 -t mangle -F kitewrt_setprobe 2>/dev/null; "
        "iptables -w 5 -t mangle -X kitewrt_setprobe 2>/dev/null; "
        "ipset destroy kitewrt_probe 2>/dev/null; [ $rc -eq 0 ]"
    )
    rc, _, _ = await router.run(probe, timeout=20.0)
    if rc == 0:
        ok("ipset + xt_set available (traffic bypass)")
        return
    info("installing ipset (for the traffic bypass)")
    await router.opkg_update()
    await router.run(
        "opkg install ipset kmod-ipt-ipset iptables-mod-ipset", check=False, timeout=300.0
    )
    rc, _, _ = await router.run(probe, timeout=20.0)
    if rc == 0:
        ok("ipset installed")
    else:
        warn(
            "ipset unavailable — the capture still works, but `bypass_address` "
            "in your rules will do nothing, so all traffic stays proxied "
            "(and off the router's hardware fast path)"
        )


async def ensure_iptables(router: Router) -> None:
    """Make sure `iptables` exists — both the LAN capture (divert.py) and the
    fail-closed kill switch (killswitch.py) shell out to it. Present on OpenWrt 21.02 /
    GL.iNet (fw3 + iptables-legacy). On a pure fw4/nftables router it may be
    absent; opkg's `iptables` there is the nft-backed compat shim, which the kill
    switch's rules work through. Best-effort: warn (don't fail) if it can't be
    installed, since the daemon still runs — only the reload-window leak guard is
    weakened."""
    rc, _, _ = await router.run("command -v iptables", timeout=10.0)
    if rc == 0:
        ok("iptables present (kill switch)")
        return
    info("installing iptables (kill switch needs it)")
    await router.opkg_update()
    await router.run("opkg install iptables", check=False, timeout=180.0)
    rc, _, _ = await router.run("command -v iptables", timeout=10.0)
    if rc == 0:
        ok("iptables installed")
    else:
        # This used to end "The daemon still works." It does not: the LAN
        # capture is built entirely out of iptables, so without it nothing is
        # ever diverted and the VPN is inert while the UI reports, at best,
        # UNVERIFIED. Measured with iptables removed from PATH: install() False,
        # installed_state() None, remove() False — and every log line blames the
        # xtables lock, which is the worst possible diagnostic on the one router
        # class where this happens.
        warn(
            "iptables unavailable (likely a pure-nftables firewall, i.e. OpenWrt "
            "22.03+ with fw4). The LAN capture cannot be installed at all, so the "
            "daemon will run but no traffic will be proxied. Install "
            "iptables-nft (and iptables-mod-tproxy) before continuing."
        )


async def ensure_bbr(router: Router) -> None:
    """Enable BBR TCP congestion control (kmod-tcp-bbr). BBR holds throughput on
    lossy / long-RTT paths where the default `cubic` collapses on loss — exactly
    the proxy uplink for TCP-carrier nodes (vless/trojan) and any direct TCP.
    hysteria2 carries its own (Brutal) CC, so this is the lever for the rest.

    Best-effort: a router whose kernel has no matching kmod just keeps cubic with
    a warning (BBR is an optimization, never fatal)."""
    _, avail, _ = await router.run(
        "sysctl -n net.ipv4.tcp_available_congestion_control", timeout=10.0
    )
    if "bbr" not in avail:
        info("installing kmod-tcp-bbr")
        await router.opkg_update()
        rc, _, _ = await router.run("opkg install kmod-tcp-bbr", check=False, timeout=180.0)
        if rc != 0:
            warn("kmod-tcp-bbr unavailable for this kernel — keeping cubic (perf only)")
            return
        await router.run(
            "modprobe tcp_bbr 2>/dev/null || insmod tcp_bbr 2>/dev/null", check=False, timeout=15.0
        )
    # Apply now + persist across reboots (sysctl.d sets it, modules.d loads the
    # module first so the sysctl takes). On kernel 4.13+ BBR has internal pacing,
    # so the `fq` qdisc isn't required.
    await router.run("sysctl -w net.ipv4.tcp_congestion_control=bbr", check=False, timeout=10.0)
    await router.run(
        "printf 'net.ipv4.tcp_congestion_control=bbr\\n' > /etc/sysctl.d/99-kitewrt-bbr.conf && "
        "printf 'tcp_bbr\\n' > /etc/modules.d/99-kitewrt-tcp-bbr",
        check=False,
        timeout=10.0,
    )
    _, cc, _ = await router.run("sysctl -n net.ipv4.tcp_congestion_control", timeout=10.0)
    if "bbr" in cc:
        ok("BBR congestion control enabled")
    else:
        warn(f"BBR setup ran but cc is still {cc.strip()!r} — left best-effort")


# --- Download safety ------------------------------------------------------
# sing-box and uv are the two things this installer fetches over the network
# and then runs as root, so they share one checksum gate and one tarball gate.
# They did not: the uv tarball was extracted with no member check at all, and
# the sing-box checksum degraded to a warning. Both are behind a pinned hash,
# which only means the gates matter exactly when the pin is wrong.


async def _tidy(router: Router, cmd: str) -> None:
    """Best-effort cleanup on a failure path. Never raises: it runs while we
    are on our way to `fail()`, and the usual reason a download died is that
    the transport did — so its own failure would replace the real one."""
    with contextlib.suppress(Exception):
        await router.run(cmd, check=False, timeout=20.0)


def _download_error(err: str) -> str:
    """The one line worth showing from a failed curl/wget.

    curl's diagnosis is `curl: (7) Failed to connect to github.com port 443`.
    Around it are a progress meter and, on a TLS failure, a paragraph about
    certificate stores whose last line — "please visit the webpage mentioned
    above" — is the least useful sentence in the output and exactly what a
    naive tail would print. Measured against a blackholed github.com on the
    24.10.0 VM.
    """
    lines = [ln.strip() for ln in err.splitlines() if ln.strip()]
    for line in lines:
        if line.startswith(("curl:", "wget:")):
            return line
    return lines[-1] if lines else "(no output)"


def _artifact_hint(name: str, artifacts_dir: Path | str | None) -> str:
    """The "drop this file here" half of a failed download.

    The failure itself was already truthful — `curl: (7) Failed to connect to
    github.com` — but the fix, the exact filename, was printed by
    `_report_artifacts` about 25 lines and a minute earlier, above an opkg
    install. Nobody scrolls back through that, so repeat it where it is needed.
    """
    where = default_artifacts_dir() if artifacts_dir is None else Path(artifacts_dir)
    return (
        f"  If GitHub is blocked here, download\n    {name}\n"
        f"  on a machine that can reach it, drop it in\n    {where}\n"
        "  and re-run (see installer/artifacts/README.md)."
    )


async def _verify_sha256(
    router: Router, remote_path: str, expected: str, *, what: str, cleanup: str
) -> None:
    """Hard-fail unless `remote_path` hashes to `expected` on the router.

    The sing-box half of this used to end in `warn("sha256sum unavailable on
    the router — skipping checksum verification")` whenever the hash came back
    empty, and then install anyway — so any hiccup in the hashing put an
    unverified root binary on a path whose own comment calls the download
    hostile. It cannot be a hiccup worth shrugging at, because `ensure_tools`
    already hard-fails when sha256sum can't be installed and runs before either
    download: by the time we get here the tool is guaranteed present (measured
    on OpenWrt 21.02.7 and 24.10.0, where it is a busybox applet and ships in
    the base image), so an empty hash means something else is wrong.
    """
    rc, out, _ = await router.run(f"sha256sum {remote_path}", check=False, timeout=120.0)
    got = (out.split() or [""])[0]
    if rc == 0 and got == expected:
        return
    await _tidy(router, cleanup)
    if rc != 0 or not got:
        fail(
            f"could not checksum the {what} download on the router "
            f"(sha256sum exited {rc}, output {out.strip()[:80]!r}).\n"
            "  It runs as root, so it is not installed unverified. sha256sum is a "
            "busybox applet on stock OpenWrt; the pre-flight installs it if missing."
        )
    fail(
        f"{what} checksum mismatch — a tampered download or the wrong file. "
        "Refusing to install it.\n"
        f"    want {expected}\n"
        f"    got  {got}"
    )


# Every member of both tarballs is unpacked by the router's `tar` as root, so
# a tarball we extract is a tarball we trust. What that actually costs was
# measured on the lab VMs with hand-built hostile archives — busybox 1.33.2
# (OpenWrt 21.02.7) and busybox 1.36.1 (24.10.0), and `tar` on OpenWrt *is*
# busybox (`/bin/tar -> busybox`; the 21.02 feed has no GNU tar package at all):
#
#   `../` and absolute members do not escape. busybox rewrites the name itself
#   — "tar: removing leading '/' from member names", on stderr — and lands the
#   file inside the extraction dir, including when the `..` is buried mid-path.
#   So the name check the sing-box path already had never fired on anything
#   busybox would have honoured, and its comment ("busybox tar doesn't guard
#   against them") was wrong. It stays because bsdtar *does* list and extract
#   those names verbatim, and `tar` is whatever the router happens to ship.
#
#   A LINK member does escape, and no name check can see it. With `uv-*/uv` a
#   symlink to an existing file, the `chmod +x` two lines later dereferences
#   it: /tmp/target went from `-rw-r--r--` to `-rwxr-xr-x`, as root, on both
#   busybox versions. A hardlink member does the same and additionally leaves
#   a second name for that file inside the staging dir — and a hardlink is
#   `-type f`, so the sing-box path's `find` would have picked one up and
#   `cat` an arbitrary file's contents into a 0755 /usr/bin/sing-box.
#
# Refusing every link and every non-plain-file costs nothing legitimate: the
# pinned tarballs are four members (dir, LICENSE, sing-box, libcronet.so) and
# three (dir, uv, uvx), all plain. The two listing passes cost 0.57 s each on
# the 22 MB tarball, measured on the aarch64 VM.


def _refuse_unsafe_tarball(tgz: str) -> str:
    """Shell — a `;`-terminated fragment for a `set -e` script — that exits 1
    rather than let `tar` unpack a member we would not want unpacked as root."""
    return (
        # `^[^-d]` is the mode column: anything that is not a plain file or a
        # directory. That catches a symlink on every tar, and a hardlink on
        # GNU/bsdtar (mode `h`). busybox prints a hardlink with a plain `-`
        # mode and an arrow instead, which is the second alternative.
        f"if tar tvzf {tgz} 2>/dev/null | grep -qE '^[^-d]|[[:space:]]->[[:space:]]'; then "
        "echo 'unsafe tarball member: link or special file' >&2; exit 1; fi; "
        # Names come from the plain listing: it is one name per line on every
        # tar, where the verbose format's field order is not.
        f"if tar tzf {tgz} 2>/dev/null | grep -qE '^/|(^|/)[.][.](/|$)'; then "
        "echo 'unsafe tarball member: path traversal' >&2; exit 1; fi; "
    )


# --- Python deps + binary -------------------------------------------------


async def install_python(router: Router) -> None:
    """Ensure python3 is installed (opkg). pip is NOT required — see
    `install_python_deps`, which uses uv and its lockfile instead."""
    # `command -v python3` is not enough on its own: an install interrupted
    # during `opkg install python3` leaves a working interpreter behind with no
    # opkg status entry and, notably, no `python3-urllib`. The next run then
    # reported "✓ python3 installed" and died much later at the dependency
    # smoke test with `ModuleNotFoundError: No module named 'urllib'` — accurate,
    # and pointing at entirely the wrong thing. Reproduced on armv7 24.10.
    # Asking the interpreter to import a stdlib module that ships in a separate
    # opkg package is the cheap way to catch a half-installed one.
    rc, _, _ = await router.run("python3 -c 'import urllib.request'", timeout=15.0)
    if rc != 0:
        info("installing python3 (~30 MB)")
        await router.opkg_update()
        await router.run("opkg install python3", check=True, timeout=600.0)
        rc, _, err = await router.run("python3 -c 'import urllib.request'", timeout=15.0)
        if rc != 0:
            fail(
                "python3 is present but incomplete (its stdlib packages are "
                f"missing): {err.strip()[:200]}\n"
                "    Try: opkg update && opkg install --force-reinstall python3"
            )
    ok("python3 installed")


async def install_uv(
    router: Router, goarch: str, *, artifacts_dir: Path | str | None = None
) -> str:
    """Put a pinned uv on the router and return its path. Staged in /tmp and
    removed by `install_python_deps` once the install is done — it is a build
    tool, not part of the runtime.

    Fetched exactly like sing-box: offline artifact first, then GitHub, with the
    checksum verified before anything is executed. It runs as root and installs
    the code that becomes the data plane's control plane, so an unverified
    download is not acceptable here.
    """
    asset = uv_artifact_name(goarch)
    if asset is None:
        fail(f"no uv build for CPU arch {goarch!r}")
    target = UV_TARGETS[goarch]
    staged = "/tmp/kitewrt_uv"
    await router.run(f"rm -rf {staged} && mkdir -p {staged}", check=True, timeout=20.0)

    local = find_local_artifact(artifacts_dir, asset)
    if local is not None:
        info(f"using bundled uv {UV_VERSION}: {local} (no GitHub fetch)")
        await router.upload_bytes(local.read_bytes(), f"{staged}/uv.tgz")
    else:
        info(f"downloading uv {UV_VERSION} ({target})")
        url = UV_URL_TMPL.format(ver=UV_VERSION, asset=asset)
        try:
            rc, _out, err = await router.run(
                f"curl -fsSL --retry 3 -o {staged}/uv.tgz {url}", check=False, timeout=600.0
            )
        except SSHError as exc:  # transport died, or the 600 s cap ran out
            rc, err = -1, str(exc)
        if rc != 0:
            await _tidy(router, f"rm -rf {staged}")
            fail(
                f"downloading uv {UV_VERSION} failed: {_download_error(err)}\n"
                + _artifact_hint(asset, artifacts_dir)
            )

    await _verify_sha256(
        router,
        f"{staged}/uv.tgz",
        UV_SHA256[target],
        what=f"uv {UV_VERSION}",
        cleanup=f"rm -rf {staged}",
    )

    # The tarball holds uv-<target>/uv. busybox tar has no --strip-components
    # (verified on OpenWrt 21.02: it prints its usage and exits), so extract and
    # move rather than assume GNU tar.
    extract = (
        f"set -e; cd {staged}; "
        + _refuse_unsafe_tarball("uv.tgz")
        + "tar xzf uv.tgz; mv uv-*/uv uv; "
        # Independent of the listing guard, and of parsing another program's
        # output: `chmod +x` follows a symlink, so a `uv-*/uv` that is one turns
        # the next line into "mark an arbitrary file on the router executable,
        # as root" — and then we execute it.
        "if [ ! -f uv ] || [ -L uv ]; then "
        "echo 'extracted uv is not a plain file' >&2; exit 1; fi; "
        "chmod +x uv"
    )
    rc, _out, err = await router.run(extract, check=False, timeout=180.0)
    if rc != 0:
        await _tidy(router, f"rm -rf {staged}")
        detail = err.strip().splitlines()[-1] if err.strip() else "(no output)"
        fail(f"unpacking the uv {UV_VERSION} tarball failed: {detail}")
    _rc, out, _ = await router.run(f"{staged}/uv --version", check=True, timeout=60.0)
    ok(f"uv ready ({out.strip()})")
    return staged


async def install_python_deps(
    router: Router,
    goarch: str,
    *,
    artifacts_dir: Path | str | None = None,
    requirements: bytes | None = None,
) -> None:
    """Install the runtime deps into REMOTE_VENDOR (a `--target` dir, so we
    avoid system site-packages and need no venv). The init script puts
    REMOTE_VENDOR on PYTHONPATH.

    `requirements` is `uv export`'s output — every version pinned to what the
    CI matrix tested, every wheel hashed. The environment markers in it are
    what make one file correct for both the router's python 3.9 and a
    developer's 3.12, so it is exported once and resolved per interpreter.

    This replaced `pip3 install 'fastapi>=0.110,<1'`: ranges meant a router
    provisioned months after a release ran a dependency tree nobody had tested,
    and pip 22.0.4 (what OpenWrt 21.02 ships) resolved them itself. Nothing
    about that failed loudly — it would just be a different FastAPI.
    """
    if requirements is None:
        requirements = export_locked_requirements()

    await router.run(f"mkdir -p {REMOTE_VENDOR}", check=True, timeout=15.0)
    staged = await install_uv(router, goarch, artifacts_dir=artifacts_dir)
    req_path = f"{staged}/requirements.txt"
    await router.upload_bytes(requirements, req_path)

    wheels = find_local_wheels(artifacts_dir)
    remote_wheels = "/tmp/kitewrt_wheels"
    offline = ""
    if wheels:
        info(f"installing deps from {len(wheels)} bundled wheel(s) (offline, no PyPI)")
        try:
            await router.upload_directory(Path(artifacts_dir) / "wheels", remote_wheels)
        except Exception:
            with contextlib.suppress(Exception):
                await router.run(f"rm -rf {remote_wheels}", check=False, timeout=15.0)
            raise
        offline = f"--offline --find-links {remote_wheels}"
    else:
        info(f"installing deps into {REMOTE_VENDOR} (~25 MB)")

    # `--python python3` targets the router's interpreter, not uv's own; the
    # markers in the export then select the 3.9-compatible pins.
    cmd = (
        f"{staged}/uv pip install --python python3 --target {REMOTE_VENDOR} "
        f"--no-cache {offline} --requirements {req_path}"
    )
    rc, _out, err = await router.run(cmd, check=False, timeout=900.0)
    await router.run(f"rm -rf {remote_wheels}", check=False, timeout=15.0)

    if rc != 0 and wheels:
        # The bundle doesn't fit this router — most often a wheels folder built
        # for a different CPU, since pydantic-core is a compiled extension
        # tagged for one arch and one python. The offline bundle exists for
        # routers that *can't* reach PyPI; one that can has nothing to lose.
        warn(
            "the bundled wheels don't satisfy this router (likely built for a "
            "different CPU or python version) — falling back to PyPI.\n"
            f"  uv said: {err.strip().splitlines()[-1] if err.strip() else 'see above'}"
        )
        rc, _out, err = await router.run(
            f"{staged}/uv pip install --python python3 --target {REMOTE_VENDOR} "
            f"--no-cache --requirements {req_path}",
            check=False,
            timeout=900.0,
        )
    await router.run(f"rm -rf {staged}", check=False, timeout=20.0)
    if rc != 0:
        fail(f"installing python deps failed:\n{err.strip()[-800:]}")

    # OpenWrt's python uses a short extension suffix (`.so` / `.cpython-XY.so`),
    # but PyPI wheels ship the long `<mod>.cpython-XY-<arch>-linux-gnu.so` name,
    # so compiled extensions (pydantic-core) aren't found → ModuleNotFoundError.
    # Symlink each to a bare `<mod>.so`, which is always an accepted suffix.
    fixup = (
        f"find {REMOTE_VENDOR} -name '*.cpython-*-linux-*.so' | while read so; do "
        'base=$(echo "$so" | sed "s/\\.cpython-[^.]*-linux-[^.]*\\.so$//"); '
        'ln -sf "$(basename "$so")" "$base.so"; done'
    )
    await router.run(fixup, check=False, timeout=30.0)
    # Full import smoke-test under the ROUTER's interpreter: a missing wheel (a
    # pure-python dep like eval_type_backport on py3.9) or a botched compiled-ext
    # .so fixup (pydantic-core) otherwise crash-loops the daemon at first boot
    # with only logread as evidence. Fail loudly here with a pointer instead.
    rc, out, _ = await router.run(
        f"PYTHONPATH={REMOTE_VENDOR} python3 -c "
        '"import fastapi, uvicorn, httpx, pydantic, websockets, pydantic_core" 2>&1',
        check=False,
        timeout=30.0,
    )
    if rc != 0:
        fail(
            "the daemon's deps don't import under the router's python "
            f"({out.strip()[:200] or 'no output'}).\n"
            "  A wheel is missing or arch/abi-mismatched (the pydantic-core .so "
            "fixup missed, or a pure-python dep absent on py3.9). Check the wheels "
            "match the router's python/arch (kitewrt --probe shows the version)."
        )
    ok("python deps installed")


# The official sing-box release is glibc-linked, so on a musl-only OpenWrt (no
# glibc-compat layer) it won't start — execve fails to find the glibc dynamic
# loader the binary requests — until that loader path resolves. The fix is a
# shim: symlink the musl loader already on the box to the glibc loader path.
# GL.iNet firmware ships a glibc-compat layer so the path already exists (the
# shim is a no-op there); a minimal OpenWrt needs it. The glibc loader name is
# per-arch.
_GLIBC_LOADER = {
    "arm64": "/lib/ld-linux-aarch64.so.1",
    "amd64": "/lib64/ld-linux-x86-64.so.2",
    "armv7": "/lib/ld-linux-armhf.so.3",
}


async def ensure_loader_shim(router: Router, goarch: str) -> None:
    """Make the glibc dynamic-loader path the sing-box binary needs resolve, by
    symlinking the present musl loader to it — when it's missing (musl OpenWrt
    without glibc-compat). Idempotent + best-effort: a no-op when the path
    already resolves (glibc-compat present / shim already made) or the box isn't
    musl. Safe on a musl box: only glibc-linked binaries we add use this path;
    musl binaries reference their own loader directly."""
    glibc = _GLIBC_LOADER.get(goarch)
    if glibc is None:
        return
    rc, _, _ = await router.run(f"[ -e {glibc} ]", timeout=10.0)
    if rc == 0:
        return  # path already resolves — nothing to do
    _, musl, _ = await router.run("ls /lib/ld-musl-*.so.1 2>/dev/null | head -1", timeout=10.0)
    musl = musl.strip()
    if not musl:
        return  # no musl loader → not a musl box; the binary's own loader applies
    # Says "in case", because whether it is needed is per-arch: the x86-64
    # release asks for the glibc loader and does not start without this, while
    # the armv7 release is genuinely static and runs with the symlink moved
    # aside. Announcing it as a fix that was applied made armv7 installs report
    # solving a problem they never had.
    info(f"musl OpenWrt: linking the glibc loader path in case it is needed ({glibc} -> {musl})")
    await router.run(
        f"mkdir -p $(dirname {glibc}) && ln -sf {musl} {glibc}", check=False, timeout=10.0
    )


async def install_singbox(
    router: Router, goarch: str, *, artifacts_dir: Path | str | None = None
) -> None:
    """Install the pinned sing-box binary → /usr/bin/sing-box.

    Uses a pre-placed release tarball from `artifacts_dir` when present (offline
    path — for routers whose ISP blocks GitHub), else downloads it on the router.
    Idempotent: if the right version is already installed, does nothing.
    """
    rc, out, _ = await router.run(f"{SINGBOX_BIN} version 2>/dev/null | head -1", timeout=10.0)
    if rc == 0 and SINGBOX_VERSION in out:
        ok(f"sing-box {SINGBOX_VERSION} already installed")
        return

    name = singbox_artifact_name(SINGBOX_VERSION, goarch)
    local = find_local_artifact(artifacts_dir, name)
    await router.run("set -e; cd /tmp; rm -rf sb_dl; mkdir sb_dl", check=True, timeout=15.0)
    if local is not None:
        info(f"using bundled sing-box {SINGBOX_VERSION}: {local} (no GitHub fetch)")
        await router.upload_bytes(local.read_bytes(), "/tmp/sb_dl/sb.tgz", mode=0o644)
    else:
        url = SINGBOX_URL_TMPL.format(ver=SINGBOX_VERSION, goarch=goarch)
        info(f"downloading sing-box {SINGBOX_VERSION} ({goarch}, ~22 MB)")
        # curl is ensured up front by ensure_tools (busybox wget often can't TLS).
        dl = (
            "set -e; cd /tmp/sb_dl; "
            f"if command -v curl >/dev/null 2>&1; then curl -fL --connect-timeout 15 -o sb.tgz '{url}'; "
            f"else wget -O sb.tgz '{url}'; fi"
        )
        try:
            rc, _out, err = await router.run(dl, check=False, timeout=300.0)
        except SSHError as exc:  # transport died, or the 300 s cap ran out
            rc, err = -1, str(exc)
        if rc != 0:
            await _tidy(router, "rm -rf /tmp/sb_dl")
            fail(
                f"downloading sing-box {SINGBOX_VERSION} failed: {_download_error(err)}\n"
                + _artifact_hint(name, artifacts_dir)
            )
    # Verify the tarball checksum before trusting it — it runs as root and is the
    # whole data plane, and the download path is assumed hostile.
    expected = SINGBOX_SHA256.get(goarch)
    if not expected:
        # Unreachable while the pins cover every arch `goarch_from_uname` can
        # return (a test asserts they do). Kept as a hard stop rather than the
        # `warn(... installing unverified)` it was, so that adding an arch to
        # the uname map and forgetting the hash cannot ship an unverified root
        # binary — it stops the one install instead.
        fail(
            f"no pinned sing-box checksum for arch {goarch!r}. It runs as root and is "
            "the whole data plane, so it is not installed unverified — add the release "
            "hash to SINGBOX_SHA256."
        )
    await _verify_sha256(
        router,
        "/tmp/sb_dl/sb.tgz",
        expected,
        what=f"sing-box {SINGBOX_VERSION}",
        cleanup="rm -rf /tmp/sb_dl",
    )

    # Shared extract + install (the tarball is now at /tmp/sb_dl/sb.tgz either
    # way). Use cat+chmod+mv rather than `install` — coreutils `install` is
    # frequently absent on minimal OpenWrt; mv (rename) over the destination
    # also avoids ETXTBSY if an old sing-box is still running.
    extract = (
        "set -e; cd /tmp/sb_dl; " + _refuse_unsafe_tarball("sb.tgz") + "tar xzf sb.tgz; "
        "BIN=$(find . -name sing-box -type f | head -1); "
        f'cat "$BIN" > {SINGBOX_BIN}.new && chmod 0755 {SINGBOX_BIN}.new '
        f"&& mv {SINGBOX_BIN}.new {SINGBOX_BIN}; "
        "cd /tmp; rm -rf sb_dl"
    )
    rc, _out, err = await router.run(extract, check=False, timeout=120.0)
    if rc != 0:
        await _tidy(router, "rm -rf /tmp/sb_dl")
        detail = err.strip().splitlines()[-1] if err.strip() else "(no output)"
        fail(f"unpacking the sing-box {SINGBOX_VERSION} tarball failed: {detail}")
    # glibc-linked binary on musl → needs the loader shim before it can run.
    await ensure_loader_shim(router, goarch)
    rc, out, _ = await router.run(f"{SINGBOX_BIN} version 2>&1 | head -1", timeout=10.0)
    if rc != 0 or SINGBOX_VERSION not in out:
        cause = (
            "the bundled tarball is the wrong arch or corrupt"
            if local is not None
            else f"GitHub unreachable (drop {name} in {default_artifacts_dir()} — see "
            "installer/artifacts/README.md), or wrong arch"
        )
        fail(
            f"sing-box install verification failed: {out.strip() or '(no output)'}.\n"
            f"  Likely cause: {cause}."
        )
    ok(f"sing-box installed ({out.strip()})")


# --- Deploy ---------------------------------------------------------------


async def deploy_source(router: Router, local_kitewrt_dir: Path | str) -> None:
    info(f"uploading kitewrt/ → {REMOTE_APP}/kitewrt")
    # Stop the daemon first so we can overwrite running files cleanly.
    await router.run(
        f"[ -x {KITEWRT_INIT} ] && {KITEWRT_INIT} stop || true", check=False, timeout=20.0
    )
    await router.upload_directory(local_kitewrt_dir, f"{REMOTE_APP}/kitewrt")
    await router.run(f"mkdir -p {REMOTE_DATA} {SINGBOX_DIR}", check=True, timeout=10.0)
    ok("kitewrt source uploaded")


async def install_init_scripts(
    router: Router,
    singbox_init_bytes: bytes,
    kitewrt_init_bytes: bytes,
) -> None:
    info("installing procd init scripts")
    await router.upload_bytes(singbox_init_bytes, SINGBOX_INIT, mode=0o755)
    await router.upload_bytes(kitewrt_init_bytes, KITEWRT_INIT, mode=0o755)
    await router.run(f"{SINGBOX_INIT} enable", check=False, timeout=15.0)
    await router.run(f"{KITEWRT_INIT} enable", check=False, timeout=15.0)
    ok("init scripts installed + enabled")


async def install_sysupgrade_keep(router: Router) -> None:
    """Keep `/etc/kitewrt` across a firmware upgrade.

    A sysupgrade wipes the overlay, and with it the whole install. The binaries
    are replaceable — rerun the installer — but `/etc/kitewrt/data/state.json`
    holds the subscriptions (with their credentials), the DNS settings and the
    rules URL, and nothing else has a copy. This is not hypothetical: it is how
    this install was lost once already.

    `/lib/upgrade/keep.d/<name>` is the documented OpenWrt mechanism and is what
    every GL.iNet package on this router uses. Listing only `/etc/kitewrt` is
    deliberate: carrying `/usr/lib/kitewrt` across would preserve a Python tree
    built against the *old* firmware's interpreter, which is exactly the kind of
    half-upgraded state a firmware update is supposed to clear.
    """
    info("registering /etc/kitewrt to survive sysupgrade")
    await router.upload_bytes(SYSUPGRADE_KEEP_BODY, SYSUPGRADE_KEEP_PATH, mode=0o644)
    # Says "settings", not "config", and names what it does not cover. The old
    # wording invited the inference that /etc/kitewrt is the durable copy of
    # the subscriptions — which is true across a *firmware upgrade* and false
    # across an uninstall, where `remove_app` deletes it outright. A reader who
    # merges those two into "my config is safe" loses their subscriptions and
    # credentials to a command they thought was reversible.
    ok("settings will survive a firmware upgrade (an uninstall still erases them)")


async def setup_firewall(router: Router) -> None:
    """Install the router-origin MSS-clamp include, a WAN-side DROP on the
    control-UI port, and a fail-closed IPv6 egress block.

    There is no zone for the capture any more. Under the tun inbound we needed
    a `singbox` zone (masq + mtu_fix) and a lan→singbox forwarding rule, because
    captured packets were *forwarded* into a device. TPROXY delivers them to a
    local socket instead: nothing traverses FORWARD, and sing-box's own egress
    is router-origin, which the stock `wan` zone already masquerades. Both
    sections are removed on install so an upgrade from the tun era converges.

    The two IPv6 rules matter more than they used to, because the capture is
    IPv4-only — `kitewrt.divert` speaks `iptables`, not `ip6tables`.

    The egress DROP is the obvious half: forwarded LAN IPv6 would otherwise
    follow the default lan→wan path straight out the WAN, exposing the real
    IPv6 address. That is the exact deanonymization this tool exists to
    prevent, and it is invisible to the IPv4 exit-IP check.

    The DNS REJECT is the half that is easy to miss. odhcpd advertises the
    router as a resolver over IPv6, and dnsmasq listens on the LAN's v6
    addresses. A client that picks the v6 resolver sends queries to the router
    over IPv6 — which is INPUT, not FORWARD, so the egress DROP never sees it
    — and dnsmasq forwards them to the ISP in cleartext while the VPN is on
    and the exit-IP check reads green. REJECT rather than DROP so clients fail
    over to the IPv4 resolver immediately instead of waiting out a timeout;
    that path is captured.

    Both are family-scoped, so IPv4 is untouched. All sections are named, so
    re-running converges rather than stacking duplicates."""
    info("configuring fw3 (MSS clamp + WAN-UI block + IPv6 egress block)")
    await router.run(f"mkdir -p {REMOTE_DATA}", check=True, timeout=15.0)
    await router.upload_bytes(_MSS_CLAMP_SCRIPT, MSS_CLAMP_PATH, mode=0o755)
    script = f"""set -e
# Left over from the tun era — TPROXY needs neither (see the docstring).
uci -q delete firewall.{_FW_ZONE} || true
uci -q delete firewall.{_FW_FWD} || true
uci -q delete firewall.{_FW_MSS} || true
uci set firewall.{_FW_MSS}=include
uci set firewall.{_FW_MSS}.path='{MSS_CLAMP_PATH}'
# No `reload='1'`: fw3 defaults to running includes on reload anyway, and fw4
# does not know the option — it prints
#   [!] Section kitewrt_mss_clamp option 'reload' is not supported by fw4
# on *every* firewall restart, for the rest of the router's life. Measured on
# 24.10.0: fw4 executes the include with or without it, so the flag bought a
# permanent warning and nothing else.
uci -q delete firewall.{_FW_BLOCK_UI} || true
uci set firewall.{_FW_BLOCK_UI}=rule
uci set firewall.{_FW_BLOCK_UI}.name='kitewrt-block-wan-ui'
uci set firewall.{_FW_BLOCK_UI}.src='wan'
uci set firewall.{_FW_BLOCK_UI}.proto='tcp'
uci set firewall.{_FW_BLOCK_UI}.dest_port='{WEB_UI_PORT}'
uci set firewall.{_FW_BLOCK_UI}.target='DROP'
uci -q delete firewall.{_FW_BLOCK_V6} || true
# `src='*'`, not `src='lan'`. A zone-scoped rule lands in that zone's forward
# chain only, so a guest SSID, an IoT VLAN or any second bridge egressed IPv6
# untouched — measured with a packet sniffer, `vpn_on=True` and the capture
# healthy: TCP, UDP and DNS all reached the far side over v6, and since fw3's
# masquerade is v4-only the destination saw the client's real global address.
# That is the deanonymization this rule exists to prevent, and it is invisible
# to the IPv4 exit-IP check. The wildcard puts the jump in FORWARD itself,
# ahead of the per-zone dispatch, so it covers every source zone the way the
# IPv4 capture's unconditional PREROUTING hook already does.
#
# **`dest='*'` for the same reason, and not for symmetry.** `dest='wan'` made
# fw4 render this as a jump into `drop_to_wan`, a chain holding only the devices
# in the fw4 `wan` zone — so when the v6 uplink is not a member of that zone the
# chain is EMPTY and the rule drops nothing. Measured on stock 24.10:
# `vpn_on: true`, `last_apply.ok: true`, the exit-IP check green, and a LAN
# client with a global v6 address got 3/3 ping6 replies from the internet while
# the proxy log stayed empty. The v4 capture does not have this problem because
# it derives the uplink from the actual default route; the v6 block derived it
# from zone membership, and the two disagree the moment a second uplink, an LTE
# failover or a 6in4/WireGuard tunnel lands on a device nobody assigned to
# `wan`. A default armsr install has an empty `wan` zone, so this was
# latent-dead out of the box.
#
# The ULA ACCEPT below keeps routed v6 between local zones working, mirroring
# the reserved-range RETURNs the IPv4 chain already has — a blanket forward DROP
# would otherwise also cut LAN-to-guest v6, which is not egress and was never
# the target. Verified on fw4 that config order is preserved, so the ACCEPT
# really does precede the DROP; same-bridge traffic never reaches FORWARD at
# all, so only inter-zone routing is affected either way.
uci -q delete firewall.{_FW_ALLOW_V6_LOCAL} || true
uci set firewall.{_FW_ALLOW_V6_LOCAL}=rule
uci set firewall.{_FW_ALLOW_V6_LOCAL}.name='kitewrt-allow-ipv6-local'
uci set firewall.{_FW_ALLOW_V6_LOCAL}.src='*'
uci set firewall.{_FW_ALLOW_V6_LOCAL}.dest='*'
uci set firewall.{_FW_ALLOW_V6_LOCAL}.dest_ip='fc00::/7'
uci set firewall.{_FW_ALLOW_V6_LOCAL}.family='ipv6'
uci set firewall.{_FW_ALLOW_V6_LOCAL}.proto='all'
uci set firewall.{_FW_ALLOW_V6_LOCAL}.target='ACCEPT'
uci set firewall.{_FW_BLOCK_V6}=rule
uci set firewall.{_FW_BLOCK_V6}.name='kitewrt-block-ipv6-egress'
uci set firewall.{_FW_BLOCK_V6}.src='*'
uci set firewall.{_FW_BLOCK_V6}.dest='*'
uci set firewall.{_FW_BLOCK_V6}.family='ipv6'
uci set firewall.{_FW_BLOCK_V6}.proto='all'
uci set firewall.{_FW_BLOCK_V6}.target='DROP'
uci -q delete firewall.{_FW_BLOCK_V6_DNS} || true
uci set firewall.{_FW_BLOCK_V6_DNS}=rule
uci set firewall.{_FW_BLOCK_V6_DNS}.name='kitewrt-block-ipv6-dns'
uci set firewall.{_FW_BLOCK_V6_DNS}.src='*'
uci set firewall.{_FW_BLOCK_V6_DNS}.dest_port='53'
uci set firewall.{_FW_BLOCK_V6_DNS}.family='ipv6'
uci set firewall.{_FW_BLOCK_V6_DNS}.proto='tcp udp'
uci set firewall.{_FW_BLOCK_V6_DNS}.target='REJECT'
uci commit firewall
mkdir -p {SINGBOX_DIR} {REMOTE_DATA}
/etc/init.d/firewall reload
"""
    await router.run(script, check=True, timeout=60.0)
    ok("firewall configured (MSS clamp + WAN-UI block + IPv6 egress/DNS block)")


async def start_daemon(router: Router, *, attempts: int = 20, interval_s: float = 1.0) -> None:
    info("starting kitewrt daemon")
    await router.run(f"{KITEWRT_INIT} enable", check=False, timeout=15.0)
    await router.run(f"{KITEWRT_INIT} restart", check=False, timeout=30.0)
    # A listening socket isn't enough — uvicorn can bind then die on a bad import
    # (e.g. the pydantic-core .so fixup missed). Poll the daemon's own
    # /api/health over the loopback and only declare success when it answers.
    health = f"curl -fs -m3 http://127.0.0.1:{WEB_UI_PORT}/api/health 2>/dev/null"
    for _ in range(attempts):
        await asyncio.sleep(interval_s)
        rc, out, _ = await router.run(health, timeout=10.0)
        if rc == 0 and '"ok"' in out:
            ok(f"daemon healthy on :{WEB_UI_PORT}")
            return
    # Not up — surface the log tail so the failure is actionable, then hard-fail
    # rather than printing a misleading "Done".
    _, logs, _ = await router.run(
        "logread 2>/dev/null | grep -i kitewrt | tail -15", check=False, timeout=15.0
    )
    fail(
        f"daemon did not become healthy on :{WEB_UI_PORT} within "
        f"{int(attempts * interval_s)}s.\n  Recent log:\n"
        f"{logs.strip() or '    (no kitewrt log lines — check the opkg / dependency steps above)'}"
    )


# --- Uninstall ------------------------------------------------------------


async def stop_daemon(router: Router) -> None:
    info("stopping daemon")
    await router.run(
        f"[ -x {KITEWRT_INIT} ] && {KITEWRT_INIT} stop || true", check=False, timeout=20.0
    )


async def stop_singbox(router: Router) -> None:
    """Stop sing-box, so the VLESS credentials stop serving traffic. No-op if
    its init script isn't present.

    Note what this does NOT do: the LAN capture is netfilter state owned by the
    kitewrt daemon, not by this process, and it survives the stop. Removing it
    is `remove_capture`'s job, which is why uninstall calls that separately.
    Under the old tun inbound auto_route really did come down with the process,
    and believing that still true is what left uninstalled routers dark."""
    rc, _, _ = await router.run(f"[ -x {SINGBOX_INIT} ]", timeout=5.0)
    if rc != 0:
        return
    info("stopping sing-box (so credentials stop serving traffic)")
    await router.run(f"{SINGBOX_INIT} stop", check=False, timeout=30.0)


async def scrub_singbox_config(router: Router) -> None:
    """Overwrite config.json with a credential-free one (no vless outbounds;
    selector points only at direct), so uninstall doesn't leave the user's
    VLESS UUIDs / servers on disk. Reuses kitewrt's own generator."""
    rc, _, _ = await router.run(f"[ -f {SINGBOX_CONFIG} ]", timeout=5.0)
    if rc != 0:
        return  # never installed; nothing to scrub
    info("scrubbing sing-box config (removing VLESS credentials)")
    from kitewrt.singbox.config import build_config
    from kitewrt.singbox.service import write_config
    from kitewrt.state import Data

    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "config.json"
        write_config(build_config(Data()), local)
        await router.upload_bytes(local.read_bytes(), SINGBOX_CONFIG, mode=0o600)


async def remove_capture(router: Router) -> None:
    """Tear down the runtime netfilter capture, without the daemon's help.

    The daemon creates this and its lifespan teardown destroys it — so uninstall
    used to just stop the daemon and assume. That assumption fails in exactly
    the cases a user reaches for uninstall: the daemon was already dead (SIGKILL,
    crash, procd gave up), so `[ -x init ] && init stop` is a no-op, or its
    bounded 3 s teardown lost the xtables lock. `remove_services` then deletes
    the init script and `remove_app` the package, so `divert.sweep()` can never
    run again either.

    Measured on a real kernel with the daemon already down: after
    stop_daemon + stop_singbox the hook is still `-A PREROUTING -j
    kitewrt_tproxy` with nothing listening on 7895, and a LAN client gets
    neither DNS nor TCP — a dark LAN, no web UI left to fix it from, recoverable
    only over SSH or by a reboot. Uninstall printed "uninstalled".

    Every command is best-effort and idempotent: this runs on routers that
    never had a capture installed.
    """
    info("removing the LAN capture")
    script = f"""
iptables -w 5 -t mangle -D PREROUTING -j {_CAPTURE_CHAIN} 2>/dev/null
while iptables -w 5 -t mangle -D PREROUTING -j {_CAPTURE_CHAIN} 2>/dev/null; do :; done
iptables -w 5 -t mangle -F {_CAPTURE_CHAIN} 2>/dev/null
iptables -w 5 -t mangle -X {_CAPTURE_CHAIN} 2>/dev/null
iptables -w 5 -t mangle -F {_CAPTURE_CHAIN}_probe 2>/dev/null
iptables -w 5 -t mangle -X {_CAPTURE_CHAIN}_probe 2>/dev/null
# The INPUT accept and any stranded kill-switch DROP are matched by comment,
# not by device: the WAN may have changed name since either was inserted.
for t in filter; do
  while iptables -w 5 -t $t -S | grep -q -- '--comment {_INPUT_ACCEPT_COMMENT}'; do
    rule=$(iptables -w 5 -t $t -S | grep -m1 -- '--comment {_INPUT_ACCEPT_COMMENT}' | sed 's/^-A /-D /')
    iptables -w 5 -t $t $rule 2>/dev/null || break
  done
  while iptables -w 5 -t $t -S | grep -q -- '--comment {_KILLSWITCH_COMMENT}'; do
    rule=$(iptables -w 5 -t $t -S | grep -m1 -- '--comment {_KILLSWITCH_COMMENT}' | sed 's/^-A /-D /')
    iptables -w 5 -t $t $rule 2>/dev/null || break
  done
done
while ip rule del fwmark {_TPROXY_MARK} lookup {_ROUTE_TABLE} 2>/dev/null; do :; done
ip route flush table {_ROUTE_TABLE} 2>/dev/null
ipset destroy {_BYPASS_SET} 2>/dev/null
ipset destroy {_BYPASS_SET}_probe 2>/dev/null
exit 0
"""
    await router.run(script, check=False, timeout=90.0)
    ok("LAN capture removed")


async def remove_firewall(router: Router) -> None:
    info("removing fw3 sections")
    deletes = "\n".join(f"uci -q delete firewall.{name} || true" for name in _FW_ALL_SECTIONS)
    script = f"""{deletes}
uci commit firewall
/etc/init.d/firewall reload || true
"""
    await router.run(script, check=False, timeout=60.0)
    # Drop the MSS-clamp rule the include installed (harmless if absent; the
    # include itself is gone, so fw3 won't re-add it).
    await router.run(
        "WAN=$(ip route show default 2>/dev/null | "
        "awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}'); "
        '[ -n "$WAN" ] && iptables -t mangle -D POSTROUTING -o "$WAN" -p tcp '
        "--tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true",
        check=False,
        timeout=15.0,
    )


async def remove_services(router: Router) -> None:
    info("disabling + removing init scripts")
    await router.run(f"rm -f {SYSUPGRADE_KEEP_PATH}", check=False, timeout=10.0)
    for init in (KITEWRT_INIT, SINGBOX_INIT):
        await router.run(f"[ -x {init} ] && {init} disable || true", check=False, timeout=15.0)
        await router.run(f"rm -f {init}", check=False, timeout=10.0)


async def remove_app(router: Router) -> None:
    info(f"removing {REMOTE_APP} + daemon state")
    # /etc/kitewrt/data/state.json holds the parsed servers — VLESS UUIDs,
    # trojan/hysteria/ss passwords, Reality keys — so the "no credentials left on
    # disk" guarantee requires removing it too, not just the package dir. Also
    # drop sing-box's cache.db (derived fakeip map + rule-sets; no credentials,
    # but leaves a clean slate). The config.json was already credential-scrubbed.
    await router.run(
        f"rm -rf {REMOTE_APP} /etc/kitewrt {SINGBOX_DIR}/cache.db",
        check=False,
        timeout=15.0,
    )
