"""Install / uninstall steps for kitewrt on OpenWrt.

Each function is one logical operation against the router; flows.py calls them
in a fixed order. The router is a normal Linux box — opkg for packages, procd
init scripts, fw3 for the firewall — so there's no Entware bootstrap, no USB
drive, and no reboot.

Data plane = sing-box with a single `tun` inbound (auto_route). The installer
fetches the sing-box binary, deploys the daemon + its python deps, writes the
procd init scripts and the fw3 zone for the tun, then starts the daemon;
kitewrt generates config.json and drives sing-box via the Clash API at runtime.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from installer.parsers import goarch_from_uname, is_openwrt
from installer.ssh import Router
from installer.ui import fail, info, ok, warn

# --- Constants ------------------------------------------------------------

REMOTE_APP = "/usr/lib/kitewrt"  # package source + vendored deps
REMOTE_VENDOR = "/usr/lib/kitewrt/vendor"
REMOTE_DATA = "/etc/kitewrt/data"
KITEWRT_INIT = "/etc/init.d/kitewrt"
# 8088, not 8080 — GL.iNet's uhttpd already binds 8080.
WEB_UI_PORT = 8088

SINGBOX_DIR = "/etc/sing-box"
SINGBOX_CONFIG = "/etc/sing-box/config.json"
SINGBOX_BIN = "/usr/bin/sing-box"
SINGBOX_INIT = "/etc/init.d/singbox"

# sing-box official Go release (one binary per arch — no separate musl build).
# It IS glibc-linked, so on a musl-only OpenWrt it needs a loader shim to start
# (see ensure_loader_shim). Pinned to the version proven on the Flint 2.
SINGBOX_VERSION = "1.13.13"
SINGBOX_URL_TMPL = (
    "https://github.com/SagerNet/sing-box/releases/download/"
    "v{ver}/sing-box-{ver}-linux-{goarch}.tar.gz"
)
# Pinned SHA256 of each official release tarball — the binary runs as root and
# IS the data plane, and the download path is assumed hostile (the offline mode
# exists because the ISP blocks GitHub), so verify before trusting it. Arches
# without a pinned hash are installed with a warning rather than blocked.
SINGBOX_SHA256 = {
    "arm64": "d7fab87b921933eb281d8ee7bd5377cdd8228089f1f7c807c9363a6a2329286c",
    "amd64": "bb99cabf47694625db421ee17898f36cdc1f9c2cb5decf65b12bac8d8437e842",
    "armv7": "3df25c595c8a669fb27d6ffae844dbe8bc049d11b181ae39cffc6e3b0a6b0e9f",
}


# --- Offline artifacts ----------------------------------------------------
# Some ISPs block GitHub (and occasionally PyPI) from the router's WAN, which
# breaks the on-router download of sing-box (and the pip deps). As an escape
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
    """Wheel files under `artifacts_dir/wheels` (for an offline pip install),
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

# Python deps the daemon needs on the router. Pinned to majors known to work.
# `websockets` is what uvicorn uses to serve the /ws push channel; pure-Python.
# (pydantic-core is a Rust wheel — pip resolves the musllinux aarch64 build on
# the router; verified on the Flint during deploy.)
PIP_PACKAGES = (
    "fastapi>=0.110,<1",
    "uvicorn>=0.27,<1",
    "websockets>=12,<16",
    "httpx>=0.27,<1",
    "pydantic>=2,<3",
    # OpenWrt ships python 3.9; pydantic needs this to evaluate PEP-604
    # (`X | None`) annotations on <3.10. Pure-python, tiny.
    "eval_type_backport",
)

# fw3 named uci sections (idempotent: re-running overwrites the same names
# rather than stacking anonymous duplicates).
_FW_ZONE = "kitewrt_singbox"
_FW_FWD = "kitewrt_lan2singbox"
_FW_MSS = "kitewrt_mss_clamp"
TUN_DEVICE = "singtun"

# Router-origin MSS clamp. The wan zone clamps *forwarded* LAN traffic, but the
# daemon's OWN HTTPS (subscription / rules / DoH bootstrap / exit-IP) on the raw
# WAN is not — and on a PMTU-limited upstream (double-NAT / PPPoE) that
# black-holes on large packets (TLS hangs, ping+DNS still work). Proven real on
# the Flint 2. Shipped as a firewall include so it re-applies on every reload +
# reboot; idempotent (delete-then-add); detects the WAN at run time.
# NOTE: this is a shell-script include, which fw3 (OpenWrt 21.02) runs but fw4
# (22.03+, nftables) does NOT — so on a pure-fw4 router the clamp silently
# degrades (the core VPN still works; only router-origin PMTU on a constrained
# upstream is affected). See docs/openwrt-notes.md.
MSS_CLAMP_PATH = "/etc/kitewrt/mss-clamp.sh"
_MSS_CLAMP_SCRIPT = b"""#!/bin/sh
# kitewrt: clamp router-origin TCP MSS to PMTU on the WAN (see installer notes).
WAN=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
[ -z "$WAN" ] && exit 0
iptables -t mangle -D POSTROUTING -o "$WAN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
iptables -t mangle -A POSTROUTING -o "$WAN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
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


# python3 (~30 MB) + the pip deps (~25 MB) + the sing-box binary (~54 MB
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
                    f"only ~{free_mb} MB free on {path}; python3 + the pip deps need "
                    f"~{MIN_OVERLAY_MB} MB. Free up space (or use a device with a roomier "
                    "overlay) and retry."
                )
            ok(f"disk space OK (~{free_mb} MB free on {path})")
            return


async def ensure_tun(router: Router) -> None:
    """Make sure the tun device node exists. Most GL.iNet/OpenWrt builds have
    kmod-tun built in; install it only when /dev/net/tun is missing."""
    rc, _, _ = await router.run("[ -e /dev/net/tun ]", timeout=10.0)
    if rc == 0:
        ok("kmod-tun present (/dev/net/tun)")
        return
    info("installing kmod-tun")
    await router.opkg_update()
    await router.run("opkg install kmod-tun", check=True, timeout=180.0)
    await router.run("[ -e /dev/net/tun ] || modprobe tun", check=False, timeout=15.0)
    rc, _, _ = await router.run("[ -e /dev/net/tun ]", timeout=10.0)
    if rc != 0:
        fail("kmod-tun installed but /dev/net/tun still missing — tun unsupported?")
    ok("kmod-tun installed")


async def ensure_iptables(router: Router) -> None:
    """Make sure `iptables` exists — the fail-closed kill switch (killswitch.py)
    shells out to it. Present on OpenWrt 21.02 /
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
        warn(
            "iptables unavailable (likely pure-nftables firewall) — the fail-closed "
            "kill switch won't engage during reloads. The daemon still works."
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


# --- Python deps + binary -------------------------------------------------


async def install_python(router: Router) -> None:
    """Ensure python3 + pip are installed (opkg)."""
    rc, _, _ = await router.run("command -v python3", timeout=10.0)
    if rc != 0:
        info("installing python3 (~30 MB)")
        await router.opkg_update()
        await router.run("opkg install python3", check=True, timeout=600.0)
    rc, _, _ = await router.run("command -v pip3", timeout=10.0)
    if rc != 0:
        info("installing python3-pip")
        await router.run("opkg install python3-pip", check=True, timeout=300.0)
    ok("python3 + pip installed")


async def install_pip_deps(router: Router, *, artifacts_dir: Path | str | None = None) -> None:
    """Install kitewrt's pip dependencies into REMOTE_VENDOR (a --target dir,
    so we avoid the system site-packages and need no venv). The init script
    puts REMOTE_VENDOR on PYTHONPATH.

    Uses pre-placed wheels from `artifacts_dir/wheels` when present (offline path
    — `pip install --no-index`), else resolves from PyPI on the router.
    """
    await router.run(f"mkdir -p {REMOTE_VENDOR}", check=True, timeout=15.0)
    packages = " ".join(f"'{p}'" for p in PIP_PACKAGES)
    wheels = find_local_wheels(artifacts_dir)
    if wheels:
        info(f"installing pip deps from {len(wheels)} bundled wheel(s) (offline, no PyPI)")
        remote_wheels = "/tmp/kitewrt_wheels"
        # One tar upload of the whole wheels dir (cheaper than N base64 streams).
        await router.upload_directory(Path(artifacts_dir) / "wheels", remote_wheels)
        # --no-index + --find-links: resolve strictly from the uploaded wheels.
        cmd = (
            f"pip3 install --no-cache-dir --no-index --find-links={remote_wheels} "
            f"--target={REMOTE_VENDOR} {packages}"
        )
        await router.run(cmd, check=True, timeout=600.0)
        await router.run(f"rm -rf {remote_wheels}", check=False, timeout=15.0)
    else:
        info(f"installing pip deps into {REMOTE_VENDOR} (~25 MB, may take 1-3 min)")
        # --no-cache-dir keeps the (small) overlay from filling with pip's cache.
        cmd = f"pip3 install --no-cache-dir --target={REMOTE_VENDOR} {packages}"
        await router.run(cmd, check=True, timeout=900.0)
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
    ok("pip deps installed")


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
    info(f"musl OpenWrt: shimming the glibc loader ({glibc} -> {musl})")
    await router.run(
        f"mkdir -p $(dirname {glibc}) && ln -sf {musl} {glibc}", check=False, timeout=10.0
    )


async def install_singbox(
    router: Router, goarch: str, *, artifacts_dir: Path | str | None = None
) -> None:
    """Install the pinned sing-box (static Go) binary → /usr/bin/sing-box.

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
        await router.run(dl, check=True, timeout=300.0)
    # Verify the tarball checksum before trusting it — it runs as root and is the
    # whole data plane, and the download path is assumed hostile.
    expected = SINGBOX_SHA256.get(goarch)
    if expected:
        _, got, _ = await router.run(
            "sha256sum /tmp/sb_dl/sb.tgz 2>/dev/null | awk '{print $1}'", timeout=30.0
        )
        got = got.strip()
        if got and got != expected:
            fail(
                f"sing-box checksum mismatch (got {got[:16]}…, want {expected[:16]}…) — "
                "tampered download or wrong file. Refusing to install."
            )
        if not got:
            warn("sha256sum unavailable on the router — skipping checksum verification")
    else:
        warn(f"no pinned checksum for arch {goarch!r} — installing unverified")

    # Shared extract + install (the tarball is now at /tmp/sb_dl/sb.tgz either
    # way). Refuse path-traversal/absolute members first (busybox tar doesn't
    # guard against them). Use cat+chmod+mv rather than `install` — coreutils
    # `install` is frequently absent on minimal OpenWrt; mv (rename) over the
    # destination also avoids ETXTBSY if an old sing-box is still running.
    extract = (
        "set -e; cd /tmp/sb_dl; "
        "if tar tzf sb.tgz | grep -qE '^/|(^|/)[.][.](/|$)'; then "
        "echo 'unsafe tarball member' >&2; exit 1; fi; "
        "tar xzf sb.tgz; "
        "BIN=$(find . -name sing-box -type f | head -1); "
        f'cat "$BIN" > {SINGBOX_BIN}.new && chmod 0755 {SINGBOX_BIN}.new '
        f"&& mv {SINGBOX_BIN}.new {SINGBOX_BIN}; "
        "cd /tmp; rm -rf sb_dl"
    )
    await router.run(extract, check=True, timeout=120.0)
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


async def setup_firewall(router: Router) -> None:
    """Create the fw3 zone for the tun device + lan→zone forwarding + the
    router-origin MSS-clamp include. All sections are named, so re-running
    converges rather than stacking duplicates."""
    info("configuring fw3 (tun zone + lan forwarding + WAN MSS clamp)")
    await router.run(f"mkdir -p {REMOTE_DATA}", check=True, timeout=15.0)
    await router.upload_bytes(_MSS_CLAMP_SCRIPT, MSS_CLAMP_PATH, mode=0o755)
    script = f"""set -e
uci -q delete firewall.{_FW_ZONE} || true
uci set firewall.{_FW_ZONE}=zone
uci set firewall.{_FW_ZONE}.name='singbox'
uci set firewall.{_FW_ZONE}.input='ACCEPT'
uci set firewall.{_FW_ZONE}.output='ACCEPT'
uci set firewall.{_FW_ZONE}.forward='ACCEPT'
uci set firewall.{_FW_ZONE}.masq='1'
uci set firewall.{_FW_ZONE}.mtu_fix='1'
uci add_list firewall.{_FW_ZONE}.device='{TUN_DEVICE}'
uci -q delete firewall.{_FW_FWD} || true
uci set firewall.{_FW_FWD}=forwarding
uci set firewall.{_FW_FWD}.src='lan'
uci set firewall.{_FW_FWD}.dest='singbox'
uci -q delete firewall.{_FW_MSS} || true
uci set firewall.{_FW_MSS}=include
uci set firewall.{_FW_MSS}.path='{MSS_CLAMP_PATH}'
uci set firewall.{_FW_MSS}.reload='1'
uci commit firewall
mkdir -p {SINGBOX_DIR} {REMOTE_DATA}
/etc/init.d/firewall reload
"""
    await router.run(script, check=True, timeout=60.0)
    ok("firewall configured (tun zone + router-origin MSS clamp)")


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
        f"{logs.strip() or '    (no kitewrt log lines — check opkg/pip steps above)'}"
    )


# --- Uninstall ------------------------------------------------------------


async def stop_daemon(router: Router) -> None:
    info("stopping daemon")
    await router.run(
        f"[ -x {KITEWRT_INIT} ] && {KITEWRT_INIT} stop || true", check=False, timeout=20.0
    )


async def stop_singbox(router: Router) -> None:
    """Stop sing-box (drops the tun + auto_route rules and the in-memory VLESS
    credentials). No-op if its init script isn't present."""
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


async def remove_firewall(router: Router) -> None:
    info("removing fw3 sections")
    script = f"""uci -q delete firewall.{_FW_ZONE} || true
uci -q delete firewall.{_FW_FWD} || true
uci -q delete firewall.{_FW_MSS} || true
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
