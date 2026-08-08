"""Top-level installer flows for OpenWrt: install / uninstall / probe."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from installer import steps
from installer.ssh import Router, SSHError
from installer.ui import fail, info, ok


def _local_kitewrt_dir() -> Path:
    """Path to the kitewrt/ package source we ship to the router."""
    here = Path(__file__).resolve().parent
    candidate = here.parent / "kitewrt"
    if not candidate.is_dir():
        raise FileNotFoundError(f"kitewrt/ source dir not found at {candidate}")
    return candidate


async def _connect(host: str, user: str, password: str, port: int) -> Router:
    """Dial the router, or exit with a sentence instead of a stack trace.

    Every flow wraps its work in `try/finally` to "show a clean message instead
    of a Python traceback" — and the connect itself sat one line *above* the
    `try` in all three, so the single most common first-run mistake (a wrong
    root password, or SSH on another port) printed 40 lines of asyncssh and
    asyncio frames. Measured on a stock router.
    """
    try:
        return await Router.connect(host, user, password, port)
    except SSHError as exc:
        fail(
            f"could not connect to {user}@{host}:{port} — {exc}\n"
            "    Check the address, that SSH is enabled, and the root password.\n"
            "    A non-standard SSH port goes in -p/--port."
        )
        raise  # unreachable; fail() exits


def _report_artifacts(artifacts_dir: Path | str, goarch: str) -> None:
    """Tell the user which offline artifacts were found (so a blocked download
    isn't a surprise). Silent about wheels when none are present — the online
    path is the norm; loud about anything fetched from GitHub, since GitHub is
    the common block.

    **uv counts as one of those.** This used to report sing-box only, so a user
    behind a GitHub block read "offline sing-box found (will skip GitHub)",
    concluded they were covered, and was then stopped by a GitHub fetch for uv
    at step [2/6] — which runs *before* sing-box, so the reassurance arrived
    for the later of the two downloads and the run died at the earlier one.
    """
    for label, name in (
        ("sing-box", steps.singbox_artifact_name(steps.SINGBOX_VERSION, goarch)),
        ("uv", steps.uv_artifact_name(goarch)),
    ):
        if name is None:
            continue  # arch with no uv build; install_uv reports that itself
        found = steps.find_local_artifact(artifacts_dir, name)
        if found is not None:
            ok(f"offline {label} found: {found.name} (will skip GitHub)")
        else:
            info(f"no offline {label} in {artifacts_dir} — will download {name} from GitHub")
            info(f"  (if GitHub is blocked, drop {name} there and re-run)")
    # Wheels get reported either way. Silence-when-absent was the same trap one
    # download further on: with both tarballs pre-placed and PyPI blocked, the
    # user read two green "will skip GitHub" ticks and was then killed by a
    # third download nobody had mentioned — `Failed to fetch
    # https://pypi.org/simple/pydantic/`. The artifacts README says outright
    # that ISPs block "GitHub, and occasionally PyPI", so this case is known.
    wheels = steps.find_local_wheels(artifacts_dir)
    if wheels:
        ok(f"offline wheels found: {len(wheels)} in {artifacts_dir}/wheels (will skip PyPI)")
    else:
        info(f"no offline wheels in {artifacts_dir}/wheels — will download deps from PyPI")
        info("  (if PyPI is blocked too, see installer/artifacts/README.md)")


def _singbox_init_bytes() -> bytes:
    return resources.files("installer.resources").joinpath("singbox.init").read_bytes()


def _kitewrt_init_bytes() -> bytes:
    return resources.files("installer.resources").joinpath("kitewrt.init").read_bytes()


async def do_install(
    host: str,
    user: str,
    password: str,
    artifacts_dir: Path | str | None = None,
    *,
    port: int = 22,
) -> None:
    if artifacts_dir is None:
        artifacts_dir = steps.default_artifacts_dir()
    print(f"\n[1/6] Connecting to {user}@{host}...")
    router = await _connect(host, user, password, port)
    try:
        await steps.preflight_openwrt(router)
        await steps.preflight_space(router)
        await steps.ensure_tools(router)
        goarch = await steps.detect_arch(router)
        ok(f"CPU arch: {goarch}")
        _report_artifacts(artifacts_dir, goarch)
        await steps.ensure_iptables(router)
        await steps.ensure_tproxy(router)
        await steps.ensure_iproute2(router)
        await steps.ensure_ipset(router)
        await steps.ensure_bbr(router)

        print("\n[2/6] Installing python3 + deps...")
        await steps.install_python(router)
        await steps.install_python_deps(router, goarch, artifacts_dir=artifacts_dir)

        print("\n[3/6] Installing sing-box...")
        await steps.install_singbox(router, goarch, artifacts_dir=artifacts_dir)

        print("\n[4/6] Deploying kitewrt...")
        await steps.deploy_source(router, _local_kitewrt_dir())
        await steps.install_init_scripts(router, _singbox_init_bytes(), _kitewrt_init_bytes())
        await steps.install_sysupgrade_keep(router)

        print("\n[5/6] Configuring firewall...")
        await steps.setup_firewall(router)

        print("\n[6/6] Starting daemon...")
        await steps.start_daemon(router)  # hard-fails if the daemon never gets healthy

        # Only reached when every step (incl. a healthy daemon) succeeded.
        print("\n  ✓ Done.")
        print(f"\n  Open http://{host}:{steps.WEB_UI_PORT}/ on any device on your LAN.\n")
    except SSHError as exc:
        # A router command failed (opkg/pip timeout, etc.) — show a clean message
        # instead of a Python traceback.
        fail(f"install failed at a router command:\n  {exc}")
    finally:
        await router.close()


async def do_uninstall(host: str, user: str, password: str, *, port: int = 22) -> None:
    print(f"\nConnecting to {user}@{host}...")
    router = await _connect(host, user, password, port)
    try:
        # Order matters:
        # 1. Stop the daemon so its watchdog doesn't restart sing-box.
        # 2. Stop sing-box so nothing is listening behind the capture.
        # 3. Remove the capture ourselves. The daemon's own teardown does it in
        #    the happy path, but uninstall is reached precisely when that did
        #    not happen (daemon already dead, or its bounded teardown lost the
        #    xtables lock) — and steps 5/6 delete the init script and the
        #    package, so nothing can ever sweep it afterwards.
        # 4. Scrub config.json so no VLESS UUIDs / servers leak.
        # 5. Remove the fw3 sections, init scripts, app files.
        await steps.stop_daemon(router)
        await steps.stop_singbox(router)
        await steps.remove_capture(router)
        await steps.scrub_singbox_config(router)
        await steps.remove_firewall(router)
        await steps.remove_services(router)
        await steps.remove_app(router)
        ok("uninstalled")
    finally:
        await router.close()
    # This used to claim the Python deps were left in place. `remove_app` runs
    # `rm -rf /usr/lib/kitewrt`, and the deps live in `vendor/` underneath it,
    # so they go with it — and so does `/etc/kitewrt`, which holds state.json:
    # the subscriptions and their credentials. That is deliberate (it is what
    # "no credentials left on disk" means) but the note said the opposite of
    # the part that costs the user something, and a re-install is therefore a
    # full dependency install, measured at 56 s, not the seconds implied.
    print("\n  Removed: the daemon, its Python dependencies, and /etc/kitewrt —")
    print("  which held your subscriptions and their credentials. Nothing on")
    print("  this router can be used to reconnect.")
    print("\n  Left in place: python3, the sing-box binary, and the BBR sysctl.")
    print("  Re-installing reinstalls the dependencies from scratch (~1 min).\n")


# What the probe looks for. fw3 *and* fw4 because 22.03+ replaced one with the
# other; `ip` because busybox's built-in caps route-table IDs at 255 and the
# capture needs 2023 (the `ip -V` line below says which one is installed).
#
# Several of these are symlinks, and where they point is the answer to the
# question being asked — so the loop below resolves them. `fw3: /sbin/fw3` on
# 22.03+ is the reason: it is a compat symlink to fw4, and printing both lines
# read as "this box has both firewalls". Measured on the 24.10.0 VM, resolving
# turns four cosmetic lines into the ones you actually want:
#   fw3: /sbin/fw3 -> fw4
#   iptables: /usr/sbin/iptables -> /usr/sbin/xtables-nft-multi   (21.02: legacy)
#   ip: /sbin/ip -> /usr/libexec/ip-full                          (not busybox)
#   sha256sum: /usr/bin/sha256sum -> ../../bin/busybox
_PROBE_TOOLS = (
    "opkg python3 pip3 uv sing-box fw3 fw4 nft uci iptables ip6tables ipset ip curl sha256sum"
)

# One `command -v` per tool, in a loop. busybox `ash` takes exactly ONE argument
# here and silently discards the rest, so the previous single call reported opkg
# and nothing else — verified on the lab VM (OpenWrt 21.02.7, kernel 5.4.238):
# `command -v opkg python3 pip3 sing-box fw3 uci iptables` printed `/bin/opkg`,
# rc=0. Nothing complains, which is why it went unnoticed.
#
# The python and wheel-tag block exists because installer/artifacts/README.md
# tells the reader to get `uv pip download`'s `--python-version` and `--platform`
# from here, and neither was printed. `uname -m` already spells the musllinux
# arch (x86_64 / aarch64 / armv7l); musl is detected by its loader rather than
# by `sysconfig`, whose HOST_GNU_TYPE reads `x86_64-openwrt-linux-gnu` on a box
# whose only libc is `/lib/ld-musl-x86_64.so.1` (measured on the same VM).
_PROBE_SCRIPT = f"""
uname -srm
[ -r /etc/openwrt_release ] && . /etc/openwrt_release && echo "openwrt: $DISTRIB_DESCRIPTION"
echo --
for t in {_PROBE_TOOLS}; do
    p=$(command -v "$t" 2>/dev/null)
    if [ -z "$p" ]; then
        echo "$t: not installed"
    elif [ -L "$p" ]; then
        echo "$t: $p -> $(readlink "$p" 2>/dev/null || echo '(symlink)')"
    else
        echo "$t: $p"
    fi
done
echo --
if command -v python3 >/dev/null 2>&1; then
    echo "python: $(python3 -c 'import platform; print(platform.python_version())' 2>&1)"
    pyver=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>&1)
else
    echo "python: not installed (the installer adds it in step [2/6])"
    pyver=
fi
arch=$(uname -m)
# Glob, not "ld-musl-$(uname -m)": on armv7 `uname -m` is armv7l while the
# loader is /lib/ld-musl-armhf.so.1, so the exact form reported glibc on a musl
# box — and the wheel-tag line below is gated on this, so the one architecture
# that most needs the tag was the one that never got it.
if [ -n "$(echo /lib/ld-musl-*.so.1)" ] && [ -e "$(echo /lib/ld-musl-*.so.1 | cut -d' ' -f1)" ]; then
    libc=musl
else
    libc=glibc
fi
echo "arch: $arch ($libc)"
# musllinux_1_1, not _1_2. The tag has to match wheels that actually exist for
# the pinned versions, and pydantic-core — the only compiled dependency, hence
# the only one that can fail — publishes musllinux_1_1 for x86_64, aarch64 and
# armv7l, and nothing newer. Printing _1_2 matched no wheel on any arch, which
# is worse than printing nothing: it is a machine-read value that looks
# authoritative. Verified against PyPI's file list for the pinned version.
if [ "$libc" = musl ] && [ -n "$pyver" ]; then
    echo "--"
    echo "to build an offline wheel bundle, run this on your admin machine:"
    echo "  uv run --no-project --python $pyver --with pip pip download \\\\"
    echo "    --only-binary=:all: --platform musllinux_1_1_$arch \\\\"
    echo "    --python-version $pyver -d installer/artifacts/wheels \\\\"
    echo "    -r installer/resources/requirements.txt"
    echo "  (pip, not uv: uv has no 'download' subcommand. It must run UNDER"
    echo "   python $pyver, or pip reads the requirements' markers against your"
    echo "   own interpreter and resolves a set the router cannot use. And"
    echo "   --no-project, or uv rebuilds this clone's .venv at $pyver without"
    echo "   the installer extra and the next 'uv run kitewrt' cannot import"
    echo "   asyncssh. Recovery if that happens: uv sync --extra installer)"
fi
command -v ip >/dev/null 2>&1 && echo "iproute2: $(ip -V 2>&1 | head -1)"
echo --
[ -e /dev/net/tun ] && echo tun=ok
echo tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
[ -x {steps.KITEWRT_INIT} ] && echo kitewrt-init=ok
[ -x {steps.SINGBOX_INIT} ] && echo singbox-init=ok
exit 0
"""


async def do_probe(host: str, user: str, password: str, *, port: int = 22) -> None:
    print(f"\nProbing {user}@{host}...")
    router = await _connect(host, user, password, port)
    try:
        _, out, _ = await router.run(_PROBE_SCRIPT, timeout=20.0)
        print(f"\n{out}\n")
    finally:
        await router.close()
