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


def _report_artifacts(artifacts_dir: Path | str, goarch: str) -> None:
    """Tell the user which offline artifacts were found (so a blocked download
    isn't a surprise). Silent about wheels when none are present — the online
    pip path is the norm; loud about a found/missing sing-box tarball since
    GitHub is the common block."""
    name = steps.singbox_artifact_name(steps.SINGBOX_VERSION, goarch)
    sb = steps.find_local_artifact(artifacts_dir, name)
    wheels = steps.find_local_wheels(artifacts_dir)
    if sb is not None:
        ok(f"offline sing-box found: {sb.name} (will skip GitHub)")
    else:
        info(f"no offline sing-box in {artifacts_dir} — will download {name} from GitHub")
        info(f"  (if GitHub is blocked, drop {name} there and re-run)")
    if wheels:
        ok(f"offline wheels found: {len(wheels)} in {artifacts_dir}/wheels (will skip PyPI)")


def _singbox_init_bytes() -> bytes:
    return resources.files("installer.resources").joinpath("singbox.init").read_bytes()


def _kitewrt_init_bytes() -> bytes:
    return resources.files("installer.resources").joinpath("kitewrt.init").read_bytes()


async def do_install(
    host: str, user: str, password: str, artifacts_dir: Path | str | None = None
) -> None:
    if artifacts_dir is None:
        artifacts_dir = steps.default_artifacts_dir()
    print(f"\n[1/6] Connecting to {user}@{host}...")
    router = await Router.connect(host, user, password)
    try:
        await steps.preflight_openwrt(router)
        await steps.preflight_space(router)
        await steps.ensure_tools(router)
        goarch = await steps.detect_arch(router)
        ok(f"CPU arch: {goarch}")
        _report_artifacts(artifacts_dir, goarch)
        await steps.ensure_tun(router)
        await steps.ensure_iptables(router)
        await steps.ensure_bbr(router)

        print("\n[2/6] Installing python3 + deps...")
        await steps.install_python(router)
        await steps.install_pip_deps(router, artifacts_dir=artifacts_dir)

        print("\n[3/6] Installing sing-box...")
        await steps.install_singbox(router, goarch, artifacts_dir=artifacts_dir)

        print("\n[4/6] Deploying kitewrt...")
        await steps.deploy_source(router, _local_kitewrt_dir())
        await steps.install_init_scripts(router, _singbox_init_bytes(), _kitewrt_init_bytes())

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


async def do_uninstall(host: str, user: str, password: str) -> None:
    print(f"\nConnecting to {user}@{host}...")
    router = await Router.connect(host, user, password)
    try:
        # Order matters:
        # 1. Stop the daemon so its watchdog doesn't restart sing-box.
        # 2. Stop sing-box → tun + auto_route rules disappear, credentials drop.
        # 3. Scrub config.json so no VLESS UUIDs / servers leak.
        # 4. Remove the fw3 sections, init scripts, app files.
        await steps.stop_daemon(router)
        await steps.stop_singbox(router)
        await steps.scrub_singbox_config(router)
        await steps.remove_firewall(router)
        await steps.remove_services(router)
        await steps.remove_app(router)
        ok("uninstalled")
    finally:
        await router.close()
    print("\n  Note: python3, the pip deps, and the sing-box binary are")
    print("  left in place (they survive a re-install). The config is scrubbed")
    print("  — no VLESS credentials left on disk.\n")


async def do_probe(host: str, user: str, password: str) -> None:
    print(f"\nProbing {user}@{host}...")
    router = await Router.connect(host, user, password)
    try:
        _, out, _ = await router.run(
            "uname -a; echo --; "
            "command -v opkg python3 pip3 sing-box fw3 uci iptables; echo --; "
            "[ -e /dev/net/tun ] && echo tun=ok; "
            "echo tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null); "
            f"[ -x {steps.KITEWRT_INIT} ] && echo kitewrt-init=ok; "
            f"[ -x {steps.SINGBOX_INIT} ] && echo singbox-init=ok",
            timeout=20.0,
        )
        print(f"\n{out}\n")
    finally:
        await router.close()
