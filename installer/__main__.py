"""kitewrt installer — Mac-side tool that brings up the daemon on an OpenWrt
router over SSH.

End-to-end flow on a clean router (no Entware, no USB, no reboot):
  1. SSH as root → a normal POSIX shell
  2. Pre-flight: confirm OpenWrt + opkg, detect arch, ensure kmod-tun
  3. opkg install python3 + pip; pip-install the daemon's deps to a target dir
  4. Fetch the sing-box (static Go) binary → /usr/bin/sing-box
  5. Upload kitewrt/ source, install the procd init scripts (singbox + kitewrt)
  6. Set up the fw3 tun zone (+ lan forwarding); start the daemon

No router credentials are stored on the device. Re-running the installer is
safe — each step is idempotent.

For a router whose ISP blocks GitHub/PyPI, pre-download the sing-box tarball
(and optionally pip wheels) on a machine that can reach them and drop them in
the artifacts dir (default installer/artifacts/, see its README) — the
installer uses them instead of fetching. Override the dir with --artifacts-dir.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from installer import flows, ui


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="kitewrt",
        description="Install / uninstall the kitewrt VPN daemon on an OpenWrt router.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  kitewrt root@192.168.8.1\n"
        "  kitewrt --uninstall root@192.168.8.1\n"
        "  kitewrt --probe root@192.168.8.1",
    )
    parser.add_argument("target", help="user@host (e.g. root@192.168.8.1)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--uninstall", action="store_true", help="uninstall instead of install")
    group.add_argument(
        "--probe",
        action="store_true",
        help="connect and report router state without making changes",
    )
    parser.add_argument(
        "--password-env", metavar="VAR", help="read password from this env var instead of prompting"
    )
    parser.add_argument(
        "--artifacts-dir",
        metavar="DIR",
        help="folder holding pre-downloaded sing-box tarball / pip wheels for an "
        "offline install (default: installer/artifacts/)",
    )
    args = parser.parse_args()

    user, _, host = args.target.partition("@")
    if not user or not host:
        parser.error(f"target must look like user@host (got {args.target!r})")

    if args.password_env:
        password = os.environ.get(args.password_env, "")
        if not password:
            ui.fail(f"env var {args.password_env} is empty")
    else:
        password = ui.prompt_password(args.target)

    try:
        if args.probe:
            asyncio.run(flows.do_probe(host, user, password))
        elif args.uninstall:
            asyncio.run(flows.do_uninstall(host, user, password))
        else:
            artifacts = Path(args.artifacts_dir) if args.artifacts_dir else None
            if artifacts is not None and not artifacts.is_dir():
                ui.warn(f"--artifacts-dir {artifacts} does not exist; offline files won't be found")
            asyncio.run(flows.do_install(host, user, password, artifacts_dir=artifacts))
    except KeyboardInterrupt:
        print("\n  ! interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
