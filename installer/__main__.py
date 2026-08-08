"""kitewrt installer — Mac-side tool that brings up the daemon on an OpenWrt
router over SSH.

End-to-end flow on a clean router (no Entware, no USB, no reboot):
  1. SSH as root → a normal POSIX shell
  2. Pre-flight: confirm OpenWrt + opkg, detect arch, ensure iptables/tproxy,
  3. opkg install python3 + pip; pip-install the daemon's deps to a target dir
  4. Fetch the pinned sing-box binary → /usr/bin/sing-box (musl loader shim)
  5. Upload kitewrt/ source, install the procd init scripts (singbox + kitewrt)
  6. Install the fw3 MSS clamp + IPv6 blocks; start the daemon

No router credentials are stored on the device. Re-running the installer is
safe — each step is idempotent.

For a router whose ISP blocks GitHub/PyPI, pre-download the sing-box tarball
(and optionally wheels) on a machine that can reach them and drop them in
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
        # `uv run`, not a bare `kitewrt`: the entry point is installed into the
        # repo's uv environment and is not on PATH, so every example printed
        # here used to be a `command not found` the reader had just been told
        # to type. Substitute your own router address.
        epilog="Examples (run from the clone):\n"
        "  uv run kitewrt root@192.168.8.1\n"
        "  uv run kitewrt --uninstall root@192.168.8.1\n"
        "  uv run kitewrt --probe root@192.168.8.1",
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
        "-p",
        "--port",
        type=int,
        default=22,
        metavar="N",
        help="SSH port (default: 22)",
    )
    parser.add_argument(
        "--password-env", metavar="VAR", help="read password from this env var instead of prompting"
    )
    parser.add_argument(
        "--artifacts-dir",
        metavar="DIR",
        help="folder holding the pre-downloaded sing-box and uv tarballs + wheels/ for an "
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
            asyncio.run(flows.do_probe(host, user, password, port=args.port))
        elif args.uninstall:
            asyncio.run(flows.do_uninstall(host, user, password, port=args.port))
        else:
            artifacts = Path(args.artifacts_dir) if args.artifacts_dir else None
            if artifacts is not None and not artifacts.is_dir():
                ui.warn(f"--artifacts-dir {artifacts} does not exist; offline files won't be found")
            asyncio.run(
                flows.do_install(host, user, password, artifacts_dir=artifacts, port=args.port)
            )
    except KeyboardInterrupt:
        print("\n  ! interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
