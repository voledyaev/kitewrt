"""CLI output + the password prompt for the installer."""

from __future__ import annotations

import getpass
import sys


def info(msg: str) -> None:
    print(f"  • {msg}")


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def warn(msg: str) -> None:
    print(f"  ! {msg}")


def fail(msg: str) -> None:
    """Print and exit non-zero. Use for unrecoverable install errors."""
    print(f"\n  ✗ {msg}\n", file=sys.stderr)
    sys.exit(1)


def prompt_password(target: str) -> str:
    pw = getpass.getpass(f"SSH password for {target}: ").strip()
    if not pw:
        fail("password is empty")
    return pw
