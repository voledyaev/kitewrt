"""Pure-function parsers for the OpenWrt installer.

Kept tiny and side-effect-free so they're unit-testable with canned text.
OpenWrt gives us a normal Linux shell with real exit codes, so the installer
reads plain command output (`uname -m`, `/etc/os-release`) — no custom-CLI
scraping needed.
"""

from __future__ import annotations

# `uname -m` machine → sing-box release GOARCH. One build per CPU arch, with no
# libc-specific variant to choose — but "static Go binary" is not why, and the
# truth turns out to be per-arch. Measured:
#
#   x86-64: dynamically linked, asks for /lib64/ld-linux-x86-64.so.2 (glibc),
#           on a musl OpenWrt. `ensure_loader_shim` is what makes it run.
#   armv7:  genuinely static — no PT_INTERP at all. `ld-musl-armhf.so.1 --list`
#           says "Not a valid dynamic program", and the binary runs with the
#           shim symlink moved aside.
#
# So the shim is load-bearing on at least one arch and a no-op on another.
# Do not delete it on the strength of whichever arch you happen to test, which
# is exactly how this comment came to claim the opposite twice.
_UNAME_TO_GOARCH = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "armv7",
    "armv7": "armv7",
}


def goarch_from_uname(uname_m: str) -> str:
    """Map `uname -m` output to the sing-box release GOARCH token.

    Raises ValueError for an arch we have no mapping for, so the installer
    fails with a clear message rather than fetching a 404 tarball.
    """
    key = uname_m.strip().lower()
    if key not in _UNAME_TO_GOARCH:
        raise ValueError(
            f"unsupported CPU arch {uname_m.strip()!r} "
            f"(known: {', '.join(sorted(set(_UNAME_TO_GOARCH)))})"
        )
    return _UNAME_TO_GOARCH[key]


def is_openwrt(os_release: str) -> bool:
    """True if the contents of /etc/os-release (or /etc/openwrt_release)
    identify OpenWrt. GL.iNet firmware is OpenWrt-based and reports OpenWrt
    here too."""
    return "openwrt" in os_release.lower()
