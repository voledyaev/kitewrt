"""Pure-function parsers for the OpenWrt installer.

Kept tiny and side-effect-free so they're unit-testable with canned text.
OpenWrt gives us a normal Linux shell with real exit codes, so the installer
reads plain command output (`uname -m`, `/etc/os-release`) — no custom-CLI
scraping needed.
"""

from __future__ import annotations

# `uname -m` machine → sing-box release GOARCH. sing-box ships static Go
# binaries (CGO disabled), so a single build per CPU arch runs on glibc and
# musl alike — there's no libc-specific variant to choose.
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
