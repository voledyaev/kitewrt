"""sing-box process control + config writing.

sing-box is supervised by its procd init script (/etc/init.d/singbox); kitewrt
writes config.json and start/stop/restarts the service. Capture is owned by
sing-box itself — the `tun` inbound's auto_route installs the LAN policy routes
— so there are no separate capture rules for kitewrt to manage.

Server switching and on/off are live Clash API calls (no restart). This service
is touched only for structural reloads (servers/rules/DNS).

A reload restarts the process, which briefly drops the tun (and with it the
auto_route capture), so restart() is bracketed by a fail-closed kill switch —
that window can't leak forwarded traffic to the WAN. The live-switch path has
no such window, so it needs no guard.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from kitewrt import killswitch

SINGBOX_BIN = "/usr/bin/sing-box"
SINGBOX_INIT = "/etc/init.d/singbox"
SINGBOX_CONFIG = "/etc/sing-box/config.json"
# sing-box's persisted cache (remote rule-sets + fakeip map + selector choice).
# Mirrors config.CACHE_FILE; kept as a literal here to avoid an import cycle.
SINGBOX_CACHE = "/etc/sing-box/cache.db"

# A reload restarts the process (re-reads config, rebinds the inbounds,
# reconnects) — give it room before assuming it hung.
DEFAULT_TIMEOUT_S = 60.0


def write_config(cfg: dict[str, Any], path: str | Path = SINGBOX_CONFIG) -> None:
    """Durably write the generated sing-box config to disk (tmp → fsync →
    rename → dir fsync).

    The config carries VLESS credentials and is the data plane's source of
    truth; an unclean power-off (unplugging the router) must not leave a
    zero-length config that crash-loops sing-box on the next boot. fsync makes
    the bytes and the rename durable, not just crash-atomic.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(cfg, indent=2).encode()
    tmp = p.with_suffix(p.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        # Loop os.write: a single call may write fewer bytes than asked (e.g. a
        # partial write before ENOSPC), and fsync+rename of a truncated config
        # would crash-loop sing-box on the next boot.
        mv = memoryview(raw)
        while mv:
            mv = mv[os.write(fd, mv) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, p)
    try:
        dir_fd = os.open(p.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


class SingBoxService:
    """sing-box lifecycle via its init script, async-friendly."""

    def __init__(
        self,
        init_path: str | Path = SINGBOX_INIT,
        bin_path: str | Path = SINGBOX_BIN,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        *,
        cache_path: str | Path = SINGBOX_CACHE,
        killswitch_enabled: bool = False,
    ):
        self._init = Path(init_path)
        self._bin = Path(bin_path)
        self._cache = Path(cache_path)
        self._timeout = timeout_s
        # Off by default so unit tests (fake init script) never touch real
        # iptables; production enables it in the lifespan.
        self._killswitch_enabled = killswitch_enabled

    def installed(self) -> bool:
        """True when the sing-box binary exists as a regular file."""
        return self._bin.is_file()

    async def check_config(self, path: str | Path) -> tuple[bool, str]:
        """Validate a config with `sing-box check -c <path>` before we promote
        it over the running one. Returns (ok, reason). A one-shot command that
        exits (no daemon fork), so unlike restart we can safely capture stderr
        for the actual rejection reason. With no binary (dev/CI) it's a no-op
        pass — the daemon can't validate what it can't run."""
        if not self.installed():
            return True, ""
        code, out = await _run_capture([str(self._bin), "check", "-c", str(path)], timeout_s=20.0)
        if code == 0:
            return True, ""
        return False, " ".join(out.split())[:300] or f"sing-box check exit {code}"

    async def drop_cache(self) -> None:
        """Delete sing-box's cache.db. It's derived data (remote rule-sets +
        fakeip map + selector), so dropping it just forces a re-download — but a
        *corrupt* cache.db (e.g. an unclean power-off mid-write) can wedge
        startup, and clearing it turns that brick into a self-heal. Best-effort."""
        try:
            self._cache.unlink()
        except OSError:
            pass

    async def start(self) -> tuple[bool, str]:
        return await self._guarded("start")

    async def stop(self) -> tuple[bool, str]:
        # Unguarded: stopping sing-box means VPN-off-direct is intended (no
        # kill switch). With the selector→direct model we rarely stop at all.
        return await self._invoke("stop")

    async def restart(
        self, *, after: Callable[[], Awaitable[None]] | None = None
    ) -> tuple[bool, str]:
        """Restart sing-box. `after`, if given, runs *inside* the kill-switch
        bracket after a successful restart — used to re-assert the selector
        before the DROP lifts, so the reload window can't leak via whatever
        sing-box restored from cache_file (possibly `direct`)."""
        return await self._guarded("restart", after=after)

    async def is_running(self) -> bool:
        code, _ = await _run(["pidof", "sing-box"], timeout_s=5.0)
        return code == 0

    async def _guarded(
        self, action: str, *, after: Callable[[], Awaitable[None]] | None = None
    ) -> tuple[bool, str]:
        """Run a start/restart bracketed by the fail-closed kill switch — the
        reload window tears the capture rules down and would otherwise leak.
        `after` (the selector re-assertion) runs inside the bracket, so the DROP
        stays engaged until traffic is flowing through the intended outbound."""
        if not self.installed() or not self._killswitch_enabled:
            ok, msg = await self._invoke(action)
            if ok and after is not None:
                await after()
            return ok, msg
        wan = await killswitch.detect_wan()
        engaged = await killswitch.engage(wan) if wan else False
        try:
            ok, msg = await self._invoke(action)
            if ok and after is not None:
                await after()
            return ok, msg
        finally:
            if engaged:
                await killswitch.disengage(wan)

    async def _invoke(self, action: str) -> tuple[bool, str]:
        if not self.installed():
            return True, "sing-box not installed; skipped (config still written)"
        code, err = await _run([str(self._init), action], timeout_s=self._timeout)
        if err:
            return False, err
        if code != 0:
            return False, f"sing-box {action} exit {code}"
        return True, ""


async def _run_capture(argv: list[str], timeout_s: float) -> tuple[int, str]:
    """Like `_run` but captures stdout+stderr — safe ONLY for one-shot commands
    that exit (e.g. `sing-box check`), never for the daemon-forking init script
    (whose forked child would keep the pipe open and hang communicate())."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except FileNotFoundError as exc:
        return -1, str(exc)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, f"timed out after {timeout_s:g}s"
    return proc.returncode or 0, (out or b"").decode(errors="replace")


async def _run(argv: list[str], timeout_s: float) -> tuple[int, str]:
    """Run `argv` with stdio fully discarded; return (exit_code, err_message).

    The init script forks sing-box, which inherits our fds — piping them
    would make proc.wait() block forever on the long-lived daemon. DEVNULL
    breaks the inheritance chain. Diagnostics are lost; leak protection wins.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        return -1, str(exc)
    try:
        code = await asyncio.wait_for(proc.wait(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, f"timed out after {timeout_s:g}s"
    return code, ""
