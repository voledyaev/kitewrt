"""SSH transport for the OpenWrt installer.

OpenWrt gives us a normal POSIX shell over SSH (dropbear) with real exit
codes, so there's no structured-CLI parsing, no `exec sh -c` wrapper, and no
exit-marker hack. One `Router` runs commands and streams file uploads over a
single persistent connection.

Uploads go as base64 over the command's stdin (`base64 -d > file`): dropbear
ships no SFTP server by default, but stdin on an exec channel is universal and
needs no extra package. base64 keeps the payload 7-bit clean, so the default
utf-8 channel encoding handles binary files without a bytes-mode channel.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import io
import tarfile
from pathlib import Path

import asyncssh


class SSHError(Exception):
    """Any SSH-layer failure (connect, run, timeout)."""


def _connect_options(user: str, password: str) -> asyncssh.SSHClientConnectionOptions:
    return asyncssh.SSHClientConnectionOptions(
        username=user,
        password=password,
        known_hosts=None,  # TOFU; the installer is a one-shot tool over LAN
        connect_timeout=15,
    )


# Decode base64 from stdin, portably: some OpenWrt/GL.iNet builds don't enable
# the busybox `base64` applet, but `openssl` is virtually always present (and
# `base64 -d` is preferred when available). `-A` makes openssl treat the input
# as one line (our payload is a single unwrapped base64 blob).
_B64_DECODE = "if command -v base64 >/dev/null 2>&1; then base64 -d; else openssl base64 -d -A; fi"


# Basenames skipped when packing a local directory for upload — keeps editor
# / cache cruft off the router.
_UPLOAD_IGNORE = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".DS_Store",
    ".git",
    ".venv",
    "node_modules",
}


class Router:
    """A live SSH connection to an OpenWrt router (typically root@host)."""

    def __init__(self, host: str, user: str, conn: asyncssh.SSHClientConnection):
        self.host = host
        self.user = user
        self._conn = conn
        self._opkg_updated = False  # run-once guard for opkg_update()

    @classmethod
    async def connect(cls, host: str, user: str, password: str) -> Router:
        try:
            conn = await asyncssh.connect(host, options=_connect_options(user, password))
        except (OSError, asyncssh.Error) as exc:
            raise SSHError(f"ssh dial {host}: {exc}") from exc
        return cls(host, user, conn)

    async def close(self) -> None:
        self._conn.close()
        await self._conn.wait_closed()

    async def run(
        self, cmd: str, *, check: bool = False, timeout: float = 30.0, stdin: str | None = None
    ) -> tuple[int, str, str]:
        """Execute `cmd`; return (rc, stdout, stderr).

        `stdin`, when given, is fed to the command's standard input (used by
        the upload helpers to pipe base64 in). If `check` is True a non-zero
        exit raises SSHError with a verbose message.
        """
        try:
            result = await asyncio.wait_for(
                self._conn.run(cmd, input=stdin, check=False), timeout=timeout
            )
        except asyncio.TimeoutError as exc:
            raise SSHError(f"command timed out after {timeout}s: {cmd}") from exc
        except asyncssh.Error as exc:
            raise SSHError(f"ssh run: {exc}") from exc
        rc = result.exit_status if result.exit_status is not None else 0
        out = result.stdout or ""
        err = result.stderr or ""
        if check and rc != 0:
            raise SSHError(
                f"remote command failed (rc={rc}): {cmd}\n--stdout--\n{out}\n--stderr--\n{err}"
            )
        return rc, out, err

    async def opkg_update(self, *, timeout: float = 180.0) -> None:
        """Refresh the opkg package index — at most once per session.

        Several install steps each want a fresh index before `opkg install`;
        without this guard a clean install runs `opkg update` 3-4x back to back
        (each up to 180s). Best-effort: a failed refresh is non-fatal here — the
        following `opkg install` surfaces any real breakage — so there's no
        `check` flag.
        """
        if self._opkg_updated:
            return
        await self.run("opkg update", check=False, timeout=timeout)
        self._opkg_updated = True

    async def is_alive(self) -> bool:
        """Tiny round-trip to verify the router is reachable."""
        try:
            rc, out, _ = await self.run("echo __OK__", timeout=5.0)
        except SSHError:
            return False
        return rc == 0 and "__OK__" in out

    async def upload_bytes(self, content: bytes, remote_path: str, mode: int = 0o644) -> None:
        """Write `content` to `remote_path` (atomic tmp+mv) with `mode`."""
        b64 = base64.b64encode(content).decode("ascii")
        parent = str(Path(remote_path).parent)
        tmp = remote_path + ".tmp"
        await self.run(f"mkdir -p {parent}", check=True, timeout=15.0)
        await self.run(f"{{ {_B64_DECODE} ; }} > {tmp}", check=True, timeout=120.0, stdin=b64)
        await self.run(f"chmod {mode:o} {tmp} && mv {tmp} {remote_path}", check=True, timeout=15.0)

    async def upload_directory(self, local_dir: Path | str, remote_dir: str) -> None:
        """Pack a local directory as tar.gz, ship it base64-over-stdin, untar
        on the router. The existing remote_dir is wiped first so deploys are
        idempotent."""
        local = Path(local_dir)
        if not local.is_dir():
            raise SSHError(f"missing local dir: {local}")

        buf = io.BytesIO()
        # mtime=0 → byte-identical tarball for identical input (no wall-clock
        # nondeterminism), which keeps re-deploys diff-free.
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                for path in sorted(local.rglob("*")):
                    rel = path.relative_to(local)
                    if any(p in _UPLOAD_IGNORE for p in rel.parts):
                        continue
                    if path.suffix == ".pyc":
                        continue
                    tar.add(path, arcname=str(rel), recursive=False)

        b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        await self.run(f"rm -rf {remote_dir} && mkdir -p {remote_dir}", check=True, timeout=30.0)
        await self.run(
            f"{{ {_B64_DECODE} ; }} | tar xzf - -C {remote_dir}",
            check=True,
            timeout=180.0,
            stdin=b64,
        )
