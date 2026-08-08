"""SSH transport for the OpenWrt installer.

OpenWrt gives us a normal POSIX shell over SSH (dropbear) with real exit
codes, so there's no structured-CLI parsing, no `exec sh -c` wrapper, and no
exit-marker hack. One `Router` runs commands and streams file uploads over a
single persistent connection.

Uploads go as raw bytes over the command's stdin (`cat > file`, `tar xzf -`):
dropbear ships no SFTP server by default, but stdin on an exec channel is
universal and needs no extra package. They used to be base64-wrapped, which
demanded a *decoder on the router* — and a stock OpenWrt x86 build has neither
the busybox `base64` applet nor `openssl`, so the very first upload failed
before anything could install one. SSH channels are 8-bit clean, so a
bytes-mode channel carries binary directly and ships 33% less.
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import io
import tarfile
from pathlib import Path

import asyncssh


class SSHError(Exception):
    """Any SSH-layer failure (connect, run, timeout)."""


def _connect_options(user: str, password: str, port: int) -> asyncssh.SSHClientConnectionOptions:
    return asyncssh.SSHClientConnectionOptions(
        username=user,
        password=password,
        port=port,
        known_hosts=None,  # TOFU; the installer is a one-shot tool over LAN
        connect_timeout=15,
    )


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

    def __init__(self, host: str, user: str, conn: asyncssh.SSHClientConnection, port: int = 22):
        self.host = host
        self.user = user
        self.port = port
        self._conn = conn
        self._opkg_updated = False  # run-once guard for opkg_update()

    @classmethod
    async def connect(cls, host: str, user: str, password: str, port: int = 22) -> Router:
        try:
            conn = await asyncssh.connect(host, options=_connect_options(user, password, port))
        except (OSError, asyncssh.Error) as exc:
            raise SSHError(f"ssh dial {host}:{port}: {exc}") from exc
        return cls(host, user, conn, port)

    async def close(self) -> None:
        self._conn.close()
        await self._conn.wait_closed()

    async def run(
        self, cmd: str, *, check: bool = False, timeout: float = 30.0, stdin: str | None = None
    ) -> tuple[int, str, str]:
        """Execute `cmd`; return (rc, stdout, stderr).

        `stdin`, when given, is fed to the command's standard input as text.
        Binary payloads go through `_pipe_bytes` instead. If `check` is True a
        non-zero exit raises SSHError with a verbose message.
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

    async def _pipe_bytes(self, cmd: str, data: bytes, *, timeout: float) -> None:
        """Feed `data` to `cmd`'s stdin as raw bytes.

        SSH channels are 8-bit clean, so binary needs no encoding hop. This
        used to go through base64, which required a *decoder on the router* —
        and a stock OpenWrt x86 build has neither the busybox `base64` applet
        nor `openssl`, so the install died at the first upload, before it
        could opkg-install one. Verified byte-exact over dropbear against a
        300 KB payload of random bytes plus NUL/CR/0x1a. Raw also ships 33%
        fewer bytes, which is the bulk of install time on a slow link.
        """
        try:
            result = await asyncio.wait_for(
                self._conn.run(cmd, input=data, encoding=None, check=False), timeout=timeout
            )
        except asyncio.TimeoutError as exc:
            raise SSHError(f"upload timed out after {timeout}s: {cmd}") from exc
        except asyncssh.Error as exc:
            raise SSHError(f"ssh upload: {exc}") from exc
        rc = result.exit_status if result.exit_status is not None else 0
        if rc != 0:
            err = bytes(result.stderr or b"").decode(errors="replace")
            raise SSHError(f"remote command failed (rc={rc}): {cmd}\n--stderr--\n{err}")

    async def _cleanup(self, cmd: str) -> None:
        """Best-effort tidy-up on a failure path. Never raises: it runs while
        an exception is propagating, and its own failure would replace the
        real one — which is exactly what happens when the transport is what
        broke."""
        with contextlib.suppress(Exception):
            await self.run(cmd, check=False, timeout=15.0)

    async def upload_bytes(self, content: bytes, remote_path: str, mode: int = 0o644) -> None:
        """Write `content` to `remote_path` (atomic tmp+mv) with `mode`."""
        parent = str(Path(remote_path).parent)
        tmp = remote_path + ".tmp"
        await self.run(f"mkdir -p {parent}", check=True, timeout=15.0)
        try:
            await self._pipe_bytes(f"cat > {tmp}", content, timeout=120.0)
        except SSHError:
            # Don't strand a partial file next to the real one — on a router
            # with a small overlay a few of those is real disk. Suppressed,
            # because the usual reason an upload failed is that the transport
            # died: the cleanup then raises too and *replaces* the real error
            # with "ssh run: SSH connection closed".
            await self._cleanup(f"rm -f {tmp}")
            raise
        try:
            await self.run(
                f"chmod {mode:o} {tmp} && mv {tmp} {remote_path}", check=True, timeout=15.0
            )
        except SSHError:
            await self._cleanup(f"rm -f {tmp}")
            raise

    async def upload_directory(self, local_dir: Path | str, remote_dir: str) -> None:
        """Pack a local directory as tar.gz, ship it over stdin, untar on the
        router. The existing remote_dir is wiped first so deploys are
        idempotent."""
        local = Path(local_dir)
        if not local.is_dir():
            raise SSHError(f"missing local dir: {local}")

        buf = io.BytesIO()
        # mtime=0 → byte-identical tarball for identical input (no wall-clock
        # nondeterminism), which keeps re-deploys diff-free.
        with (
            gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz,
            tarfile.open(fileobj=gz, mode="w") as tar,
        ):
            for path in sorted(local.rglob("*")):
                rel = path.relative_to(local)
                if any(p in _UPLOAD_IGNORE for p in rel.parts):
                    continue
                if path.suffix == ".pyc":
                    continue
                tar.add(path, arcname=str(rel), recursive=False)

        await self.run(f"rm -rf {remote_dir} && mkdir -p {remote_dir}", check=True, timeout=30.0)
        try:
            await self._pipe_bytes(f"tar xzf - -C {remote_dir}", buf.getvalue(), timeout=180.0)
        except SSHError:
            await self._cleanup(f"rm -rf {remote_dir}")
            raise
