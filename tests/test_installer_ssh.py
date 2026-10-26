"""Tests for installer.ssh.Router — the SSH transport (run mapping, raw-byte
uploads, deterministic dir packing, the opkg-update run-once guard).

A fake asyncssh connection records commands + replays scripted results, so these
exercise the transport with no network.
"""

from __future__ import annotations

import asyncio

import asyncssh
import pytest
from installer.ssh import Router, SSHError


class FakeResult:
    def __init__(self, exit_status=0, stdout="", stderr=""):
        self.exit_status = exit_status
        self.stdout = stdout
        self.stderr = stderr


class FakeConn:
    def __init__(self, responder=None):
        self.calls: list[tuple[str, str | None]] = []
        self._responder = responder or (lambda cmd, inp: FakeResult())

    async def create_process(self, cmd, input=None, encoding="utf-8"):
        self.calls.append((cmd, input))
        conn = self

        class Process:
            async def wait(self, check=False):
                result = conn._responder(cmd, input)
                if asyncio.iscoroutine(result):
                    result = await result
                return result

            def kill(self):
                conn.killed = True

            def close(self):
                conn.process_closed = True

            async def wait_closed(self):
                pass

        return Process()

    def close(self):
        pass

    async def wait_closed(self):
        pass


def _router(responder=None) -> Router:
    return Router("host", "root", FakeConn(responder))


# --- run --------------------------------------------------------------------


async def test_run_maps_exit_status_and_streams():
    r = _router(lambda cmd, inp: FakeResult(exit_status=5, stdout="out", stderr="err"))
    rc, out, err = await r.run("whatever")
    assert (rc, out, err) == (5, "out", "err")


async def test_run_check_raises_on_nonzero():
    r = _router(lambda cmd, inp: FakeResult(exit_status=2, stderr="boom"))
    with pytest.raises(SSHError, match="rc=2"):
        await r.run("x", check=True)


async def test_run_check_passes_on_zero():
    r = _router(lambda cmd, inp: FakeResult(exit_status=0))
    rc, _, _ = await r.run("x", check=True)
    assert rc == 0


async def test_run_wraps_asyncssh_error():
    async def boom(cmd, inp):
        raise asyncssh.Error(1, "transport died")

    with pytest.raises(SSHError):
        await _router(boom).run("x")


async def test_run_times_out():
    async def slow(cmd, inp):
        await asyncio.sleep(0.3)
        return FakeResult()

    with pytest.raises(SSHError, match="timed out"):
        await _router(slow).run("sleep", timeout=0.05)


# --- uploads ----------------------------------------------------------------


async def test_upload_bytes_streams_raw_and_moves_atomically():
    """The payload goes over stdin as *bytes*, with no decoder on the router.

    It used to be base64, which needs `base64 -d` or `openssl` remotely — and
    a stock OpenWrt x86 build ships neither, so the first upload of an install
    failed outright. Nothing caught it because the fake conn never modelled a
    router without a decoder.
    """
    conn = FakeConn()
    r = Router("h", "u", conn)
    await r.upload_bytes(b"\x00\x01binary", "/etc/kitewrt/x", mode=0o600)
    cmds = [c for c, _ in conn.calls]
    inputs = [i for _, i in conn.calls]
    assert any("mkdir -p /etc/kitewrt" in c for c in cmds)
    assert b"\x00\x01binary" in inputs
    assert not any("base64" in c or "openssl" in c for c in cmds)
    # atomic: chmod the temp then mv onto the final path
    assert any("chmod 600" in c and "mv " in c and "/etc/kitewrt/x" in c for c in cmds)


async def test_upload_directory_is_deterministic(tmp_path):
    d = tmp_path / "pkg"
    (d / "sub").mkdir(parents=True)
    (d / "a.py").write_text("print(1)\n")
    (d / "sub" / "b.py").write_text("print(2)\n")

    async def pack(conn):
        await Router("h", "u", conn).upload_directory(d, "/usr/lib/kitewrt/x")

    c1, c2 = FakeConn(), FakeConn()
    await pack(c1)
    await pack(c2)
    # The untar command + a deterministic (mtime=0) tarball → identical stdin
    # across runs, so re-deploys stay diff-free.
    assert any("tar xzf - -C /usr/lib/kitewrt/x" in c for c, _ in c1.calls)
    b1 = next(i for c, i in c1.calls if i)
    b2 = next(i for c, i in c2.calls if i)
    assert b1 == b2


async def test_upload_directory_skips_pyc_and_cruft(tmp_path):
    d = tmp_path / "pkg"
    (d / "__pycache__").mkdir(parents=True)
    (d / "__pycache__" / "x.pyc").write_text("junk")
    (d / "keep.py").write_text("ok")
    conn = FakeConn()
    await Router("h", "u", conn).upload_directory(d, "/r")
    tar_bytes = next(i for c, i in conn.calls if i)
    import gzip
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(tar_bytes))) as tf:
        names = tf.getnames()
    assert "keep.py" in names
    assert not any("__pycache__" in n or n.endswith(".pyc") for n in names)


# --- opkg_update run-once ---------------------------------------------------


async def test_opkg_update_runs_once_per_session():
    seen = []
    r = _router(lambda cmd, inp: seen.append(cmd) or FakeResult())
    await r.opkg_update()
    await r.opkg_update()
    assert sum(1 for c in seen if "opkg update" in c) == 1


async def test_remote_timeout_closes_only_the_command_channel():
    async def hung(cmd, data):
        await asyncio.Event().wait()

    conn = FakeConn(hung)
    with pytest.raises(SSHError, match="timed out"):
        await Router("host", "root", conn).run("hung", timeout=0.02)
    assert conn.killed
    assert conn.process_closed


async def test_real_ssh_channel_is_closed_after_timeout_and_connection_is_reusable():
    ended = asyncio.Event()

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return False

    async def command(proc):
        if proc.command == "hang":
            await proc.wait_closed()
            ended.set()
        else:
            proc.stdout.write("ok")
            proc.exit(0)

    server = await asyncssh.create_server(
        Server,
        "127.0.0.1",
        0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=command,
    )
    try:
        async with asyncssh.connect("127.0.0.1", port=server.get_port(), known_hosts=None) as conn:
            router = Router("127.0.0.1", "test", conn)
            with pytest.raises(SSHError, match="timed out"):
                await router.run("hang", timeout=0.05)
            await asyncio.wait_for(ended.wait(), 1)
            assert (await router.run("ok"))[:2] == (0, "ok")
    finally:
        server.close()
        await server.wait_closed()
