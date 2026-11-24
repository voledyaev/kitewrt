"""Exercise actual OS children: cancellation used to leave them running."""

import asyncio
import os
import sys
from pathlib import Path

import pytest
from kitewrt.process import wait_process


@pytest.mark.parametrize("cancel", [False, True])
async def test_wait_terminates_and_reaps_child(cancel):
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import time; time.sleep(60)",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    task = asyncio.create_task(wait_process(proc, proc.communicate(), 0.03 if not cancel else 60))
    try:
        if cancel:
            await asyncio.sleep(0.02)
            task.cancel()
        with pytest.raises(asyncio.CancelledError if cancel else asyncio.TimeoutError):
            await task
        assert proc.returncode is not None
        with pytest.raises(ProcessLookupError):
            os.kill(proc.pid, 0)
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.communicate()


async def test_local_shell_timeout_kills_descendant_with_inherited_pipes(tmp_path):
    from installer.ssh import LocalRouter, SSHError

    pidfile = tmp_path / "child.pid"
    # The parent shell exits only after sleep; killing just the shell leaves
    # sleep alive, holding stdout/stderr open and blocking proc.wait().
    command = f"sleep 60 & echo $! > '{pidfile}'; wait"
    task = asyncio.create_task(LocalRouter().run(command, timeout=0.1))
    with pytest.raises(SSHError, match="timed out"):
        await asyncio.wait_for(task, timeout=2)
    pid = int(pidfile.read_text())
    # Linux may briefly retain a zombie for init to reap; a zombie has exited.
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    if sys.platform.startswith("linux"):
        try:
            state = Path(f"/proc/{pid}/stat").read_text().split()[2]
        except FileNotFoundError:
            # init can reap the exited child after kill(pid, 0) above but
            # before this read. Disappearance is successful cleanup too.
            return
        assert state == "Z"
    else:
        # macOS has no procfs. ps also tolerates the process disappearing
        # between the liveness probe and this observation.
        proc = await asyncio.create_subprocess_exec(
            "ps", "-p", str(pid), "-o", "stat=", stdout=asyncio.subprocess.PIPE
        )
        output, _ = await asyncio.wait_for(proc.communicate(), timeout=1)
        assert proc.returncode in (0, 1)
        assert not output.strip() or output.lstrip().startswith(b"Z")


async def test_output_flood_is_bounded_and_child_is_reaped():
    from kitewrt.process import OutputLimitError, communicate

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import os\nwhile True: os.write(1, b'x' * 8192)",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    with pytest.raises(OutputLimitError):
        await wait_process(proc, communicate(proc, max_bytes=16384), 2)
    assert proc.returncode is not None
