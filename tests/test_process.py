"""Exercise actual OS children: cancellation used to leave them running."""

import asyncio
import os
import sys

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
    stat = f"/proc/{pid}/stat"
    assert os.path.exists(stat)
    with open(stat) as file:
        assert file.read().split()[2] == "Z"


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
