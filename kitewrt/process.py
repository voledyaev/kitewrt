"""Subprocess waits which also clean up on task cancellation.

Killing without reaping leaks process resources. Reaping with undrained PIPEs
can itself hang, especially when a shell's descendants inherited those pipes.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from collections.abc import Awaitable
from typing import TypeVar

T = TypeVar("T")


async def wait_process(
    proc: asyncio.subprocess.Process,
    operation: Awaitable[T],
    timeout: float,
    *,
    process_group: bool = False,
) -> T:
    """Wait with a deadline; terminate and drain on timeout, error or cancel.

    process_group requires start_new_session=True at spawn. Use it for shells,
    never service init scripts which intentionally launch a lasting daemon.
    """
    try:
        return await asyncio.wait_for(operation, timeout=timeout)
    except BaseException:
        with contextlib.suppress(ProcessLookupError):
            if process_group:
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        # communicate drains pipes before waiting. A descendant may still own
        # a pipe even after its parent died; cleanup must have its own budget.
        with contextlib.suppress(asyncio.TimeoutError, OSError):
            await asyncio.wait_for(proc.communicate(), timeout=1.0)
        raise


class OutputLimitError(OSError):
    """A command produced more output than the router can safely buffer."""


async def communicate(
    proc: asyncio.subprocess.Process, data: bytes | None = None, *, max_bytes: int = 8 << 20
) -> tuple[bytes | None, bytes | None]:
    """Drain both pipes concurrently with one combined output size limit."""
    total = 0

    async def read(stream: asyncio.StreamReader | None) -> bytes | None:
        nonlocal total
        if stream is None:
            return None
        body = bytearray()
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return bytes(body)
            total += len(chunk)
            if total > max_bytes:
                raise OutputLimitError(f"command output exceeded {max_bytes} bytes")
            body.extend(chunk)

    async def write() -> None:
        if proc.stdin is not None:
            try:
                if data:
                    proc.stdin.write(data)
                    await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                proc.stdin.close()

    tasks = [
        asyncio.create_task(read(proc.stdout)),
        asyncio.create_task(read(proc.stderr)),
        asyncio.create_task(write()),
    ]
    try:
        results = await asyncio.gather(*tasks)
        await proc.wait()
        return results[0], results[1]
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
