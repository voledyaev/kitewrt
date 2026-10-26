"""Exercise real uvicorn HTTP and WebSocket transports with synthetic state."""

from __future__ import annotations

import asyncio
import json
import socket
import tempfile
from pathlib import Path

import httpx
import uvicorn
import websockets
from kitewrt.api import create_app
from kitewrt.hub import Broadcaster
from kitewrt.state import State


class Pipeline:
    def signal(self) -> None:
        pass


async def main() -> None:
    with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.setblocking(False)
        port = listener.getsockname()[1]
        async with httpx.AsyncClient(trust_env=False) as client:
            app = create_app(
                state=State(Path(directory) / "state.json"), pipeline=Pipeline(), fetcher=client
            )
            app.state.kitewrt_hub = Broadcaster()
            server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
            task = asyncio.create_task(server.serve(sockets=[listener]))
            try:
                for _ in range(200):
                    if server.started:
                        break
                    if task.done():
                        await task
                        raise RuntimeError("server exited before binding")
                    await asyncio.sleep(0.025)
                response = await client.get(f"http://127.0.0.1:{port}/api/health", timeout=5)
                response.raise_for_status()
                async with websockets.connect(f"ws://127.0.0.1:{port}/ws", proxy=None) as ws:
                    frame = json.loads(await asyncio.wait_for(ws.recv(), 5))
                    assert frame["type"] == "state"
                    assert frame["data"]["vpn_on"] is False
            finally:
                server.should_exit = True
                await asyncio.wait_for(task, 5)
    print("Production HTTP + WebSocket transport smoke passed")


if __name__ == "__main__":
    asyncio.run(main())
