"""In-process fan-out hub for pushing live updates to connected UIs.

The browser opens one WebSocket to kitewrt (`/ws`); kitewrt pushes two kinds of
frame: `state` (the full snapshot, on every change — replaces UI polling for
toggle/switch feedback) and `metrics` (live Clash-API stats, ~1/s while the VPN
is on). Each connection gets its own bounded queue; a slow client drops its
oldest frame rather than stalling the publisher. Pure in-memory, no deps.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class Broadcaster:
    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[dict[str, Any]]] = set()

    def register(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=32)
        self._queues.add(q)
        return q

    def unregister(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._queues.discard(q)

    @property
    def has_clients(self) -> bool:
        return bool(self._queues)

    def publish(self, msg: dict[str, Any]) -> None:
        """Enqueue `msg` for every connected client. Non-blocking; on a full
        queue (slow client) drop its oldest frame so it stays current."""
        for q in list(self._queues):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(msg)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass
