"""Bounded reads for small internal HTTP responses (no URL/SSRF policy)."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx


async def request_response(
    client: Any,
    method: str,
    url: str,
    *,
    max_bytes: int,
    timeout_s: float,
    **kwargs: Any,
) -> httpx.Response:
    """Limit both decoded body size and total time, including streaming reads.

    httpx's read timeout is an inactivity timeout, not a whole-request budget.
    Raising HTTPError keeps existing best-effort callers' error paths intact.
    """

    async def read() -> httpx.Response:
        async with client.stream(method, url, timeout=timeout_s, **kwargs) as response:
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > max_bytes:
                    raise httpx.HTTPError(f"response too large (>{max_bytes} bytes)")
                body.extend(chunk)
            return httpx.Response(
                response.status_code, content=bytes(body), request=response.request
            )

    try:
        return await asyncio.wait_for(read(), timeout=timeout_s)
    except asyncio.TimeoutError as exc:
        raise httpx.ReadTimeout(f"request exceeded {timeout_s:g}s total budget") from exc


async def request_bytes(
    client: Any, method: str, url: str, *, max_bytes: int, timeout_s: float, **kwargs: Any
) -> bytes:
    response = await request_response(
        client, method, url, max_bytes=max_bytes, timeout_s=timeout_s, **kwargs
    )
    response.raise_for_status()
    return response.content
