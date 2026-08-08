"""Tests for the Clash API client — the URL delay-test in particular.

Drives ClashClient with an httpx MockTransport so the delay/select calls are
exercised against canned controller responses (no sing-box, no network).
"""

from __future__ import annotations

import httpx
import pytest
from kitewrt.singbox.clash import DEFAULT_DELAY_URL, ClashClient


def _client(handler) -> ClashClient:
    return ClashClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))


async def test_delay_returns_ms_on_success():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["raw_path"] = request.url.raw_path.decode()
        seen["url"] = request.url.params.get("url")
        seen["timeout"] = request.url.params.get("timeout")
        return httpx.Response(200, json={"delay": 187})

    delay = await _client(handler).delay("sub-1/de-01.example:443")
    assert delay == 187
    # Composite tag is percent-encoded on the wire (no bare '/' or ':' in the
    # path segment), so sing-box matches the exact outbound tag.
    assert seen["raw_path"].startswith("/proxies/sub-1%2Fde-01.example%3A443/delay")
    assert seen["url"] == DEFAULT_DELAY_URL
    assert seen["timeout"] == "5000"


async def test_delay_none_on_non_200():
    # sing-box returns a non-200 (e.g. 408/503) when the node fails the test.
    delay = await _client(lambda req: httpx.Response(503, json={"message": "timeout"})).delay("x")
    assert delay is None


async def test_delay_none_on_transport_error():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("controller down")

    assert await _client(boom).delay("x") is None


async def test_delay_none_on_malformed_body():
    assert await _client(lambda req: httpx.Response(200, json={})).delay("x") is None


async def test_delay_honours_custom_url_and_timeout():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = request.url.params.get("url")
        seen["timeout"] = request.url.params.get("timeout")
        return httpx.Response(200, json={"delay": 42})

    await _client(handler).delay("x", url="http://cp.cloudflare.com/", timeout_ms=2000)
    assert seen["url"] == "http://cp.cloudflare.com/"
    assert seen["timeout"] == "2000"


@pytest.mark.parametrize("delay_val", [0, 9999])
async def test_delay_passes_through_extremes(delay_val):
    assert (
        await _client(lambda req: httpx.Response(200, json={"delay": delay_val})).delay("x")
        == delay_val
    )


async def test_proxies_returns_map():
    body = {"proxies": {"select": {"type": "Selector"}, "sub/de:443": {"type": "Vless"}}}
    proxies = await _client(lambda req: httpx.Response(200, json=body)).proxies()
    assert "sub/de:443" in proxies


async def test_proxies_empty_on_error():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("controller down")

    assert await _client(boom).proxies() == {}
