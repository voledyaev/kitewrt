"""Tests for the fetch helper — the SSRF guard in particular."""

from __future__ import annotations

import httpx
import pytest
from kitewrt.fetch import FetchError, blocks_ssrf, fetch_url


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "0.0.0.0", "::1", "224.0.0.1"])
def test_blocks_ssrf_sensitive_ip_literals(host):
    # loopback (local Clash controller), link-local (cloud metadata),
    # unspecified, multicast — all refused.
    assert blocks_ssrf(host) is True


@pytest.mark.parametrize("host", ["example.com", "192.168.8.5", "10.0.0.1", "8.8.8.8", "sub.test"])
def test_blocks_ssrf_allows_public_private_and_hostnames(host):
    # public IPs, hostnames, and private LAN IPs (self-hosted configs) pass.
    assert blocks_ssrf(host) is False


async def test_fetch_url_refuses_loopback_target():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(FetchError, match="non-public"):
        await fetch_url(client, "http://127.0.0.1:9090/proxies")
    await client.aclose()


async def test_fetch_url_allows_public_host():
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"ok"))
    )
    assert await fetch_url(client, "https://provider.example/sub") == b"ok"
    await client.aclose()


async def test_fetch_url_empty_httpx_error_surfaces_type_name():
    # Connect/read timeouts and connection resets (a blocked host) often
    # stringify to "" — the FetchError must still carry a non-empty detail so
    # the API surfaces e.g. "ConnectError" instead of collapsing to "error".
    def boom(request):
        raise httpx.ConnectError("")  # empty message, like a real reset/timeout

    client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    with pytest.raises(FetchError) as ei:
        await fetch_url(client, "https://blocked.example/sub")
    assert str(ei.value).strip()  # never empty
    assert "ConnectError" in str(ei.value)
    await client.aclose()
