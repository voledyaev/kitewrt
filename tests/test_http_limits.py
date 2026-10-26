"""Deadlines and size limits must apply while reading, not after buffering."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from kitewrt.fetch import FetchError, fetch_url
from kitewrt.http import request_bytes
from kitewrt.routes.connectivity import _probe, connectivity
from kitewrt.routes.exit_ip import exit_ip


class Drip(httpx.AsyncByteStream):
    def __init__(self):
        self.closed = False
        self.reads = 0

    async def __aiter__(self):
        while True:
            self.reads += 1
            await asyncio.sleep(0.005)
            yield b"x"

    async def aclose(self):
        self.closed = True


@pytest.mark.parametrize("subscription", [True, False])
async def test_trickling_body_has_a_total_deadline(subscription):
    stream = Drip()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, stream=stream))
    ) as client:
        if subscription:
            with pytest.raises(FetchError, match="total budget"):
                await fetch_url(client, "https://8.8.8.8/sub", timeout_s=0.03)
        else:
            with pytest.raises(httpx.ReadTimeout, match="total budget"):
                await request_bytes(
                    client, "GET", "https://example.test", max_bytes=4096, timeout_s=0.03
                )
    assert stream.reads > 1
    assert stream.closed


async def test_dns_guard_is_inside_fetch_deadline(monkeypatch):
    from kitewrt import fetch

    async def hung(host):
        await asyncio.Event().wait()

    monkeypatch.setattr(fetch, "resolve_blocks_ssrf", hung)
    async with httpx.AsyncClient() as client:
        with pytest.raises(FetchError, match="total budget"):
            await fetch_url(client, "https://example.test", timeout_s=0.02)


async def test_connectivity_never_reads_the_body():
    stream = Drip()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(503, stream=stream))
    ) as client:
        assert (await _probe(client, "target", "https://example.test")).ok
    assert stream.reads == 0
    assert stream.closed


async def test_exit_ip_rejects_oversized_body_without_draining():
    async def large():
        yield b"x" * 4097
        pytest.fail("oversize response must be closed immediately")

    class Large(Drip):
        def __aiter__(self):
            return large()

    stream = Large()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    state = SimpleNamespace(snapshot=lambda: SimpleNamespace(vpn_on=True))
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, stream=stream))
    ) as client:
        assert not (await exit_ip(request, state, client)).available
    assert stream.closed


@pytest.mark.parametrize("route", ["exit", "connectivity"])
async def test_simultaneous_dashboard_reads_share_one_probe(route):
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return httpx.Response(200, content=b"ip=8.8.8.8\nloc=US\n")

    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    state = SimpleNamespace(snapshot=lambda: SimpleNamespace(vpn_on=True))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        if route == "exit":
            results = await asyncio.gather(*(exit_ip(request, state, client) for _ in range(8)))
            assert all(r.available for r in results)
            assert calls == 1
        else:
            await asyncio.gather(*(connectivity(request, client) for _ in range(8)))
            assert calls == 3


@pytest.mark.parametrize("caller", ["doh", "clash"])
async def test_internal_http_reads_have_size_limits(caller):
    from kitewrt.endpoints import via_doh
    from kitewrt.singbox.clash import ClashClient, ClashError

    limit = 65535 if caller == "doh" else 4 << 20

    class Large(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield b"x" * (limit + 1)
            pytest.fail("must stop reading after the size limit")

        async def aclose(self):
            self.closed = True

    stream = Large()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, stream=stream))
    ) as client:
        with pytest.raises(httpx.HTTPError if caller == "doh" else ClashError, match="too large"):
            if caller == "doh":
                await via_doh(client, "https://1.1.1.1/dns-query", "example.test")
            else:
                await ClashClient(client).connections()
    assert stream.closed
