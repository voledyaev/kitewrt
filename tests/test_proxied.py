"""Tests for the daemon's own egress path (kitewrt.proxied).

The fallback exists to stop a first-run deadlock: sing-box only starts once
there is something to apply, so on a fresh install there is no local proxy yet
— and if the subscription fetch went exclusively through it, you could never
add the first subscription. The fallback also has to stay *narrow*: retrying a
real far-end failure in the clear would leak the request to the ISP for
nothing.
"""

from __future__ import annotations

import asyncio
import logging

import httpx
import pytest
from kitewrt.proxied import ProxiedFetcher


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _ok(body: bytes):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    return handler


def _raise(exc: Exception):
    def handler(_request: httpx.Request) -> httpx.Response:
        raise exc

    return handler


async def _read(fetcher: ProxiedFetcher) -> bytes:
    async with fetcher.stream("GET", "https://example.test/x") as resp:
        return await resp.aread()


async def test_uses_the_proxy_when_it_is_up():
    f = ProxiedFetcher(_client(_ok(b"via-proxy")), _client(_ok(b"direct")))
    assert await _read(f) == b"via-proxy"
    await f.aclose()


async def test_falls_back_to_direct_when_the_proxy_is_not_listening():
    """The first-run case: no subscription yet, so no sing-box, so no proxy."""
    f = ProxiedFetcher(
        _client(_raise(httpx.ConnectError("connection refused"))),
        _client(_ok(b"direct")),
    )
    assert await _read(f) == b"direct"
    await f.aclose()


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ReadTimeout("slow"),
        httpx.ConnectTimeout("slow connect"),
        httpx.RemoteProtocolError("bad framing"),
    ],
)
async def test_does_not_fall_back_on_far_end_failures(exc):
    """Only an unreachable *proxy* falls through. A timeout or protocol error
    is an answer about the destination — retrying it direct would hand the
    request to the ISP and change nothing."""
    direct_called: list[str] = []

    def direct_handler(request: httpx.Request) -> httpx.Response:
        direct_called.append(str(request.url))
        return httpx.Response(200, content=b"direct")

    f = ProxiedFetcher(_client(_raise(exc)), _client(direct_handler))
    with pytest.raises(type(exc)):
        await _read(f)
    assert direct_called == []
    await f.aclose()


async def test_http_error_status_is_not_retried_direct():
    """A 403 from the far end is a real answer; the fallback must not turn it
    into a second, unproxied request."""
    direct_called: list[str] = []

    def direct_handler(request: httpx.Request) -> httpx.Response:
        direct_called.append(str(request.url))
        return httpx.Response(200, content=b"direct")

    def blocked(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403)

    f = ProxiedFetcher(_client(blocked), _client(direct_handler))
    async with f.stream("GET", "https://example.test/x") as resp:
        assert resp.status_code == 403
    assert direct_called == []
    await f.aclose()


async def test_get_goes_through_the_proxy():
    """`get()` existing at all is the regression: both /api/exit-ip and
    /api/connectivity call it, and a fetcher that only had `stream()` turned
    them into hard 500s — invisible to the suite, which injects a real
    AsyncClient everywhere."""
    f = ProxiedFetcher(_client(_ok(b"via-proxy")), _client(_ok(b"direct")))
    assert (await f.get("https://example.test/x")).content == b"via-proxy"
    await f.aclose()


async def test_get_falls_back_when_the_proxy_is_not_listening():
    f = ProxiedFetcher(
        _client(_raise(httpx.ConnectError("connection refused"))),
        _client(_ok(b"direct")),
    )
    assert (await f.get("https://example.test/x")).content == b"direct"
    await f.aclose()


async def _listening_port() -> tuple[asyncio.AbstractServer, int]:
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


@pytest.mark.parametrize("call", ["stream", "get"])
async def test_no_plaintext_retry_when_the_proxy_is_alive(call):
    """The leak.

    httpcore maps a far-end `ssl.SSLError` to `httpx.ConnectError` from inside
    `start_tls` — which runs *after* the CONNECT tunnel is established. So a
    working proxy plus a failed handshake with the destination is
    indistinguishable by exception type from a proxy that isn't running, and
    the old blanket retry re-sent the subscription URL, token and all, in the
    clear. A router with a wrong clock after a power cut does this on every
    single fetch.
    """
    server, port = await _listening_port()
    direct_called: list[str] = []

    def direct_handler(request: httpx.Request) -> httpx.Response:
        direct_called.append(str(request.url))
        return httpx.Response(200, content=b"direct")

    f = ProxiedFetcher(
        _client(_raise(httpx.ConnectError("[SSL] certificate is not yet valid"))),
        _client(direct_handler),
        proxy_url=f"http://127.0.0.1:{port}",
    )
    try:
        with pytest.raises(httpx.ConnectError):
            if call == "get":
                await f.get("https://sub.example.test/?token=s3cret")
            else:
                await _read(f)
        assert direct_called == []
    finally:
        server.close()
        await server.wait_closed()
        await f.aclose()


@pytest.mark.parametrize("call", ["stream", "get"])
async def test_falls_back_when_the_configured_proxy_port_is_dead(call):
    """The other half: with a proxy address configured and nothing on it, the
    first-run bootstrap must still work."""
    server, port = await _listening_port()
    server.close()
    await server.wait_closed()  # port now free

    f = ProxiedFetcher(
        _client(_raise(httpx.ConnectError("connection refused"))),
        _client(_ok(b"direct")),
        proxy_url=f"http://127.0.0.1:{port}",
    )
    if call == "get":
        assert (await f.get("https://example.test/x")).content == b"direct"
    else:
        assert await _read(f) == b"direct"
    await f.aclose()


async def test_the_fallback_log_does_not_carry_the_url(caplog):
    """Subscription URLs carry tokens and this logs at INFO, straight to
    syslog — exactly the state an operator reads logs in."""
    f = ProxiedFetcher(
        _client(_raise(httpx.ConnectError("refused"))),
        _client(_ok(b"direct")),
    )
    with caplog.at_level(logging.INFO, logger="kitewrt.proxied"):
        await f.get("https://sub.example.test/feed?token=s3cret")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "sub.example.test" in text
    assert "s3cret" not in text
    await f.aclose()


async def test_aclose_closes_both_clients():
    proxied, direct = _client(_ok(b"a")), _client(_ok(b"b"))
    await ProxiedFetcher(proxied, direct).aclose()
    assert proxied.is_closed and direct.is_closed


async def test_the_ssrf_optout_follows_the_transport_not_the_class():
    """`ProxiedFetcher` falls back to a direct request whenever the proxy port
    is dead — the fresh-install state, i.e. exactly when a user pastes a
    subscription link they were handed. A flat "I tunnel" attribute disabled
    `fetch`'s DNS-rebinding guard on that path too, where the lookup is local
    anyway and there is nothing to leak."""
    server, port = await _listening_port()
    live = ProxiedFetcher(
        _client(_ok(b"x")), _client(_ok(b"y")), proxy_url=f"http://127.0.0.1:{port}"
    )
    try:
        assert await live.tunnels() is True
    finally:
        server.close()
        await server.wait_closed()

    # Same object, port now dead: the answer has to change.
    assert await live.tunnels() is False
    await live.aclose()

    # No proxy address configured at all → always direct → always guarded.
    bare = ProxiedFetcher(_client(_ok(b"x")), _client(_ok(b"y")))
    assert await bare.tunnels() is False
    await bare.aclose()


@pytest.mark.parametrize("call", ["get", "stream"])
@pytest.mark.parametrize("failure", ["disconnect", "timeout"])
async def test_failed_connect_tls_does_not_poison_later_requests(call, failure):
    """Real httpcore pool: CONNECT succeeds, then TLS is cut short (#921).

    With one shared pool/one slot, only the first call raises ConnectError;
    every later call raises PoolTimeout without reaching the proxy at all.
    """
    attempts = []

    async def proxy(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            attempts.append(head.split(b" ", 1)[0])
            if head.startswith(b"CONNECT "):
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                await reader.read(4096)  # ClientHello
                if failure == "timeout":
                    await reader.read()  # wait for the TLS timeout to close the socket
            else:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(proxy, "127.0.0.1", 0)
    url = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    clients = []

    def fresh_client():
        client = httpx.AsyncClient(
            proxy=url, timeout=0.2, limits=httpx.Limits(max_connections=1), trust_env=False
        )
        clients.append(client)
        return client

    def no_direct(request):
        pytest.fail("a failed TLS tunnel must not fall back direct")

    f = ProxiedFetcher(fresh_client, _client(no_direct), proxy_url=url)
    try:
        for _ in range(3):
            expected = httpx.ConnectError if failure == "disconnect" else httpx.ConnectTimeout
            with pytest.raises(expected):
                if call == "get":
                    await f.get("https://example.test/subscription")
                else:
                    await _read(f)
            assert clients[-1].is_closed
        if call == "get":
            assert (await f.get("http://example.test/recovered")).content == b"ok"
        else:
            async with f.stream("GET", "http://example.test/recovered") as response:
                assert await response.aread() == b"ok"
        assert attempts == [b"CONNECT", b"CONNECT", b"CONNECT", b"GET"]
        assert all(c.is_closed for c in clients)
    finally:
        await f.aclose()
        server.close()
        await server.wait_closed()


async def test_cancelled_stream_closes_only_its_own_client():
    entered = asyncio.Event()
    clients = []

    def fresh_client():
        client = _client(_ok(b"ok"))
        clients.append(client)
        return client

    f = ProxiedFetcher(fresh_client, _client(_ok(b"direct")))

    async def held_stream():
        async with f.stream("GET", "https://example.test/held"):
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(held_stream())
    try:
        await entered.wait()
        assert (await f.get("https://example.test/other")).content == b"ok"
        assert not clients[0].is_closed
        assert clients[1].is_closed
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert clients[0].is_closed
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await f.aclose()
