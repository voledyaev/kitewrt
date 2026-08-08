"""Tests for the fetch helper — the SSRF guard in particular."""

from __future__ import annotations

import httpx
import pytest
from kitewrt.fetch import (
    FetchError,
    blocks_ssrf,
    blocks_ssrf_name,
    fetch_url,
    resolve_blocks_ssrf,
)


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "0.0.0.0", "::1", "224.0.0.1"])
def test_blocks_ssrf_sensitive_ip_literals(host):
    # loopback (local Clash controller), link-local (cloud metadata),
    # unspecified, multicast — all refused.
    assert blocks_ssrf(host) is True


@pytest.mark.parametrize("host", ["example.com", "192.168.8.5", "10.0.0.1", "8.8.8.8", "sub.test"])
def test_blocks_ssrf_allows_public_private_and_hostnames(host):
    # public IPs, hostnames, and private LAN IPs (self-hosted configs) pass.
    assert blocks_ssrf(host) is False


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "LOCALHOST",
        "localhost.",  # the same name, written as an FQDN
        "app.localhost",
        "metadata.google.internal",
        "2130706433",  # 127.0.0.1 as one integer — inet_aton takes it
        "127.1",
        "0177.0.0.1",
        "0x7f.1",
    ],
)
def test_blocks_ssrf_name_refuses_hosts_that_are_local_by_definition(host):
    # Answers that don't depend on *whose* resolver is asked: RFC 6761
    # `localhost`, the reserved `.internal` TLD, and IPv4 literals in the
    # spellings `ipaddress` rejects but a C resolver accepts.
    assert blocks_ssrf_name(host) is True


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "raw.githubusercontent.com",  # every real rule-set URL is a bare name
        "sub.test",
        "nas.lan",
        "nas.local",
        "192.168.8.5",
        "3232235521",  # 192.168.0.1 — private, so allowed like the literal
    ],
)
def test_blocks_ssrf_name_leaves_public_and_lan_names_alone(host):
    # Same policy as blocks_ssrf: the LAN is allowed on purpose (self-hosted
    # subscriptions and rule-sets), so only loopback/metadata-class names go.
    assert blocks_ssrf_name(host) is False


async def test_resolve_blocks_ssrf_hostname_to_loopback():
    # A hostname that resolves to loopback (localhost → 127.0.0.1/::1) is refused
    # — this is the DNS-rebinding shape the IP-literal guard alone misses.
    assert await resolve_blocks_ssrf("localhost") is True


async def test_resolve_blocks_ssrf_ip_literal_defers_to_blocks_ssrf():
    # IP literals are covered by blocks_ssrf; resolve_blocks_ssrf returns False.
    assert await resolve_blocks_ssrf("127.0.0.1") is False


async def test_fetch_url_refuses_loopback_target():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(FetchError, match="non-public"):
        await fetch_url(client, "http://127.0.0.1:9090/proxies")
    await client.aclose()


async def test_fetch_url_refuses_hostname_resolving_to_loopback():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(FetchError, match="non-public"):
        await fetch_url(client, "http://localhost:9090/proxies")
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


@pytest.mark.parametrize("url", ["http://[not a url", "::::"])
async def test_a_malformed_url_raises_FetchError_and_nothing_else(url):
    """Two separate escapes, both past `refresh_all`'s documented "never
    raises" contract and so out of the 6-hourly background refresh pump:
    `urlparse` raises `ValueError` on an unbalanced IPv6 bracket *before* the
    try block, and `httpx.InvalidURL` does not inherit `HTTPError` — it derives
    straight from `Exception` — so it slipped the handler too."""
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    try:
        with pytest.raises(FetchError):
            await fetch_url(client, url)
    finally:
        await client.aclose()


async def test_a_proxied_fetcher_does_not_resolve_the_hostname_locally():
    """The SSRF guard's `getaddrinfo` was a plaintext DNS query from the
    router — and router-origin traffic takes OUTPUT, so it is never captured.
    On the proxied path httpx never resolves (it sends `CONNECT host:port`), so
    the guard was the *only* lookup: it handed every subscription hostname to
    the ISP's resolver, on every fetch and every 6-hourly refresh. That is the
    one thing `kitewrt.proxied` exists to prevent.
    """
    from kitewrt import fetch as fetch_mod

    resolved: list[str] = []

    async def spy(host):
        resolved.append(host)
        return False

    original = fetch_mod.resolve_blocks_ssrf
    fetch_mod.resolve_blocks_ssrf = spy
    try:
        direct = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        assert await fetch_url(direct, "https://sub.example.test/x") == b""
        assert resolved == ["sub.example.test"], "the direct path must still be guarded"

        resolved.clear()
        proxied = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))

        async def tunnels():
            return True

        proxied.tunnels = tunnels  # what ProxiedFetcher answers when the proxy is up
        assert await fetch_url(proxied, "https://sub.example.test/x") == b""
        assert resolved == []
        await direct.aclose()
        await proxied.aclose()
    finally:
        fetch_mod.resolve_blocks_ssrf = original


@pytest.mark.parametrize(
    "url", ["http://localhost:9090/proxies", "http://metadata.google.internal/computeMetadata/v1/"]
)
async def test_a_name_that_is_local_by_definition_is_blocked_on_the_proxied_path_too(url):
    """The proxied fetcher opts out of the *resolving* guard (it would leak the
    hostname to the ISP resolver), which left `localhost` unguarded on that
    path entirely — and a proxied `CONNECT localhost:9090` is resolved by
    sing-box's own `dns-local`, i.e. back to the router. The name check costs no
    lookup, so it applies on both paths."""
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))

    async def tunnels():
        return True

    client.tunnels = tunnels
    with pytest.raises(FetchError, match="non-public"):
        await fetch_url(client, url)
    await client.aclose()


@pytest.mark.parametrize("url", ["http://127.0.0.1:9090/proxies", "http://169.254.169.254/meta"])
async def test_a_sensitive_ip_literal_is_still_blocked_on_the_proxied_path(url):
    """Opting out of the *resolving* check must not opt out of the literal one
    — that half costs no DNS and blocks the obvious targets (the local Clash
    controller, cloud metadata). Private LAN ranges stay allowed on purpose, so
    a user can self-host their subscription."""
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))

    async def tunnels():
        return True

    client.tunnels = tunnels
    with pytest.raises(FetchError, match="non-public"):
        await fetch_url(client, url)
    await client.aclose()
