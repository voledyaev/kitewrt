"""Incident context must be useful, bounded and exclude authentication material."""

import asyncio
import json
import os
from types import SimpleNamespace

import pytest
from kitewrt import diag


def state():
    return SimpleNamespace(
        vpn_on=True,
        applying=False,
        active_server=SimpleNamespace(subscription_id="s", server_id="n"),
        subscriptions=[SimpleNamespace(id="s", servers=[SimpleNamespace(id="n")])],
    )


class Clash:
    async def current(self, selector):
        return "s/n"

    async def probe_delay(self, name, *, timeout_ms):
        return SimpleNamespace(reachable=False, delay_ms=None)


def config(tmp_path, address="1.1.1.1", protocol="vless"):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "outbounds": [
                    {
                        "tag": "s/n",
                        "type": protocol,
                        "server": address,
                        "server_port": 443,
                        "uuid": "DO-NOT-COPY-UUID",
                        "password": "DO-NOT-COPY-PASSWORD",
                        "tls": {
                            "enabled": True,
                            "server_name": "example.test",
                            "reality": {"private_key": "DO-NOT-COPY-KEY"},
                        },
                    }
                ]
            }
        )
    )
    return path


async def test_context_keeps_endpoint_and_selector_but_not_credentials(tmp_path, monkeypatch):
    calls = []

    async def dial(host, port, **kwargs):
        calls.append((host, port, kwargs))
        return {"status": "connected", "source_ip": "192.0.2.1"}

    monkeypatch.setattr(diag, "_dial", dial)
    raw = await diag._connection_context(
        state(), Clash(), "select", config(tmp_path), probe_network=True
    )
    info = json.loads(raw.split(b"=====\n", 1)[1])
    assert info["configured_endpoint"]["address"] == "1.1.1.1"
    assert info["selector_matches_intent"] is True
    assert info["unauthenticated_tls_probe"]["status"] == "connected"
    assert info["proxy_probe"] == {"reachable": False, "delay_ms": None}
    assert len(calls) == 2
    assert all(
        secret not in raw.decode()
        for secret in ("DO-NOT-COPY-UUID", "DO-NOT-COPY-PASSWORD", "DO-NOT-COPY-KEY")
    )


@pytest.mark.parametrize(
    "address,protocol,applying,probe",
    [
        ("127.0.0.1", "vless", False, True),
        ("192.168.1.1", "vless", False, True),
        ("example.test", "vless", False, True),
        ("1.1.1.1", "hysteria2", False, True),
        ("1.1.1.1", "vless", True, True),
        ("1.1.1.1", "vless", False, False),
    ],
)
async def test_context_never_probes_private_unresolved_udp_or_applying(
    tmp_path, monkeypatch, address, protocol, applying, probe
):
    async def forbidden(*args, **kwargs):
        pytest.fail("unexpected network probe")

    monkeypatch.setattr(diag, "_dial", forbidden)
    snap = state()
    snap.applying = applying
    raw = await diag._connection_context(
        snap, Clash(), "select", config(tmp_path, address, protocol), probe_network=probe
    )
    assert b'"status": "skipped"' in raw


async def test_snapshot_is_private_before_writing_and_names_do_not_collide(tmp_path, monkeypatch):
    original = os.fdopen

    def check_mode(fd, *args, **kwargs):
        assert os.fstat(fd).st_mode & 0o777 == 0o600
        return original(fd, *args, **kwargs)

    monkeypatch.setattr(diag.os, "fdopen", check_mode)
    monkeypatch.setattr(diag.time, "strftime", lambda *a: "20000101-000000")
    first, second = await asyncio.gather(
        diag.snapshot(tmp_path, "first"), diag.snapshot(tmp_path, "second")
    )
    assert first and second and first != second
    assert "reason: first" in first.read_text()
    assert "reason: second" in second.read_text()


async def test_context_timeout_preserves_the_system_snapshot(tmp_path, monkeypatch):
    async def hung(*args, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(diag, "_connection_context", hung)
    result = await asyncio.wait_for(
        diag.snapshot(tmp_path, "watchdog: node_unreachable", state=state(), timeout_s=0.5),
        timeout=2,
    )
    assert result is not None
    assert b"unavailable within budget" in result.read_bytes()
    assert b"===== sing-box log =====" in result.read_bytes()


async def test_hung_selector_does_not_hide_endpoint_or_transport_probe(tmp_path, monkeypatch):
    class HungSelector(Clash):
        async def current(self, selector):
            await asyncio.Event().wait()

    async def failed_tcp(*args, **kwargs):
        return {"status": "failed", "error": "TimeoutError"}

    monkeypatch.setattr(diag, "_dial", failed_tcp)
    raw = await asyncio.wait_for(
        diag._connection_context(
            state(), HungSelector(), "select", config(tmp_path), probe_network=True
        ),
        timeout=2,
    )
    info = json.loads(raw.split(b"=====\n", 1)[1])
    assert info["selector_error"] == "TimeoutError"
    assert info["configured_endpoint"]["address"] == "1.1.1.1"
    assert info["tcp_probe"]["status"] == "failed"
    assert "unauthenticated_tls_probe" not in info
    assert info["proxy_probe"]["reachable"] is False


async def test_vpn_off_selector_matches_direct_and_never_probes(tmp_path, monkeypatch):
    class Direct(Clash):
        async def current(self, selector):
            return "direct"

        async def probe_delay(self, *args, **kwargs):
            pytest.fail("VPN-off must not probe the selected proxy")

    async def forbidden(*args, **kwargs):
        pytest.fail("VPN-off must not probe transport")

    monkeypatch.setattr(diag, "_dial", forbidden)
    snap = state()
    snap.vpn_on = False
    raw = await diag._connection_context(
        snap, Direct(), "select", config(tmp_path), probe_network=True
    )
    info = json.loads(raw.split(b"=====\n", 1)[1])
    assert info["selector_matches_intent"] is True
    assert info["tcp_probe"]["status"] == "skipped"


def test_snapshot_collects_post_tproxy_nat_redirects():
    # A mangle-only snapshot hid firmware DNS rewrites after TPROXY.
    assert 'section "nat prerouting"; iptables -w 5 -t nat -S PREROUTING' in diag._SCRIPT
