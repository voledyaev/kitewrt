"""Tests for the fail-closed kill switch module.

Hermetic: the iptables / ip subprocess layer is monkeypatched so nothing
touches the host firewall. We assert the command shapes and engage/disengage
behaviour. The integration with SingBoxService (restart bracketing) lives in
test_singbox_runtime.py.
"""

from __future__ import annotations

import pytest
from kitewrt import killswitch


@pytest.fixture(autouse=True)
def _reset_depth():
    # The reentrancy refcount is module-global; isolate each test.
    killswitch._engaged_depth = 0
    yield
    killswitch._engaged_depth = 0


@pytest.fixture
def fake_ipt(monkeypatch):
    """Record every iptables invocation; make them all succeed."""
    calls: list[list[str]] = []

    async def rec(args, timeout=5.0):
        calls.append(list(args))
        return 0

    monkeypatch.setattr(killswitch, "_ipt", rec)
    return calls


def test_parse_default_dev_single():
    assert killswitch._parse_default_dev("default via 192.168.1.1 dev eth1\n") == "eth1"


def test_parse_default_dev_none_when_no_route():
    assert killswitch._parse_default_dev("") is None
    assert killswitch._parse_default_dev("unreachable default proto static") is None


def test_parse_default_dev_multi_wan_warns(caplog):
    text = "default via 10.0.0.1 dev eth1\ndefault via 10.0.1.1 dev wwan0 metric 10\n"
    with caplog.at_level("WARNING"):
        dev = killswitch._parse_default_dev(text)
    assert dev == "eth1"  # guards the first
    assert "multiple default routes" in caplog.text


def test_insert_delete_arg_shapes():
    assert killswitch._insert_args("eth3")[:4] == ["-I", "FORWARD", "1", "-o"]
    assert killswitch._insert_args("eth3")[-1] == killswitch.COMMENT
    assert killswitch._delete_args("eth3")[0] == "-D"


async def test_engage_disengage_refcount_nesting(fake_ipt):
    # Outer engage inserts once; a nested engage doesn't re-insert; the nested
    # disengage doesn't lift the guard; only the outer disengage removes it.
    assert await killswitch.engage("eth3")  # outer
    assert await killswitch.engage("eth3")  # nested
    assert len([c for c in fake_ipt if c[0] == "-I"]) == 1
    await killswitch.disengage("eth3")  # nested exit → no delete
    assert not any(c[0] == "-D" for c in fake_ipt)
    await killswitch.disengage("eth3")  # outer exit → delete
    assert any(c[0] == "-D" for c in fake_ipt)


async def test_engage_inserts_drop_with_comment(fake_ipt):
    ok = await killswitch.engage("eth3")
    assert ok is True
    assert fake_ipt == [
        [
            "-I",
            "FORWARD",
            "1",
            "-o",
            "eth3",
            "-j",
            "DROP",
            "-m",
            "comment",
            "--comment",
            "kitewrt-killswitch",
        ]
    ]


async def test_engage_reports_failure(monkeypatch):
    async def fail(args, timeout=5.0):
        return 1

    monkeypatch.setattr(killswitch, "_ipt", fail)
    assert await killswitch.engage("eth3") is False


async def test_disengage_deletes_until_absent(monkeypatch):
    # Two copies present, then nothing: expect 3 delete attempts (2 ok, 1 miss).
    results = iter([0, 0, 1])
    seen: list[list[str]] = []

    async def rec(args, timeout=5.0):
        seen.append(list(args))
        return next(results, 1)

    monkeypatch.setattr(killswitch, "_ipt", rec)
    await killswitch.disengage("eth3")
    assert len(seen) == 3
    assert all(a[0] == "-D" for a in seen)


async def test_sweep_noop_without_wan(monkeypatch):
    async def no_wan():
        return None

    called = False

    async def rec(args, timeout=5.0):
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr(killswitch, "detect_wan", no_wan)
    monkeypatch.setattr(killswitch, "_ipt", rec)
    await killswitch.sweep()
    assert called is False
