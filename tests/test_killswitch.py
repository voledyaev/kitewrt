"""Tests for the fail-closed kill switch module.

Hermetic: the iptables / ip subprocess layer is monkeypatched so nothing
touches the host firewall. We assert the command shapes and engage/disengage
behaviour. The integration with SingBoxService (restart bracketing) lives in
test_singbox_runtime.py.
"""

from __future__ import annotations

import asyncio

import pytest
from kitewrt import killswitch


@pytest.fixture(autouse=True)
def _reset_depth():
    # The reentrancy refcount is module-global; isolate each test. Reset the lock
    # to None so it's recreated lazily inside THIS test's event loop on first use
    # — a module-level asyncio.Lock binds to the loop it's built in (at
    # construction time on Python 3.9), which otherwise leaks across test loops.
    killswitch._engaged_depth = 0
    killswitch._lock = None
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


async def test_disengage_retries_on_transient_timeout(monkeypatch):
    # A transient timeout (-1, e.g. xtables-lock contention) on the first delete
    # must NOT be read as "no rule left" — retry, so a single timeout can't
    # strand the DROP and black out the whole LAN.
    results = iter([-1, 0, 1])  # timeout, delete one, absent
    seen: list[list[str]] = []

    async def rec(args, timeout=5.0):
        seen.append(list(args))
        return next(results, 1)

    monkeypatch.setattr(killswitch, "_ipt", rec)
    await killswitch.disengage("eth3")
    assert len(seen) == 3  # did not stop on the -1


async def test_disengage_gives_up_after_repeated_timeouts(monkeypatch, caplog):
    # Persistent failure is bounded (no infinite loop) and surfaced.
    async def always_timeout(args, timeout=5.0):
        return -1

    monkeypatch.setattr(killswitch, "_ipt", always_timeout)
    with caplog.at_level("WARNING"):
        await killswitch.disengage("eth3")
    assert "leftover DROP may persist" in caplog.text


async def test_concurrent_engages_insert_once_and_hold(monkeypatch):
    # Two independent brackets (apply pipeline + watchdog) engaging at the same
    # time must insert the DROP exactly once and hold it until BOTH disengage —
    # the TOCTOU race the lock closes. The yield inside _ipt forces interleaving;
    # without the lock both coroutines would observe depth==0 and double-insert.
    inserts: list[int] = []
    del_results = iter([0, 1])  # one real delete, then absent

    async def rec(args, timeout=5.0):
        await asyncio.sleep(0)  # yield mid-call to interleave the two engages
        if args[0] == "-I":
            inserts.append(1)
            return 0
        return next(del_results, 1)

    monkeypatch.setattr(killswitch, "_ipt", rec)
    results = await asyncio.gather(killswitch.engage("eth3"), killswitch.engage("eth3"))
    assert all(results)
    assert len(inserts) == 1  # locked → outer engage is atomic
    assert killswitch._engaged_depth == 2
    await killswitch.disengage("eth3")  # first bracket exits — guard holds
    assert killswitch._engaged_depth == 1
    await killswitch.disengage("eth3")  # second exits — guard lifts
    assert killswitch._engaged_depth == 0


async def test_sweep_finds_the_drop_by_comment_not_by_device(monkeypatch):
    """The two states sweep() exists for, both of which it used to miss.

    It keyed the delete on `detect_wan()`. With no default route yet — the
    normal reading at S95 on a PPPoE or slow-DHCP WAN, i.e. exactly when the
    previous boot's DROP is still there — it did nothing at all; with a WAN
    that had since changed name it deleted a rule that does not exist and
    reported success. Measured on a 5.4 kernel: a DROP stranded on eth0 while
    the default route was br-lan survived four consecutive sweeps.
    """
    stranded = f"-A FORWARD -o eth0 -m comment --comment {killswitch.COMMENT} -j DROP"
    live = [stranded]
    deletes: list[list[str]] = []

    async def dump(args, timeout=5.0):
        return 0, "-P FORWARD ACCEPT\n" + "\n".join(live) + "\n"

    async def rec(args, timeout=5.0):
        deletes.append(args)
        live.clear()
        return 0

    async def no_wan():
        return None  # the case that used to make this a total no-op

    monkeypatch.setattr(killswitch, "_ipt_capture", dump)
    monkeypatch.setattr(killswitch, "_ipt", rec)
    monkeypatch.setattr(killswitch, "detect_wan", no_wan)
    await killswitch.sweep()
    assert len(deletes) == 1
    assert "-D" in deletes[0] and "eth0" in deletes[0]


async def test_sweep_reports_when_it_cannot_read_the_chain(monkeypatch):
    """A stranded DROP blocks the whole LAN and the caller is about to engage a
    new one on top, so an unreadable chain must not read as a clean sweep."""
    deletes = []

    async def unreadable(args, timeout=5.0):
        return -1, ""

    async def rec(args, timeout=5.0):
        deletes.append(args)
        return 0

    monkeypatch.setattr(killswitch, "_ipt_capture", unreadable)
    monkeypatch.setattr(killswitch, "_ipt", rec)
    await killswitch.sweep()
    assert deletes == []  # nothing guessed at


async def test_sweep_noop_when_nothing_is_stranded(monkeypatch):
    async def clean(args, timeout=5.0):
        return 0, "-P FORWARD ACCEPT\n-A FORWARD -j zone_lan_forward\n"

    called = False

    async def rec(args, timeout=5.0):
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr(killswitch, "_ipt_capture", clean)
    monkeypatch.setattr(killswitch, "_ipt", rec)
    await killswitch.sweep()
    assert called is False
