"""Tests for ApplyPipeline machinery (signal coalescing + result recording).

The pipeline is data-plane-agnostic: it delegates each apply to the injected
DataPlane and records the outcome. The concrete sing-box plane is tested in
test_dataplane_singbox.py; here we use a fake plane to exercise the loop.
"""

import asyncio

from kitewrt.apply import ApplyPipeline
from kitewrt.state import Data, State


class FakeDataPlane:
    """Records apply() calls; scriptable result."""

    def __init__(self, result=(True, "")):
        self.result = result
        self.calls = 0

    def parse_rules(self, raw):
        return []

    async def apply(self, snap: Data):
        self.calls += 1
        return self.result


async def _run_one(state, plane):
    p = ApplyPipeline(state, plane)
    await p.start()
    p.signal()
    for _ in range(50):
        await asyncio.sleep(0.01)
        if state.snapshot().last_apply is not None:
            break
    await p.stop()


async def test_apply_records_success(tmp_path):
    state = State(tmp_path / "state.json")
    await state.update(lambda d: setattr(d, "applying", True))
    plane = FakeDataPlane((True, ""))

    await _run_one(state, plane)

    snap = state.snapshot()
    assert plane.calls == 1
    assert snap.last_apply.ok is True
    assert snap.applying is False  # cleared by the worker
    assert snap.last_error == ""


async def test_apply_records_failure(tmp_path):
    state = State(tmp_path / "state.json")
    plane = FakeDataPlane((False, "sing-box: boom"))

    await _run_one(state, plane)

    snap = state.snapshot()
    assert snap.last_apply.ok is False
    assert snap.last_apply.msg == "sing-box: boom"
    assert snap.last_error == "sing-box: boom"


async def test_successful_apply_clears_stale_error(tmp_path):
    state = State(tmp_path / "state.json")
    await state.update(lambda d: setattr(d, "last_error", "stale"))
    plane = FakeDataPlane((True, ""))

    await _run_one(state, plane)

    assert state.snapshot().last_error == ""


class RaisingDataPlane:
    """apply() raises on the first call, succeeds after — to prove the worker
    records the failure (clears `applying`) and survives to serve more signals."""

    def __init__(self):
        self.calls = 0

    def parse_rules(self, raw):
        return []

    async def apply(self, snap):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("kaboom")
        return True, ""


async def test_apply_crash_clears_applying_and_records_failure(tmp_path):
    state = State(tmp_path / "state.json")
    await state.update(lambda d: setattr(d, "applying", True))
    plane = RaisingDataPlane()

    await _run_one(state, plane)

    snap = state.snapshot()
    assert snap.applying is False  # cleared despite the exception
    assert snap.last_apply.ok is False
    assert "kaboom" in snap.last_apply.msg


async def test_apply_loop_survives_a_raising_apply(tmp_path):
    state = State(tmp_path / "state.json")
    plane = RaisingDataPlane()

    p = ApplyPipeline(state, plane)
    await p.start()
    p.signal()
    for _ in range(50):
        await asyncio.sleep(0.01)
        if state.snapshot().last_apply is not None:
            break
    assert state.snapshot().last_apply.ok is False  # first apply crashed

    # The worker must still be alive: a second signal applies successfully.
    p.signal()
    for _ in range(50):
        await asyncio.sleep(0.01)
        if state.snapshot().last_apply.ok:
            break
    await p.stop()
    assert state.snapshot().last_apply.ok is True
    assert plane.calls == 2


class CoalesceProbe:
    """First apply re-signals the pipeline (a click landing mid-apply); the
    second apply blocks on a gate so the test can observe state between the two
    coalesced passes."""

    def __init__(self):
        self.calls = 0
        self.pipeline = None
        self.gate = asyncio.Event()
        self.in_second = asyncio.Event()

    def parse_rules(self, raw):
        return []

    async def apply(self, snap):
        self.calls += 1
        if self.calls == 1:
            self.pipeline.signal()  # queue a 2nd pass during the first apply
            return True, ""
        self.in_second.set()
        await self.gate.wait()
        return True, ""


async def test_applying_stays_true_across_coalesced_applies(tmp_path):
    # The watchdog defers its recovery restart while applying() is true; that
    # flag must stay on continuously across back-to-back coalesced applies, not
    # blink false between them (which would let the watchdog restart concurrently
    # with a structural reload — the concurrency the kill switch must survive).
    state = State(tmp_path / "state.json")
    plane = CoalesceProbe()
    p = ApplyPipeline(state, plane)
    plane.pipeline = p
    await state.update(lambda d: setattr(d, "applying", True))
    await p.start()
    p.signal()
    # Wait until the SECOND (coalesced) apply is running.
    await asyncio.wait_for(plane.in_second.wait(), timeout=2.0)
    assert state.snapshot().applying is True  # never blinked false
    plane.gate.set()
    for _ in range(100):
        await asyncio.sleep(0.01)
        if not state.snapshot().applying:
            break
    await p.stop()
    assert plane.calls == 2
    assert state.snapshot().applying is False  # last pass clears it


async def test_set_applying_failure_does_not_kill_worker(tmp_path):
    # A durable-write failure when flagging `applying` (e.g. OSError on a full
    # overlay) must NOT kill the worker — that would strand applying=True forever
    # and make the watchdog defer recovery permanently. The apply still runs.
    state = State(tmp_path / "state.json")
    plane = FakeDataPlane((True, ""))
    p = ApplyPipeline(state, plane)

    n = 0
    orig = p._set_applying

    async def flaky(value):
        nonlocal n
        n += 1
        if n == 1 and value is True:
            raise OSError("disk full")
        await orig(value)

    p._set_applying = flaky

    await p.start()
    p.signal()
    for _ in range(50):
        await asyncio.sleep(0.01)
        if state.snapshot().last_apply is not None:
            break
    await p.stop()

    assert plane.calls == 1  # apply still ran despite the flag-set failure
    assert state.snapshot().last_apply is not None
    assert state.snapshot().last_apply.ok is True


async def test_rapid_signals_coalesce(tmp_path):
    state = State(tmp_path / "state.json")
    plane = FakeDataPlane((True, ""))

    p = ApplyPipeline(state, plane)
    await p.start()
    for _ in range(10):
        p.signal()
    for _ in range(100):
        await asyncio.sleep(0.01)
        if state.snapshot().last_apply is not None:
            break
    await p.stop()

    # 10 signals collapse into at most 2 iterations (one running + one re-set
    # during it), never 10.
    assert 1 <= plane.calls <= 2
