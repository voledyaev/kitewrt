"""Diagnostic snapshots and the persistent log — the evidence the original
outage did not leave behind (RAM-only logread, gone after the firmware update)."""

from __future__ import annotations

import logging

from kitewrt import diag


async def test_snapshot_writes_the_reason_and_keeps_only_the_newest(tmp_path):
    for i in range(diag.KEEP + 2):
        (tmp_path / f"20000101-00000{i}.txt").write_text("old")
    path = await diag.snapshot(tmp_path, "watchdog: singbox_down")
    assert path is not None
    assert "reason: watchdog: singbox_down" in path.read_text()
    assert "===== sing-box log =====" in path.read_text()
    assert len(list(tmp_path.glob("*.txt"))) == diag.KEEP
    assert path.exists()


async def test_snapshot_never_raises(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert await diag.snapshot(blocker / "diag", "x") is None  # parent is a file


async def test_a_new_fault_takes_one_snapshot(tmp_path, monkeypatch):
    from kitewrt.dataplane import SingBoxWatchdogDeps
    from kitewrt.state import State, now_iso

    taken: list[str] = []

    async def fake_snapshot(directory, reason, **_kw):
        taken.append(reason)

    monkeypatch.setattr(diag, "snapshot", fake_snapshot)
    deps = SingBoxWatchdogDeps(State(tmp_path / "s.json"), None, None, diag_dir=tmp_path / "d")
    await deps.report_fault(now_iso(), "singbox_down")
    await deps.report_fault(now_iso(), "singbox_down")  # already up: no second snapshot
    assert taken == ["watchdog: singbox_down"]


def test_persistent_log_is_written_under_the_data_dir(tmp_path):
    from kitewrt.__main__ import add_persistent_log

    root = logging.getLogger()
    before = list(root.handlers)
    try:
        add_persistent_log(str(tmp_path), "%(message)s")
        logging.getLogger("kitewrt.test").warning("evidence")
        for h in root.handlers:
            h.flush()
        assert "evidence" in (tmp_path / "logs" / "kitewrt.log").read_text()
    finally:
        for h in list(root.handlers):
            if h not in before:
                root.removeHandler(h)
                h.close()


def test_persistent_log_is_skipped_without_a_data_dir():
    from kitewrt.__main__ import add_persistent_log

    root = logging.getLogger()
    n = len(root.handlers)
    add_persistent_log(None, "%(message)s")
    assert len(root.handlers) == n
