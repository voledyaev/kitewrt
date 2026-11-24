"""Keep process-shared readiness locks private to each hermetic test."""

import pytest
from kitewrt import killswitch


@pytest.fixture(autouse=True)
def private_readiness_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(killswitch, "RELOAD_LOCK_PATH", tmp_path / "readiness.lock")
    monkeypatch.setattr(killswitch, "_reload_mutex", None)
    monkeypatch.setattr(killswitch, "_reload_owner", None)
