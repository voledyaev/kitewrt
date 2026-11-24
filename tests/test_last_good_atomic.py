"""Config promotion requires a complete rollback copy from this very operation."""

import json
import os
from pathlib import Path

import pytest
from kitewrt import dataplane


class Service:
    def __init__(self, succeeds=True):
        self.succeeds = succeeds
        self.restarts = 0

    async def check_config(self, path):
        return True, ""

    async def restart(self, *, after=None):
        self.restarts += 1
        return self.succeeds, "failed" if not self.succeeds else ""

    async def restart_without_cache(self, *, after=None):
        return False, "failed without cache"


def files(tmp_path):
    live = tmp_path / "config.json"
    backup = live.with_suffix(".json.last-good")
    live.write_text('{"old":true}')
    backup.write_text('{"older":true}')
    backup.chmod(0o600)
    return live, backup


async def test_partial_backup_failure_aborts_promotion_and_preserves_previous_backup(
    tmp_path, monkeypatch
):
    live, backup = files(tmp_path)
    svc = Service()
    plane = dataplane.SingBoxDataPlane(svc, None, config_path=live)

    def partial(source, output):
        assert os.fstat(output.fileno()).st_mode & 0o777 == 0o600
        output.write(b"{broken")
        raise OSError("disk full")

    monkeypatch.setattr(dataplane.shutil, "copyfileobj", partial)
    ok, msg = await plane._reload_locked({"new": True}, "key", "direct")
    assert not ok and msg.startswith("backup config failed:")
    assert json.loads(live.read_text()) == {"old": True}
    assert json.loads(backup.read_text()) == {"older": True}
    assert svc.restarts == 0
    assert not list(tmp_path.glob("*.tmp"))
    assert not live.with_suffix(".json.staging").exists()


@pytest.mark.parametrize("failure", ["replace", "fsync"])
async def test_backup_publication_failure_never_promotes(tmp_path, monkeypatch, failure):
    live, backup = files(tmp_path)
    svc = Service()
    plane = dataplane.SingBoxDataPlane(svc, None, config_path=live)
    if failure == "replace":
        original = os.replace

        def replace(src, dst):
            if Path(dst) == backup:
                raise OSError("rename denied")
            return original(src, dst)

        monkeypatch.setattr(dataplane.os, "replace", replace)
    else:
        original = dataplane._atomic_private_copy

        def fsync_copy(source, dest):
            def fail(fd):
                raise OSError("fsync failed")

            with monkeypatch.context() as patch:
                patch.setattr(dataplane.os, "fsync", fail)
                original(source, dest)

        monkeypatch.setattr(dataplane, "_atomic_private_copy", fsync_copy)
    ok, _ = await plane._reload_locked({"new": True}, "key", "direct")
    assert not ok
    assert json.loads(live.read_text()) == {"old": True}
    assert svc.restarts == 0


async def test_successful_backup_replaces_older_copy_with_private_live_bytes(tmp_path):
    live, backup = files(tmp_path)
    backup.chmod(0o644)
    plane = dataplane.SingBoxDataPlane(Service(), None, config_path=live)
    assert await plane._reload_locked({"new": True}, "key", "direct") == (True, "")
    assert json.loads(live.read_text()) == {"new": True}
    assert json.loads(backup.read_text()) == {"old": True}
    assert backup.stat().st_mode & 0o777 == 0o600


async def test_first_start_never_restores_unrelated_old_backup(tmp_path):
    live = tmp_path / "config.json"
    backup = live.with_suffix(".json.last-good")
    backup.write_text('{"unrelated":true}')
    svc = Service(succeeds=False)
    plane = dataplane.SingBoxDataPlane(svc, None, config_path=live)
    ok, _ = await plane._reload_locked({"new": True}, "key", "direct")
    assert not ok
    assert json.loads(live.read_text()) == {"new": True}
    assert svc.restarts == 1


async def test_rollback_write_failure_is_reported_instead_of_restarting_bad_config(
    tmp_path, monkeypatch
):
    live, backup = files(tmp_path)
    original = dataplane._atomic_private_copy

    def restore_fails(source, dest):
        if source == backup:
            raise OSError("restore failed")
        original(source, dest)

    monkeypatch.setattr(dataplane, "_atomic_private_copy", restore_fails)
    svc = Service(succeeds=False)
    plane = dataplane.SingBoxDataPlane(svc, None, config_path=live)
    ok, msg = await plane._reload_locked({"new": True}, "key", "direct")
    assert not ok and msg.startswith("rollback config failed:")
    assert svc.restarts == 1
