"""Managed Python must be verified before activation and safe to unpack on 3.9."""

import io
import tarfile

import pytest
from installer import steps
from installer.resources.extract_python import extract
from installer.ssh import SSHError

from tests.test_installer_singbox import FakeRouter


def archive(tmp_path, members):
    path = tmp_path / "runtime.tgz"
    with tarfile.open(path, "w:gz") as tar:
        for name, target in members:
            entry = tarfile.TarInfo(name)
            if target is not None:
                entry.type = tarfile.SYMTYPE
                entry.linkname = target
                tar.addfile(entry)
            else:
                entry.size = 2
                tar.addfile(entry, io.BytesIO(b"ok"))
    return path


@pytest.mark.parametrize(
    "members",
    [
        [("../escape", None)],
        [("/escape", None)],
        [("python/bin/python3", "/etc/passwd")],
        [("python/bin/python3", "../../../escape")],
        [("python/link", "lib"), ("python/link/module.py", None)],
    ],
)
def test_runtime_archive_rejects_escaping_paths_and_directory_links(tmp_path, members):
    path = archive(tmp_path, members)
    with pytest.raises(ValueError):
        extract(str(path), str(tmp_path / "out"))
    assert not (tmp_path / "escape").exists()


def test_runtime_archive_keeps_only_safe_in_tree_links(tmp_path):
    path = archive(
        tmp_path, [("python/bin/python3.15", None), ("python/bin/python3", "python3.15")]
    )
    extract(str(path), str(tmp_path / "out"))
    assert (tmp_path / "out/python/bin/python3").read_bytes() == b"ok"


@pytest.mark.parametrize("failure", ["checksum", "smoke"])
async def test_failed_runtime_never_switches_active_interpreter(tmp_path, failure):
    asset = f"cpython-{steps.PYTHON_VERSION}+{steps.PYTHON_BUILD}-aarch64-unknown-linux-musl-install_only_stripped.tar.gz"
    (tmp_path / asset).write_bytes(b"fixture")

    def respond(cmd):
        if cmd.startswith(steps.REMOTE_APP + "/python-"):
            return 1, "", "not installed"
        if "sha256sum" in cmd:
            digest = (
                "bad"
                if failure == "checksum"
                else steps.PYTHON_SHA256["aarch64-unknown-linux-musl"]
            )
            return 0, digest + "  python.tgz", ""
        if ".python-stage/python/bin/python3" in cmd and failure == "smoke":
            return 1, "", "bad runtime"
        return 0, "", ""

    router = FakeRouter(respond)
    with pytest.raises((SystemExit, SSHError)):
        await steps.install_managed_python(router, "arm64", artifacts_dir=tmp_path)
    assert not any("os.replace(link" in cmd for cmd in router.commands)
    assert any("rm -rf /tmp/kitewrt_python" in cmd for cmd in router.commands)


async def test_managed_runtime_passes_smoke_before_atomic_link_switch(tmp_path):
    def respond(cmd):
        if cmd.startswith(steps.REMOTE_APP + "/python-"):
            return 1, "", "not installed"
        if "sha256sum" in cmd:
            return 0, steps.PYTHON_SHA256["aarch64-unknown-linux-musl"] + "  python.tgz", ""
        return 0, "", ""

    router = FakeRouter(respond)
    assert (
        await steps.install_managed_python(router, "arm64", artifacts_dir=tmp_path)
        == steps.REMOTE_PYTHON
    )
    smoke = next(
        i for i, c in enumerate(router.commands) if ".python-stage/python/bin/python3" in c
    )
    activate = next(i for i, c in enumerate(router.commands) if "os.replace(link" in c)
    assert smoke < activate


async def test_dependency_activation_happens_after_old_daemon_stops(tmp_path, monkeypatch):
    import shlex

    from installer.ssh import LocalRouter

    root = tmp_path / "app"
    root.mkdir()
    for name, value in [("vendor", "old"), ("vendor.next", "new")]:
        (root / name).mkdir()
        (root / name / "version").write_text(value)
    source = tmp_path / "source"
    source.mkdir()
    (source / "__init__.py").write_text("")
    stopped = tmp_path / "stopped"
    init = tmp_path / "daemon.init"
    init.write_text(
        "#!/bin/sh\nset -e\n"
        + 'test "$(cat '
        + shlex.quote(str(root / "vendor/version"))
        + ')" = old\n'
        + "touch "
        + shlex.quote(str(stopped))
        + "\n"
    )
    init.chmod(0o755)
    for name, value in {
        "REMOTE_APP": str(root),
        "REMOTE_VENDOR": str(root / "vendor"),
        "REMOTE_DATA": str(tmp_path / "data"),
        "SINGBOX_DIR": str(tmp_path / "sing-box"),
        "KITEWRT_INIT": str(init),
        "GUARD_INIT": str(tmp_path / "no-guard"),
    }.items():
        monkeypatch.setattr(steps, name, value)
    await steps.deploy_source(LocalRouter(), source)
    assert stopped.exists()
    assert (root / "vendor/version").read_text() == "new"
    assert (root / "vendor.previous/version").read_text() == "old"
