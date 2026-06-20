"""Hermetic tests for the OpenWrt installer steps.

A fake Router records `run` commands and `upload_bytes`/`upload_directory`
payloads and replays scripted results, so these exercise the step logic
(idempotency, arch→URL mapping, fw3 wiring, credential-free scrub) without a
router.
"""

from __future__ import annotations

import json

import pytest
from installer import steps


class FakeRouter:
    user = "root"
    host = "192.168.8.1"

    def __init__(self, responder=None):
        # responder(cmd) -> (rc, out, err); default: success, empty output.
        self._responder = responder or (lambda cmd: (0, "", ""))
        self.commands: list[str] = []
        self.uploads: list[tuple[str, bytes, int]] = []
        self.dir_uploads: list[tuple[str, str]] = []

    async def run(self, cmd, *, check=False, timeout=0.0, stdin=None):
        self.commands.append(cmd)
        return self._responder(cmd)

    async def opkg_update(self, *, timeout=180.0):
        self.commands.append("opkg update")

    async def upload_bytes(self, data, path, mode=0o644):
        self.uploads.append((path, data, mode))

    async def upload_directory(self, local, remote):
        self.dir_uploads.append((str(local), remote))


# --- detect_arch -----------------------------------------------------------


async def test_detect_arch_maps_uname():
    r = FakeRouter(lambda cmd: (0, "aarch64\n", "") if "uname" in cmd else (0, "", ""))
    assert await steps.detect_arch(r) == "arm64"


# --- preflight_space -------------------------------------------------------


async def test_preflight_space_fails_when_overlay_too_small():
    r = FakeRouter(lambda cmd: (0, "10240\n", "") if "df -Pk /overlay" in cmd else (0, "", ""))
    with pytest.raises(SystemExit):  # 10 MB < 80 MB needed
        await steps.preflight_space(r)


async def test_preflight_space_passes_with_room():
    r = FakeRouter(lambda cmd: (0, "5000000\n", "") if "df -Pk /overlay" in cmd else (0, "", ""))
    await steps.preflight_space(r)  # ~4.8 GB free → no raise


async def test_preflight_space_skips_when_unreadable():
    r = FakeRouter(lambda cmd: (0, "", ""))  # df returns nothing for both paths
    await steps.preflight_space(r)  # can't read → don't block


# --- install_singbox -------------------------------------------------------


async def test_install_singbox_skips_when_version_matches():
    def respond(cmd):
        if "version" in cmd:
            return (0, f"sing-box version {steps.SINGBOX_VERSION}\n", "")
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.install_singbox(r, "arm64")
    # No download attempted (only the version probe ran).
    assert not any("releases/download" in c for c in r.commands)


async def test_install_singbox_downloads_static_arch_url():
    captured = {}

    def respond(cmd):
        if "releases/download" in cmd:
            captured["cmd"] = cmd
            return (0, "", "")
        if "version" in cmd:
            # not installed until the download ran; then reports the version
            return (
                (0, f"sing-box version {steps.SINGBOX_VERSION}\n", "") if captured else (1, "", "")
            )
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.install_singbox(r, "arm64")
    assert "linux-arm64.tar.gz" in captured["cmd"]
    assert "-musl" not in captured["cmd"]  # static Go build, no libc variant
    assert steps.SINGBOX_VERSION in captured["cmd"]


# --- musl loader shim -------------------------------------------------------


async def test_loader_shim_created_when_glibc_loader_missing():
    def respond(cmd):
        if cmd.startswith("[ -e /lib/ld-linux-aarch64.so.1 ]"):
            return (1, "", "")  # glibc loader path absent (musl box)
        if "ls /lib/ld-musl-" in cmd:
            return (0, "/lib/ld-musl-aarch64.so.1\n", "")
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.ensure_loader_shim(r, "arm64")
    assert any(
        "ln -sf /lib/ld-musl-aarch64.so.1 /lib/ld-linux-aarch64.so.1" in c for c in r.commands
    )


async def test_loader_shim_noop_when_loader_resolves():
    # [ -e glibc ] → rc 0 (glibc-compat present / shim already made) → no ln.
    r = FakeRouter(lambda cmd: (0, "", ""))
    await steps.ensure_loader_shim(r, "arm64")
    assert not any("ln -sf" in c for c in r.commands)


async def test_loader_shim_noop_when_not_musl():
    def respond(cmd):
        if cmd.startswith("[ -e "):
            return (1, "", "")  # glibc loader absent
        if "ls /lib/ld-musl-" in cmd:
            return (0, "\n", "")  # ...but no musl loader either → not a musl box
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.ensure_loader_shim(r, "arm64")
    assert not any("ln -sf" in c for c in r.commands)


async def test_loader_shim_noop_for_unknown_arch():
    r = FakeRouter(lambda cmd: (0, "", ""))
    await steps.ensure_loader_shim(r, "mips")
    assert r.commands == []  # unsupported arch → returns before touching the router


# --- offline artifacts ------------------------------------------------------


def test_singbox_artifact_name_matches_github_release():
    assert steps.singbox_artifact_name("1.13.13", "arm64") == "sing-box-1.13.13-linux-arm64.tar.gz"


def test_default_artifacts_dir_is_under_installer():
    d = steps.default_artifacts_dir()
    assert d.name == "artifacts" and d.parent.name == "installer"


def test_find_local_artifact_present_and_absent(tmp_path):
    assert steps.find_local_artifact(tmp_path, "x.tar.gz") is None
    (tmp_path / "x.tar.gz").write_bytes(b"z")
    assert steps.find_local_artifact(tmp_path, "x.tar.gz") == tmp_path / "x.tar.gz"
    assert steps.find_local_artifact(None, "x.tar.gz") is None


def test_find_local_wheels(tmp_path):
    assert steps.find_local_wheels(tmp_path) == []  # no wheels/ subdir
    wd = tmp_path / "wheels"
    wd.mkdir()
    (wd / "b.whl").write_bytes(b"b")
    (wd / "a.whl").write_bytes(b"a")
    (wd / "note.txt").write_bytes(b"ignored")
    assert steps.find_local_wheels(tmp_path) == [wd / "a.whl", wd / "b.whl"]  # sorted, .whl only


async def test_install_singbox_uses_local_artifact_no_github(tmp_path):
    art = tmp_path / "artifacts"
    art.mkdir()
    name = steps.singbox_artifact_name(steps.SINGBOX_VERSION, "arm64")
    (art / name).write_bytes(b"FAKE_SB_TARBALL")
    seen = {"version": 0}

    def respond(cmd):
        if "version" in cmd:
            seen["version"] += 1
            # not installed on the first probe; installed after extract
            if seen["version"] == 1:
                return (1, "", "")
            return (0, f"sing-box version {steps.SINGBOX_VERSION}\n", "")
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.install_singbox(r, "arm64", artifacts_dir=art)
    # No GitHub fetch; the local tarball was uploaded to the staging path instead.
    assert not any("releases/download" in c for c in r.commands)
    assert not any("curl" in c or "wget" in c for c in r.commands)
    assert ("/tmp/sb_dl/sb.tgz", b"FAKE_SB_TARBALL", 0o644) in r.uploads


async def test_install_singbox_fails_on_checksum_mismatch(tmp_path):
    art = tmp_path / "artifacts"
    art.mkdir()
    name = steps.singbox_artifact_name(steps.SINGBOX_VERSION, "arm64")
    (art / name).write_bytes(b"TAMPERED")

    def respond(cmd):
        if "sha256sum" in cmd:
            return (0, "deadbeef" * 8 + "\n", "")  # wrong hash
        if "version" in cmd:
            return (1, "", "")  # not installed → proceed to verify
        return (0, "", "")

    r = FakeRouter(respond)
    with pytest.raises(SystemExit):  # fail() on mismatch
        await steps.install_singbox(r, "arm64", artifacts_dir=art)
    # Refused before extracting/installing.
    assert not any("mv " in c and steps.SINGBOX_BIN in c for c in r.commands)


async def test_install_singbox_guards_tar_traversal():
    # The extract command refuses path-traversal / absolute members.
    captured = {}

    def respond(cmd):
        if "tar tzf" in cmd or "tar xzf" in cmd:
            captured["extract"] = cmd
        if "version" in cmd:
            return (
                (0, f"sing-box version {steps.SINGBOX_VERSION}\n", "") if captured else (1, "", "")
            )
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.install_singbox(r, "arm64")  # no artifact, no pinned-hash match (empty sha → skip)
    assert "tar tzf" in captured["extract"] and "unsafe tarball member" in captured["extract"]


async def test_install_singbox_downloads_when_artifact_absent(tmp_path):
    # Empty artifacts dir → falls back to the GitHub download path.
    captured = {}

    def respond(cmd):
        if "releases/download" in cmd:
            captured["cmd"] = cmd
            return (0, "", "")
        if "version" in cmd:
            return (
                (0, f"sing-box version {steps.SINGBOX_VERSION}\n", "") if captured else (1, "", "")
            )
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.install_singbox(r, "arm64", artifacts_dir=tmp_path)
    assert "linux-arm64.tar.gz" in captured["cmd"]


async def test_install_pip_deps_offline_uses_local_wheels(tmp_path):
    wd = tmp_path / "wheels"
    wd.mkdir()
    (wd / "httpx-0.28.1-py3-none-any.whl").write_bytes(b"whl")
    r = FakeRouter()
    await steps.install_pip_deps(r, artifacts_dir=tmp_path)
    # Wheels dir shipped once (tar), and pip resolves strictly offline from it.
    assert any(remote == "/tmp/kitewrt_wheels" for _local, remote in r.dir_uploads)
    pip = next(c for c in r.commands if "pip3 install" in c)
    assert "--no-index" in pip and "--find-links=/tmp/kitewrt_wheels" in pip


async def test_install_pip_deps_online_when_no_wheels(tmp_path):
    r = FakeRouter()
    await steps.install_pip_deps(r, artifacts_dir=tmp_path)  # no wheels/ subdir
    pip = next(c for c in r.commands if "pip3 install" in c)
    assert "--no-index" not in pip
    assert r.dir_uploads == []


# --- no bundled geo ---------------------------------------------------------


def test_installer_ships_no_geo_rulesets():
    # kitewrt must not download or reference any geo/.srs data — that's the
    # user's (remote rule-sets). Guards against re-introducing it.
    assert not hasattr(steps, "install_geo_rulesets")
    import pathlib

    text = pathlib.Path(steps.__file__).read_text()
    assert ".srs" not in text
    assert "geoip" not in text and "geosite" not in text


# --- scrub_singbox_config ---------------------------------------------------


async def test_scrub_writes_credential_free_config():
    r = FakeRouter(lambda cmd: (0, "", ""))  # [ -f config ] → present
    await steps.scrub_singbox_config(r)
    assert len(r.uploads) == 1
    path, data, mode = r.uploads[0]
    assert path == steps.SINGBOX_CONFIG
    assert mode == 0o600
    cfg = json.loads(data)
    # No vless outbounds → no UUIDs/keys; selector points only at direct.
    assert not any(o.get("type") == "vless" for o in cfg["outbounds"])
    selector = next(o for o in cfg["outbounds"] if o["type"] == "selector")
    assert selector["outbounds"] == ["direct"]
    assert b"uuid" not in data.lower()


async def test_scrub_skips_when_no_config():
    r = FakeRouter(lambda cmd: (1, "", ""))  # [ -f config ] → absent
    await steps.scrub_singbox_config(r)
    assert r.uploads == []


# --- stop_singbox -----------------------------------------------------------


async def test_stop_singbox_noop_when_init_absent():
    r = FakeRouter(lambda cmd: (1, "", ""))  # [ -x init ] → absent
    await steps.stop_singbox(r)
    assert not any(f"{steps.SINGBOX_INIT} stop" in c for c in r.commands)


async def test_stop_singbox_runs_when_present():
    r = FakeRouter(lambda cmd: (0, "", ""))  # [ -x init ] → present
    await steps.stop_singbox(r)
    assert any(f"{steps.SINGBOX_INIT} stop" in c for c in r.commands)


# --- init scripts -----------------------------------------------------------


async def test_install_init_scripts_uploads_and_enables():
    r = FakeRouter()
    rc = b"#!/bin/sh /etc/rc.common\n"
    await steps.install_init_scripts(r, rc, rc)
    paths = [u[0] for u in r.uploads]
    assert steps.SINGBOX_INIT in paths
    assert steps.KITEWRT_INIT in paths
    joined = "\n".join(r.commands)
    assert f"{steps.SINGBOX_INIT} enable" in joined
    assert f"{steps.KITEWRT_INIT} enable" in joined


# --- fw3 wiring -------------------------------------------------------------


async def test_setup_firewall_writes_tun_zone_and_forwarding():
    r = FakeRouter()
    await steps.setup_firewall(r)
    joined = "\n".join(r.commands)
    assert "firewall.kitewrt_singbox=zone" in joined
    assert f"device='{steps.TUN_DEVICE}'" in joined
    assert "src='lan'" in joined and "dest='singbox'" in joined
    assert "/etc/init.d/firewall reload" in joined  # backend-agnostic (fw3 + fw4)
    # MSS-clamp include registered + its script uploaded.
    assert "firewall.kitewrt_mss_clamp=include" in joined
    assert steps.MSS_CLAMP_PATH in joined
    assert any(path == steps.MSS_CLAMP_PATH for path, _, _ in r.uploads)
    body = next(data for path, data, _ in r.uploads if path == steps.MSS_CLAMP_PATH)
    assert b"clamp-mss-to-pmtu" in body


async def test_remove_firewall_deletes_named_sections():
    r = FakeRouter()
    await steps.remove_firewall(r)
    joined = "\n".join(r.commands)
    assert "delete firewall.kitewrt_singbox" in joined
    assert "delete firewall.kitewrt_lan2singbox" in joined
    assert "delete firewall.kitewrt_mss_clamp" in joined  # MSS include dropped too


async def test_remove_app_scrubs_state_and_cache():
    r = FakeRouter()
    await steps.remove_app(r)
    joined = "\n".join(r.commands)
    assert steps.REMOTE_APP in joined  # package dir
    assert "/etc/kitewrt" in joined  # state.json (credentials) — privacy guarantee
    assert "cache.db" in joined


async def test_start_daemon_ok_when_health_responds():
    def respond(cmd):
        if "api/health" in cmd:
            return (0, '{"ok":true,"host":"OpenWrt"}', "")
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.start_daemon(r, attempts=3, interval_s=0)  # no real sleeping
    # reached here without raising → success


async def test_start_daemon_hard_fails_when_never_healthy():
    # health always non-zero (uvicorn bound then died / never started)
    r = FakeRouter(lambda cmd: (7, "", "") if "api/health" in cmd else (0, "", ""))
    with pytest.raises(SystemExit):
        await steps.start_daemon(r, attempts=2, interval_s=0)


async def test_install_pip_deps_fails_loudly_on_missing_dep():
    def respond(cmd):
        if "import fastapi" in cmd:  # the import smoke-test
            return (1, "ModuleNotFoundError: No module named 'eval_type_backport'", "")
        return (0, "", "")

    r = FakeRouter(respond)
    with pytest.raises(SystemExit):
        await steps.install_pip_deps(r)


# --- ensure_tools (curl + sha256sum) ---------------------------------------


async def test_ensure_tools_noop_when_present():
    r = FakeRouter(lambda cmd: (0, "/usr/bin/x", "") if "command -v" in cmd else (0, "", ""))
    await steps.ensure_tools(r)  # both present → no opkg, no raise
    assert not any("opkg install" in c for c in r.commands)


async def test_ensure_tools_installs_missing_curl():
    seen = {"curl": 0}

    def respond(cmd):
        if "command -v curl" in cmd:
            seen["curl"] += 1
            return (1, "", "") if seen["curl"] == 1 else (0, "/usr/bin/curl", "")
        return (0, "/usr/bin/sha256sum", "")  # sha256sum present

    r = FakeRouter(respond)
    await steps.ensure_tools(r)
    assert any("opkg install curl" in c for c in r.commands)


async def test_ensure_tools_fails_when_uninstallable():
    # curl never resolves even after opkg → router can't be configured.
    r = FakeRouter(lambda cmd: (1, "", "") if "command -v curl" in cmd else (0, "", ""))
    with pytest.raises(SystemExit):
        await steps.ensure_tools(r)
