"""Hermetic tests for the OpenWrt installer steps.

A fake Router records `run` commands and `upload_bytes`/`upload_directory`
payloads and replays scripted results, so these exercise the step logic
(idempotency, arch→URL mapping, fw3 wiring, credential-free scrub) without a
router.
"""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
from installer import steps
from installer.ssh import SSHError


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
        rc, out, err = self._responder(cmd)
        # Honour `check` like the real Router does. It used to be ignored, so a
        # scripted rc=1 sailed past every `check=True` call and tests reached
        # code the router never would have — which is how a mutant that skipped
        # the checksum entirely went uncaught.
        if check and rc != 0:
            raise SSHError(f"remote command failed (rc={rc}): {cmd}\n--stderr--\n{err}")
        return rc, out, err

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


def _pinned_sha(cmd: str):
    """The checksum step answering with the pin, for the arm64 tarball.

    Every install_singbox test needs it now: an unverifiable download is a hard
    stop, so a router that answers "" to sha256sum no longer reaches the
    extract at all.
    """
    return (0, f"{steps.SINGBOX_SHA256['arm64']}  /tmp/sb_dl/sb.tgz\n", "")


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
        if "sha256sum" in cmd:
            return _pinned_sha(cmd)
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
        if "sha256sum" in cmd:
            return _pinned_sha(cmd)
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


async def test_install_singbox_downloads_when_artifact_absent(tmp_path):
    # Empty artifacts dir → falls back to the GitHub download path.
    captured = {}

    def respond(cmd):
        if "releases/download" in cmd:
            captured["cmd"] = cmd
            return (0, "", "")
        if "sha256sum" in cmd:
            return _pinned_sha(cmd)
        if "version" in cmd:
            return (
                (0, f"sing-box version {steps.SINGBOX_VERSION}\n", "") if captured else (1, "", "")
            )
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.install_singbox(r, "arm64", artifacts_dir=tmp_path)
    assert "linux-arm64.tar.gz" in captured["cmd"]


def _uv_ready(cmd):
    """A router where the uv download + checksum + extract all succeed."""
    if "sha256sum" in cmd:
        return (0, f"{steps.UV_SHA256['aarch64-unknown-linux-musl']}  /tmp/kitewrt_uv/uv.tgz", "")
    if "uv --version" in cmd:
        # Derived from the pin, not a literal. It matched UV_VERSION only
        # because both were written in the same commit (d83a919); the first
        # bump of the pin — this one — is what would have desynced them.
        return (0, f"uv {steps.UV_VERSION}", "")
    return (0, "", "")


async def test_install_deps_offline_uses_local_wheels(tmp_path):
    wd = tmp_path / "wheels"
    wd.mkdir()
    (wd / "httpx-0.28.1-py3-none-any.whl").write_bytes(b"whl")
    (tmp_path / steps.uv_artifact_name("arm64")).write_bytes(b"uv-tarball")
    r = FakeRouter(_uv_ready)
    await steps.install_python_deps(r, "arm64", artifacts_dir=tmp_path)
    assert any(remote == "/tmp/kitewrt_wheels" for _local, remote in r.dir_uploads)
    install = next(c for c in r.commands if "uv pip install" in c)
    assert "--offline" in install and "--find-links /tmp/kitewrt_wheels" in install
    # Installed from the exported lock, never from a version range.
    assert "--requirements /tmp/kitewrt_uv/requirements.txt" in install
    assert not any("pip3 install" in c for c in r.commands)


async def test_install_deps_online_when_no_wheels(tmp_path):
    (tmp_path / steps.uv_artifact_name("arm64")).write_bytes(b"uv-tarball")
    r = FakeRouter(_uv_ready)
    await steps.install_python_deps(r, "arm64", artifacts_dir=tmp_path)
    install = next(c for c in r.commands if "uv pip install" in c)
    assert "--offline" not in install
    assert r.dir_uploads == []


async def test_uv_is_verified_before_it_is_executed(tmp_path):
    """It runs as root and installs the code that becomes the control plane, so
    a tampered download must not reach `tar`, let alone execution."""
    (tmp_path / steps.uv_artifact_name("arm64")).write_bytes(b"tampered")

    def respond(cmd):
        if "sha256sum" in cmd:
            return (0, "deadbeef" * 8 + "  /tmp/kitewrt_uv/uv.tgz", "")
        return (0, "", "")

    r = FakeRouter(respond)
    with pytest.raises(SystemExit):
        await steps.install_python_deps(r, "arm64", artifacts_dir=tmp_path)
    assert not any("tar xzf" in c and "uv.tgz" in c for c in r.commands)


# --- the two gates on what the router runs as root --------------------------
# Both downloads are unpacked and executed as root, so both are behind a
# checksum and a tarball-member check. Neither gate was symmetric: the uv
# tarball had no member check at all, and the sing-box checksum degraded to a
# warning. These test the gates by driving hostile input through the shell the
# installer actually sends, not by asserting the command string reads right.


def _tgz(members) -> bytes:
    """A gzipped tar built from `(TarInfo, payload|None)` pairs."""
    buf = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tar,
    ):
        for info, payload in members:
            tar.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return buf.getvalue()


def _plain(name: str, data: bytes = b"#!/bin/sh\necho pwned\n"):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o755
    return info, data


def _link(name: str, target: str, kind: bytes):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    info.mode = 0o777
    return info, None


def _hostile_tgz(kind: str, victim: str, escape: str) -> bytes:
    """A uv-shaped tarball (`uv-<target>/uv` plus a sibling) with one hostile
    member. `victim` is an existing file the links aim at; `escape` a path
    outside the extraction dir the names aim at."""
    if kind == "benign":
        return _tgz([_plain("uv-x/uv"), _plain("uv-x/uvx")])
    if kind == "symlink":
        return _tgz([_plain("uv-x/uvx"), _link("uv-x/uv", victim, tarfile.SYMTYPE)])
    if kind == "hardlink":
        return _tgz([_plain("uv-x/uvx"), _link("uv-x/uv", victim, tarfile.LNKTYPE)])
    if kind == "traversal":
        return _tgz([_plain("uv-x/uv"), _plain(f"uv-x/../../{Path(escape).name}")])
    if kind == "absolute":
        return _tgz([_plain("uv-x/uv"), _plain(escape)])
    raise AssertionError(kind)


def _sh(script: str, cwd=None):
    return subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, cwd=cwd)


HOSTILE = ("symlink", "hardlink", "traversal", "absolute")


@pytest.mark.parametrize("kind", HOSTILE)
def test_the_tarball_guard_refuses_hostile_members(tmp_path, kind):
    """Run the guard, don't read it.

    The shapes come from a hostile tarball built by hand and extracted on the
    lab VMs: on busybox (1.33.2 / OpenWrt 21.02.7 and 1.36.1 / 24.10.0) the two
    *name* shapes are rewritten by tar itself and land harmlessly inside the
    extraction dir, while the two *link* shapes go through — which is why the
    name-only check the sing-box path already had would not have stopped the
    thing that actually works.
    """
    victim = tmp_path / "victim"
    victim.write_bytes(b"a file that already exists\n")
    escape = tmp_path / "escaped"
    work = tmp_path / "work"
    work.mkdir()
    (work / "t.tgz").write_bytes(_hostile_tgz(kind, str(victim), str(escape)))

    done = _sh("set -e; " + steps._refuse_unsafe_tarball("t.tgz") + "tar xzf t.tgz", cwd=work)

    assert done.returncode != 0, f"extracted a {kind} member: {done.stdout}{done.stderr}"
    assert "unsafe tarball member" in done.stderr, done.stderr
    assert not escape.exists()


def test_the_tarball_guard_accepts_a_real_release(tmp_path):
    """A guard that refuses the real thing is an install that never happens."""
    work = tmp_path / "work"
    work.mkdir()
    (work / "t.tgz").write_bytes(_hostile_tgz("benign", "", ""))
    done = _sh("set -e; " + steps._refuse_unsafe_tarball("t.tgz") + "tar xzf t.tgz", cwd=work)
    assert done.returncode == 0, done.stderr
    assert (work / "uv-x" / "uv").is_file()

    # And against the pinned artifact itself when it has been downloaded here —
    # the tarballs are gitignored, so CI checks the shape above instead.
    for real in steps.default_artifacts_dir().glob("sing-box-*.tar.gz"):
        done = _sh("set -e; " + steps._refuse_unsafe_tarball(str(real)) + "true")
        assert done.returncode == 0, f"{real.name}: {done.stderr}"


async def _uv_extract_script(staged: Path) -> str:
    """The exact extract shell `install_uv` sends, retargeted at a local dir.

    Captured from the step rather than restated, so this cannot pass against a
    guard the installer does not actually send.
    """
    r = FakeRouter(_uv_ready)
    await steps.install_uv(r, "arm64")
    script = next(c for c in r.commands if "chmod +x" in c)
    return script.replace("/tmp/kitewrt_uv", str(staged))


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
async def test_the_uv_extract_will_not_chmod_through_a_link(tmp_path, kind):
    """The primitive, not the exit code.

    `install_uv` extracts, `chmod +x`es and then *executes* `uv-*/uv` as root.
    `chmod` dereferences, so a tarball whose `uv` member is a link to an
    existing file marks that file executable. Measured on both lab VMs before
    this guard: /tmp/target went `-rw-r--r--` → `-rwxr-xr-x`, on busybox 1.33.2
    and 1.36.1 alike, for a symlink and for a hardlink.
    """
    staged = tmp_path / "staged"
    staged.mkdir()
    victim = tmp_path / "victim"
    victim.write_bytes(b"not executable\n")
    victim.chmod(0o644)
    (staged / "uv.tgz").write_bytes(_hostile_tgz(kind, str(victim), str(tmp_path / "escaped")))

    done = _sh(await _uv_extract_script(staged))

    assert done.returncode != 0, f"the installer accepted it: {done.stdout}{done.stderr}"
    # By our own refusal, not by the local tar's: bsdtar happens to reject a
    # hardlink out of the archive while busybox — what the router runs — makes
    # it, so a bare "it failed" would pass here and not on the box that matters.
    assert "unsafe tarball member" in done.stderr, done.stderr
    assert victim.stat().st_mode & 0o111 == 0, "root chmod +x'd a file the tarball chose"
    assert not (staged / "uv").exists()


async def test_the_uv_extract_re_checks_what_the_listing_guard_cleared(tmp_path):
    """Two layers, because the first one parses another program's output.

    `tar tv`'s columns are not a contract — busybox prints a hardlink with a
    `-` mode and an arrow, bsdtar with an `h` mode and "link to" — so a tar
    that prints something else walks straight through the listing guard. The
    test right before the `chmod` depends on nothing but the extracted file, so
    this deletes the listing guard from the real script and checks it holds
    alone.
    """
    staged = tmp_path / "staged"
    staged.mkdir()
    victim = tmp_path / "victim"
    victim.write_bytes(b"not executable\n")
    victim.chmod(0o644)
    (staged / "uv.tgz").write_bytes(_hostile_tgz("symlink", str(victim), ""))
    script = await _uv_extract_script(staged)

    done = _sh(script.replace(steps._refuse_unsafe_tarball("uv.tgz"), ""))

    assert done.returncode != 0, f"{done.stdout}{done.stderr}"
    assert "not a plain file" in done.stderr, done.stderr
    assert victim.stat().st_mode & 0o111 == 0


async def test_the_uv_extract_still_installs_a_normal_tarball(tmp_path):
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "uv.tgz").write_bytes(_hostile_tgz("benign", "", ""))

    done = _sh(await _uv_extract_script(staged))

    assert done.returncode == 0, done.stderr
    uv = staged / "uv"
    assert uv.is_file() and not uv.is_symlink() and uv.stat().st_mode & 0o111


async def test_both_downloads_are_extracted_behind_the_same_guard():
    """The asymmetry this closes: sing-box refused unsafe members "because
    busybox tar doesn't guard against them" and uv, fetched from the same
    GitHub behind the same kind of pin, ran a bare `tar xzf`."""
    uv_router = FakeRouter(_uv_ready)
    await steps.install_uv(uv_router, "arm64")
    assert any(steps._refuse_unsafe_tarball("uv.tgz") in c for c in uv_router.commands)

    sb_router = FakeRouter(
        lambda cmd: (
            _pinned_sha(cmd)
            if "sha256sum" in cmd
            else ((1, "", "") if "version" in cmd else (0, "", ""))
        )
    )
    with contextlib.suppress(SystemExit):  # the version re-check can't pass on a fake
        await steps.install_singbox(sb_router, "arm64")
    assert any(steps._refuse_unsafe_tarball("sb.tgz") in c for c in sb_router.commands)


async def test_singbox_will_not_install_when_it_cannot_be_checksummed():
    """It used to `warn("sha256sum unavailable on the router — skipping
    checksum verification")` and install anyway, on a path whose own comment
    calls the download hostile. The pre-flight hard-fails when sha256sum can't
    be installed, so an empty hash here is not a router quirk to shrug at."""
    # sha256sum answers with nothing — which is what "unavailable" looked like.
    r = FakeRouter(
        lambda cmd: (
            (0, "", "")
            if "sha256sum" in cmd
            else ((1, "", "") if "version" in cmd else (0, "", ""))
        )
    )
    with pytest.raises(SystemExit):
        await steps.install_singbox(r, "arm64")
    # Stopped *at* the checksum, not later by luck: nothing was unpacked.
    assert not any("tar xzf" in c for c in r.commands)
    assert not any("mv " in c and steps.SINGBOX_BIN in c for c in r.commands)


async def test_singbox_refuses_an_arch_it_has_no_pin_for(monkeypatch):
    """The other half of the same decision. This used to be `warn(f"no pinned
    checksum for arch {goarch!r} — installing unverified")`, which is a
    sentence about a root binary that nobody would agree to if asked. It is
    unreachable today (the pins cover every detectable arch, asserted below)
    and stays a hard stop so that adding a CPU to the uname map without its
    hash stops one install rather than shipping an unverified data plane."""
    monkeypatch.setattr(steps, "SINGBOX_SHA256", {})
    r = FakeRouter(lambda cmd: (1, "", "") if "version" in cmd else (0, "", ""))
    with pytest.raises(SystemExit):
        await steps.install_singbox(r, "arm64")
    assert not any("tar xzf" in c for c in r.commands)


def test_the_checksum_pins_cover_every_arch_the_installer_can_detect():
    """Both `fail()`s for a missing pin are meant to be unreachable. This is
    what keeps them that way: adding a CPU to the uname map without adding its
    hashes would otherwise turn a hard stop into a broken install."""
    from installer import parsers

    arches = set(parsers._UNAME_TO_GOARCH.values())
    assert arches <= set(steps.SINGBOX_SHA256), "sing-box pin missing for a detectable arch"
    assert arches <= set(steps.UV_TARGETS), "uv build missing for a detectable arch"
    assert {steps.UV_TARGETS[a] for a in arches} <= set(steps.UV_SHA256)


def test_the_preflight_guarantees_sha256sum_before_anything_is_downloaded():
    """What makes an unverifiable download a hard stop rather than a false
    alarm: `ensure_tools` installs sha256sum or refuses the router, and it runs
    before both downloads."""
    import inspect

    from installer import flows

    src = inspect.getsource(flows.do_install)
    assert src.index("ensure_tools") < src.index("install_python_deps")  # fetches uv
    assert src.index("ensure_tools") < src.index("install_singbox")
    assert "coreutils-sha256sum" in inspect.getsource(steps.ensure_tools)


@pytest.mark.parametrize(
    ("what", "step"),
    [("uv", "install_uv"), ("sing-box", "install_singbox")],
)
async def test_a_blocked_github_names_the_file_to_drop_in(tmp_path, capsys, what, step):
    """The failure was truthful and useless: `curl: (7) Failed to connect to
    github.com`, with the filename that fixes it printed ~25 lines and a minute
    earlier, above an opkg install nobody scrolls back through."""

    def respond(cmd):
        if "curl" in cmd or "wget" in cmd:
            raise SSHError(
                "remote command failed (rc=7): curl: (7) Failed to connect to github.com"
            )
        return (1, "", "") if "version" in cmd else (0, "", "")

    r = FakeRouter(respond)
    with pytest.raises(SystemExit):
        await getattr(steps, step)(r, "arm64", artifacts_dir=tmp_path)

    said = capsys.readouterr().err
    name = (
        steps.uv_artifact_name("arm64")
        if what == "uv"
        else steps.singbox_artifact_name(steps.SINGBOX_VERSION, "arm64")
    )
    assert name in said, said
    assert str(tmp_path) in said, "and where to put it — --artifacts-dir moves that"
    assert "Failed to connect to github.com" in said, "without losing the real cause"


# Real stderr from a blackholed github.com on the 24.10.0 VM. curl's own line
# is the third of nine; the last one is a sentence about a webpage.
_CURL_TLS_NOISE = """\
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
curl: (60) mbedTLS: The certificate Common Name (CN) does not match with the expected CN
The certificate is not correctly signed by the trusted CA

More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the webpage mentioned above.
"""


async def test_a_failed_download_quotes_curl_not_the_paragraph_after_it(tmp_path, capsys):
    """A tail of that output ends on "please visit the webpage mentioned
    above", which is the least useful sentence in it."""
    r = FakeRouter(
        lambda cmd: (
            (60, "", _CURL_TLS_NOISE)
            if "curl" in cmd
            else ((1, "", "") if "version" in cmd else (0, "", ""))
        )
    )
    with pytest.raises(SystemExit):
        await steps.install_singbox(r, "arm64", artifacts_dir=tmp_path)

    said = capsys.readouterr().err
    assert "curl: (60) mbedTLS" in said, said
    assert "webpage mentioned above" not in said
    assert "% Total" not in said


async def test_the_exported_lock_is_pinned_and_hashed():
    """What the router installs from. Ranges are what let a router run a
    dependency tree CI had never seen; hashes are what stop a mirror serving
    something else."""
    req = steps.export_locked_requirements().decode()
    assert "fastapi==" in req and "pydantic==" in req
    assert ">=" not in req.split("--hash")[0].split("\n")[-2]
    assert req.count("--hash=sha256:") > 100


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


async def test_sysupgrade_keep_preserves_config_only():
    """A firmware upgrade wipes the overlay and took the whole install with it
    once already. The config dir holds the subscriptions and their credentials
    and nothing else has a copy, so it must be listed — while the vendored
    Python tree must NOT be, or it would survive built against the old
    firmware's interpreter."""
    r = FakeRouter()
    await steps.install_sysupgrade_keep(r)
    body = {path: data for path, data, _mode in r.uploads}
    assert steps.SYSUPGRADE_KEEP_PATH in body
    listed = body[steps.SYSUPGRADE_KEEP_PATH].decode().split()
    assert listed == ["/etc/kitewrt"]
    assert steps.REMOTE_APP not in listed


async def test_uninstall_removes_the_sysupgrade_keep_entry():
    r = FakeRouter()
    await steps.remove_services(r)
    assert steps.SYSUPGRADE_KEEP_PATH in "\n".join(r.commands)


async def test_uninstall_removes_the_runtime_capture():
    """Both the chain and everything that outlives it.

    The capture is created by the daemon and was destroyed only by the daemon's
    lifespan teardown, so uninstall assumed it had run. It has not, in exactly
    the cases people uninstall from: the daemon is already dead, or its bounded
    3 s teardown lost the xtables lock. Measured with the daemon down, the hook
    survived stop_daemon + stop_singbox with nothing listening behind it — a
    dark LAN, and remove_services/remove_app then delete the init script and the
    package, so nothing can ever sweep it.
    """
    r = FakeRouter()
    await steps.remove_capture(r)
    joined = "\n".join(r.commands)
    for needle in (
        steps._CAPTURE_CHAIN,  # the chain and its PREROUTING hook
        steps._BYPASS_SET,  # the ipset it references
        steps._INPUT_ACCEPT_COMMENT,  # matched by comment: the WAN may have been renamed
        steps._KILLSWITCH_COMMENT,  # a DROP stranded by a SIGKILLed daemon
        f"fwmark {steps._TPROXY_MARK}",  # the policy-routing half
        f"table {steps._ROUTE_TABLE}",
    ):
        assert needle in joined, needle


def test_uninstall_flow_actually_calls_the_capture_teardown():
    """The step above is useless if nothing invokes it, and the mutation that
    deleted the call from the flow passed every other test."""
    import inspect

    from installer import flows

    src = inspect.getsource(flows.do_uninstall)
    for name in ("stop_daemon", "stop_singbox", "remove_capture", "remove_services"):
        assert f"steps.{name}(router)" in src, name
    # Order matters: nothing may listen behind the capture while we drop it, and
    # remove_services deletes the init script that is the only other way to.
    assert src.index("stop_singbox") < src.index("remove_capture") < src.index("remove_services")


async def test_ipv6_blocks_are_not_scoped_to_one_zone():
    """A zone-scoped v6 rule lands in that zone's forward chain only, so a guest
    SSID or IoT VLAN egressed IPv6 untouched — with fw3's masquerade being
    v4-only, the destination saw the client's real global address. The IPv4
    capture is deliberately interface-agnostic for exactly this reason; the v6
    half must not enumerate either."""
    r = FakeRouter()
    await steps.setup_firewall(r)
    joined = "\n".join(r.commands)
    for section in (steps._FW_BLOCK_V6, steps._FW_BLOCK_V6_DNS):
        assert f"firewall.{section}.src='*'" in joined, section
        assert f"firewall.{section}.src='lan'" not in joined, section


def test_install_flow_runs_the_prerequisite_probes():
    """A probe nothing calls is a probe that does not exist — deleting the call
    from the flow passed every other test in this file."""
    import inspect

    from installer import flows

    src = inspect.getsource(flows.do_install)
    for name in ("ensure_tproxy", "ensure_iproute2", "ensure_ipset"):
        assert f"steps.{name}(router)" in src, name
    # Both hard stops must run before anything is deployed.
    assert src.index("ensure_iproute2") < src.index("deploy_source")


async def test_iproute2_probe_installs_ip_full_when_busybox_rejects_the_table():
    """The blocker every non-GL.iNet router hit.

    busybox's `ip` applet caps route-table IDs at 255 and the capture needs
    2023, so on stock OpenWrt `ip rule add ... lookup 2023` fails with
    "invalid argument '2023' to 'table ID'". Nothing probed it: the install
    reported 6/6 green, the daemon came up healthy, the UI worked, and only
    the VPN switch failed — with the LAN silently unproxied.
    """
    attempts = {"n": 0}

    def respond(cmd):
        if "ip rule add" in cmd:
            attempts["n"] += 1
            return (
                (1, "", "ip: invalid argument '2023' to 'table ID'")
                if attempts["n"] == 1
                else (0, "", "")
            )
        return (0, "", "")

    r = FakeRouter(respond)
    await steps.ensure_iproute2(r)
    joined = "\n".join(r.commands)
    assert "opkg install ip-full" in joined
    assert attempts["n"] == 2  # probed, installed, re-probed


async def test_iproute2_probe_is_a_hard_stop_when_it_cannot_be_fixed():
    """Refuse rather than install a VPN that would silently not tunnel — the
    same stance ensure_tproxy takes."""
    r = FakeRouter(lambda cmd: (1, "", "") if "ip rule add" in cmd else (0, "", ""))
    with pytest.raises(SystemExit):
        await steps.ensure_iproute2(r)


async def test_the_probe_cannot_drift_from_what_the_daemon_installs():
    """A pre-flight that probes a different table than runtime uses would pass
    on a router where the real thing fails."""
    from kitewrt import divert

    assert int(steps._ROUTE_TABLE) == divert.ROUTE_TABLE
    assert steps.divert_mark() == divert.TPROXY_MARK


# --- fw3 wiring -------------------------------------------------------------


async def test_setup_firewall_removes_the_tun_era_zone():
    """TPROXY delivers to a local socket, so nothing traverses FORWARD and
    sing-box's own egress is masqueraded by the stock `wan` zone. The old
    `singbox` zone and its lan-forwarding are not just unnecessary — leaving
    them behind on an upgrade would keep a zone pointing at a device that no
    longer exists."""
    r = FakeRouter()
    await steps.setup_firewall(r)
    joined = "\n".join(r.commands)
    assert "delete firewall.kitewrt_singbox" in joined
    assert "delete firewall.kitewrt_lan2singbox" in joined
    assert "firewall.kitewrt_singbox=zone" not in joined
    assert "dest='singbox'" not in joined
    assert "/etc/init.d/firewall reload" in joined  # backend-agnostic (fw3 + fw4)
    # MSS-clamp include registered + its script uploaded.
    assert "firewall.kitewrt_mss_clamp=include" in joined
    assert steps.MSS_CLAMP_PATH in joined
    assert any(path == steps.MSS_CLAMP_PATH for path, _, _ in r.uploads)
    body = next(data for path, data, _ in r.uploads if path == steps.MSS_CLAMP_PATH)
    assert b"clamp-mss-to-pmtu" in body


async def test_setup_firewall_blocks_ipv6_egress_and_wan_ui():
    r = FakeRouter()
    await steps.setup_firewall(r)
    joined = "\n".join(r.commands)
    # WAN-side DROP on the control-UI port (defense-in-depth over the default
    # WAN-input REJECT).
    assert "firewall.kitewrt_block_wan_ui=rule" in joined
    assert f"dest_port='{steps.WEB_UI_PORT}'" in joined
    # Fail-closed IPv6 egress block — the data plane is IPv4-only, so forwarded
    # LAN IPv6 must be dropped, not leaked around the tunnel.
    assert "firewall.kitewrt_block_ipv6_egress=rule" in joined
    assert "family='ipv6'" in joined
    assert "dest='wan'" in joined  # lan→wan v6 drop (unique to this rule)


async def test_uninstall_deletes_every_section_install_creates():
    """Derived from `setup_firewall`, not hand-listed — because the hand-list
    was the bug.

    `kitewrt_block_ipv6_dns` was added to the install and never to the
    uninstall, so an uninstalled router went on REJECTing its LAN's IPv6 DNS
    forever with nothing on the box left to explain it. Verified on the VM:
    after `--uninstall`, `uci show firewall | grep kitewrt` still listed all
    seven of that section's lines. Enumerating by hand a second time is what
    lets that happen, so this test does the enumerating.
    """
    installer_router = FakeRouter()
    await steps.setup_firewall(installer_router)
    created = {
        line.split("firewall.", 1)[1].split("=", 1)[0]
        for line in "\n".join(installer_router.commands).splitlines()
        if line.startswith("uci set firewall.")
        and "=" in line
        and "." not in line.split("=")[0][17:]
    }
    assert created, "setup_firewall created no named sections — test is broken"

    uninstaller_router = FakeRouter()
    await steps.remove_firewall(uninstaller_router)
    removed = "\n".join(uninstaller_router.commands)
    missing = [name for name in sorted(created) if f"delete firewall.{name}" not in removed]
    assert not missing, f"install creates these but uninstall never deletes them: {missing}"

    # Retired sections stay in the delete list so an old install still cleans up.
    assert "delete firewall.kitewrt_singbox" in removed
    assert "delete firewall.kitewrt_lan2singbox" in removed


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


async def test_install_deps_fails_loudly_on_missing_dep(tmp_path):
    (tmp_path / steps.uv_artifact_name("arm64")).write_bytes(b"uv-tarball")

    def respond(cmd):
        if "sha256sum" in cmd:
            return (0, f"{steps.UV_SHA256['aarch64-unknown-linux-musl']}  x", "")
        if "import fastapi" in cmd:  # the import smoke-test
            return (1, "ModuleNotFoundError: No module named 'eval_type_backport'", "")
        return (0, "", "")

    r = FakeRouter(respond)
    with pytest.raises(SystemExit):
        await steps.install_python_deps(r, "arm64", artifacts_dir=tmp_path)


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


# --- TPROXY preflight -------------------------------------------------------


async def test_tproxy_probe_passes_when_the_kernel_supports_it():
    r = FakeRouter()
    await steps.ensure_tproxy(r)
    joined = "\n".join(r.commands)
    assert "-j TPROXY" in joined
    # We must NOT demand the `socket` match: the daemon never uses it (the
    # TPROXY target does its own socket lookup), and requiring it refused
    # routers that were perfectly capable.
    assert "-m socket" not in joined
    # Already capable → nothing installed.
    assert "opkg install" not in joined


async def test_tproxy_probe_installs_then_rechecks():
    calls = {"n": 0}

    def responder(cmd):
        if "TPROXY" in cmd:
            calls["n"] += 1
            return (1, "", "") if calls["n"] == 1 else (0, "", "")
        return (0, "", "")

    r = FakeRouter(responder)
    await steps.ensure_tproxy(r)
    joined = "\n".join(r.commands)
    assert "opkg install iptables-mod-tproxy" in joined
    assert calls["n"] == 2  # probed again after installing


async def test_tproxy_missing_is_a_hard_failure(monkeypatch):
    """Not a warning. Without TPROXY the divert installs nothing, so every LAN
    client egresses unproxied while the UI reports the VPN as on — a silent
    failure of the property the tool exists to provide."""
    fails: list[str] = []

    def fake_fail(msg):
        fails.append(msg)
        raise SystemExit(1)

    monkeypatch.setattr(steps, "fail", fake_fail)
    r = FakeRouter(lambda cmd: (1, "", "") if "TPROXY" in cmd else (0, "", ""))
    with pytest.raises(SystemExit):
        await steps.ensure_tproxy(r)
    assert fails and "TPROXY" in fails[0]


async def test_firewall_blocks_ipv6_dns_to_the_router():
    """The leak the egress DROP doesn't cover.

    odhcpd advertises the router as a resolver over IPv6 and dnsmasq listens
    on the LAN's v6 addresses. A client that picks the v6 resolver talks to the
    router over IPv6 — that is INPUT, not FORWARD, so the lan→wan egress DROP
    never sees it — and dnsmasq forwards the query to the ISP in cleartext
    while the VPN is on and the IPv4 exit-IP check reads green. The capture
    can't help: divert speaks iptables, not ip6tables.
    """
    r = FakeRouter()
    await steps.setup_firewall(r)
    joined = "\n".join(r.commands)
    assert "firewall.kitewrt_block_ipv6_dns=rule" in joined
    assert "kitewrt_block_ipv6_dns.family='ipv6'" in joined
    assert "kitewrt_block_ipv6_dns.dest_port='53'" in joined
    # REJECT, not DROP: clients must fail over to the IPv4 resolver at once
    # (that path is captured) instead of waiting out a timeout.
    assert "kitewrt_block_ipv6_dns.target='REJECT'" in joined
    # IPv4 DNS must be untouched — it is the path we actually capture.
    assert "kitewrt_block_ipv6_dns.family='ipv4'" not in joined


# --- --probe ---------------------------------------------------------------


def _strict_posix_shell() -> str | None:
    """A shell whose `command -v` honours POSIX's single-operand rule, as the
    router's busybox `ash` does.

    macOS `/bin/sh` is bash in POSIX mode and happily resolves every operand,
    which is why the multi-argument probe looked correct on a dev machine for
    as long as it did. `dash` (Ubuntu's /bin/sh, so CI's) behaves like ash.
    """
    for name in ("dash", "ash", "sh"):
        path = shutil.which(name)
        if path is None:
            continue
        probe = subprocess.run([path, "-c", "command -v ls echo"], capture_output=True, text=True)
        if len(probe.stdout.split()) == 1:
            return path
    return None


def _run_probe_script(path_prefix: Path | None = None) -> str:
    shell = _strict_posix_shell()
    if shell is None:
        pytest.skip("no POSIX-strict shell here; CI's /bin/sh (dash) is one")
    import os

    from installer import flows

    env = dict(os.environ)
    if path_prefix is not None:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
    # Read-only: every line is a lookup, a `[ -e ]` test or a `-V`/`-n` query.
    return subprocess.run(
        [shell, "-c", flows._PROBE_SCRIPT], capture_output=True, text=True, env=env
    ).stdout


def test_probe_resolves_a_compat_symlink(tmp_path):
    """`fw3: /sbin/fw3` on OpenWrt 22.03+ is a lie of omission: it is a compat
    symlink to fw4, so printing it next to `fw4: /sbin/fw4` read as "this box
    has both firewalls". Verified on the 24.10.0 VM (`/sbin/fw3 -> fw4`) and
    that 21.02.7 has a real one, which this pair stands in for."""
    (tmp_path / "fw4").write_text("#!/bin/sh\n")
    (tmp_path / "fw4").chmod(0o755)
    (tmp_path / "fw3").symlink_to("fw4")

    out = _run_probe_script(tmp_path)

    assert re.search(rf"^fw3: {re.escape(str(tmp_path))}/fw3 -> fw4$", out, re.M), out
    # A real binary keeps reading as one — the arrow means something.
    assert re.search(rf"^fw4: {re.escape(str(tmp_path))}/fw4$", out, re.M), out


def test_probe_reports_every_tool_it_claims_to_check():
    """busybox `ash`'s `command -v` takes exactly ONE operand and discards the
    rest without a word, so `command -v opkg python3 pip3 sing-box fw3 uci
    iptables` reported opkg alone. Verified on the lab VM (OpenWrt 21.02.7,
    kernel 5.4.238): it printed `/bin/opkg`, rc=0.
    """
    from installer import flows

    out = _run_probe_script()
    for tool in flows._PROBE_TOOLS.split():
        assert re.search(rf"^{re.escape(tool)}: ", out, re.M), f"{tool} is not in the probe output"


def test_probe_reports_the_python_version_and_platform_the_readme_promises():
    """The probe printed neither, so the README had to tell people to ssh in
    and run `python3 -V; uname -m`. It now prints a ready-to-paste command —
    which matters more than the flags did, because the flags it printed first
    were *wrong*: `uv --platform: musllinux_1_2_$arch` named a tool with no
    `download` subcommand and a wheel tag that exists for nothing in the
    requirements (pydantic-core publishes musllinux_1_1 only), so pasting it
    produced no bundle at all.
    """
    out = _run_probe_script()
    assert re.search(r"^python: \d+\.\d+", out, re.M), out
    assert re.search(r"^arch: \S+ \((musl|glibc)\)$", out, re.M), out
    assert "musllinux_1_2" not in out, "that tag matches no wheel in the requirements"


async def test_probe_flow_sends_the_script_and_prints_what_came_back(capsys, monkeypatch):
    """A probe nothing runs is a probe that does not exist."""
    from installer import flows

    r = FakeRouter(lambda cmd: (0, "python: 3.9.16\n", ""))

    async def fake_connect(host, user, password, port):
        return r

    async def noop():
        pass

    r.close = noop
    monkeypatch.setattr(flows.Router, "connect", staticmethod(fake_connect))
    await flows.do_probe("192.168.8.1", "root", "pw")
    assert r.commands == [flows._PROBE_SCRIPT]
    assert "python: 3.9.16" in capsys.readouterr().out


def test_offline_report_covers_uv_not_just_sing_box(tmp_path, capsys):
    """The offline hatch has two GitHub downloads, and the report named one.

    A user behind a GitHub block who pre-placed the sing-box tarball read
    "offline sing-box found (will skip GitHub)", concluded they were covered,
    and was then stopped by a GitHub fetch for uv at step [2/6] — which runs
    *before* sing-box, so the reassurance covered the later download and the
    run died at the earlier one.
    """
    from installer import flows

    (tmp_path / steps.singbox_artifact_name(steps.SINGBOX_VERSION, "amd64")).write_bytes(b"x")
    flows._report_artifacts(tmp_path, "amd64")
    out = capsys.readouterr().out

    assert "offline sing-box found" in out
    uv_name = steps.uv_artifact_name("amd64")
    assert uv_name in out, "the uv download must be reported too"
    assert "will download" in out, "and reported as still needing GitHub"


def test_offline_report_is_quiet_about_uv_once_it_is_present(tmp_path, capsys):
    from installer import flows

    for name in (
        steps.singbox_artifact_name(steps.SINGBOX_VERSION, "amd64"),
        steps.uv_artifact_name("amd64"),
    ):
        (tmp_path / name).write_bytes(b"x")
    flows._report_artifacts(tmp_path, "amd64")
    out = capsys.readouterr().out

    assert out.count("will skip GitHub") == 2
    # Wheels are still reported as a PyPI download, because they are one: with
    # both tarballs present and PyPI blocked, two green ticks used to be
    # followed by death at a third download nobody mentioned.
    assert "from PyPI" in out


async def test_install_python_rejects_a_half_installed_interpreter():
    """`command -v python3` is not enough. An install interrupted during
    `opkg install python3` leaves a working binary with no opkg status entry and
    no `python3-urllib`, so the next run reported "✓ python3 installed" and then
    died at the dependency smoke test with `ModuleNotFoundError: No module named
    'urllib'` — accurate, and pointing at entirely the wrong thing. Reproduced
    on armv7 24.10."""
    seen: list[str] = []

    def handler(cmd: str):
        seen.append(cmd)
        if "import urllib.request" in cmd:
            # Broken before the opkg install, fine after it — the half-installed
            # interpreter this test is named for.
            done = any("opkg install python3" in c for c in seen)
            return (0, "", "") if done else (1, "", "No module named 'urllib'")
        return (0, "", "")

    await steps.install_python(FakeRouter(handler))

    assert any("opkg install python3" in c for c in seen), (
        "a python3 that cannot import its own stdlib must be reinstalled"
    )


async def test_the_ipv6_egress_block_does_not_depend_on_zone_membership():
    """`dest='wan'` made fw4 render this as a jump into `drop_to_wan`, which
    holds only the devices in the fw4 `wan` zone — so a v6 uplink outside that
    zone left the chain EMPTY and the rule dropped nothing. Measured on stock
    24.10: vpn_on true, last_apply.ok true, the exit-IP check green, and a LAN
    client with a global v6 address getting 3/3 ping6 replies from the internet
    while the proxy log stayed empty. The v4 capture derives its uplink from the
    actual default route; this derived it from zone membership, and the two
    disagree the moment a second uplink or a tunnel lands elsewhere."""
    seen: list[str] = []
    await steps.setup_firewall(FakeRouter(lambda cmd: (seen.append(cmd), (0, "", ""))[1]))
    script = "\n".join(seen)

    assert "kitewrt-block-ipv6-egress" in script
    assert f"firewall.{steps._FW_BLOCK_V6}.dest='*'" in script, (
        "scoping the v6 drop to a zone is what made it a no-op"
    )
    # ...and the local-traffic escape hatch must come first, or a blanket
    # forward DROP also cuts routed LAN-to-guest v6, which is not egress.
    assert script.index("kitewrt-allow-ipv6-local") < script.index("kitewrt-block-ipv6-egress")
    assert "fc00::/7" in script


def test_the_offline_readme_names_the_versions_actually_pinned():
    """These literals have drifted twice. `installer/artifacts/README.md` hands
    the reader copy-paste `curl` commands for the exact tarballs to pre-place,
    and both are checked against a pinned SHA-256 with no override — so a stale
    version there is not a typo, it is a guaranteed hash mismatch for the one
    user who cannot download from GitHub in the first place."""
    import pathlib

    doc = (
        pathlib.Path(__file__).resolve().parent.parent / "installer" / "artifacts" / "README.md"
    ).read_text()
    assert steps.SINGBOX_VERSION in doc, "the sing-box pin the README tells people to fetch"
    assert steps.UV_VERSION in doc, "the uv pin the README tells people to fetch"


async def test_the_tproxy_step_names_only_what_it_installs():
    """The message announced `iptables-mod-socket` alongside the package it
    actually installs — while the comment eight lines above it explains that the
    `socket` match requirement was removed as invented, because the TPROXY
    target does its own socket lookup. A user reading the output would look for
    a package that was never wanted."""
    seen: list[str] = []

    def handler(cmd: str):
        seen.append(cmd)
        return (1, "", "") if "kitewrt_probe" in cmd and len(seen) < 2 else (0, "", "")

    r = FakeRouter(handler)
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        await steps.ensure_tproxy(r)
    printed = buf.getvalue()
    installed = " ".join(c for c in seen if c.startswith("opkg install"))
    for pkg in ("iptables-mod-tproxy",):
        assert pkg not in printed or pkg in installed, f"{pkg} announced but not installed"
    assert "iptables-mod-socket" not in printed
