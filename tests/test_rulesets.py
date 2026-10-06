"""kitewrt.rulesets — local copies of remote rule-sets.

The property everything here protects: sing-box must be able to start with no
network. A remote rule-set it has no cached copy of is downloaded before any
inbound binds, and a failed download is FATAL — measured on the live router as
a procd crash loop and a LAN with no DNS.
"""

from __future__ import annotations

import json
import os
import time

import pytest
from kitewrt import rulesets
from kitewrt.rulesets import (
    EMPTY_SOURCE,
    EMPTY_SRS,
    ensure_present,
    is_placeholder,
    local_path,
    localize,
    prune,
    refresh,
)
from kitewrt.singbox.config import build_config
from kitewrt.state import Data

BIN = {
    "tag": "geoip-x",
    "type": "remote",
    "format": "binary",
    "url": "https://example.com/geoip-x.srs",
    "download_detour": "proxy",
}
SRC = {"tag": "list", "type": "remote", "url": "https://example.com/list.json"}
INLINE = {"tag": "inl", "type": "inline", "rules": [{"ip_cidr": ["203.0.113.0/24"]}]}

REAL_SRS = b"SRS\x01" + b"\x00" * 64


def test_localize_rewrites_remote_and_keeps_others(tmp_path):
    out = localize([BIN, SRC, INLINE], tmp_path)
    assert out[0] == {
        "type": "local",
        "tag": "geoip-x",
        "format": "binary",
        "path": str(local_path(tmp_path, BIN)),
    }
    assert out[1]["format"] == "source"  # inferred from the .json URL
    assert out[1]["path"].endswith(".json")
    assert out[2] == INLINE


def test_local_path_is_keyed_on_the_url_not_the_tag(tmp_path):
    renamed = {**BIN, "tag": "something-else"}
    moved = {**BIN, "url": "https://example.com/other.srs"}
    assert local_path(tmp_path, renamed) == local_path(tmp_path, BIN)
    assert local_path(tmp_path, moved) != local_path(tmp_path, BIN)


def test_build_config_localizes_only_when_asked(tmp_path):
    snap = Data(rule_sets=[BIN], rules=[{"rule_set": ["geoip-x"], "outbound": "direct"}])
    remote = build_config(snap)["route"]["rule_set"][0]
    assert remote["type"] == "remote"
    local = build_config(snap, ruleset_dir=tmp_path)["route"]["rule_set"][0]
    assert local["type"] == "local" and "download_detour" not in local


def test_contents_changing_does_not_change_the_config(tmp_path):
    """An update must not look structural — that would restart sing-box for
    something it reloads by itself."""
    from kitewrt.dataplane import _structural_key

    snap = Data(rule_sets=[BIN])
    ensure_present(snap.rule_sets, tmp_path)
    before = _structural_key(build_config(snap, ruleset_dir=tmp_path))
    local_path(tmp_path, BIN).write_bytes(REAL_SRS)
    assert _structural_key(build_config(snap, ruleset_dir=tmp_path)) == before


def test_ensure_present_writes_empty_placeholders_once(tmp_path):
    assert set(ensure_present([BIN, SRC, INLINE], tmp_path)) == {"geoip-x", "list"}
    assert local_path(tmp_path, BIN).read_bytes() == EMPTY_SRS
    assert json.loads(local_path(tmp_path, SRC).read_bytes()) == {"version": 1, "rules": []}
    local_path(tmp_path, BIN).write_bytes(REAL_SRS)
    assert ensure_present([BIN, SRC], tmp_path) == []  # never clobbers real data
    assert local_path(tmp_path, BIN).read_bytes() == REAL_SRS


def test_placeholders_are_generic():
    """No country's data is bundled: the placeholder is an empty set."""
    assert EMPTY_SOURCE.strip() == b'{"version": 1, "rules": []}'
    assert EMPTY_SRS.startswith(b"SRS")


def _downloader(responses: dict[str, bytes | Exception], calls: list | None = None):
    async def download(url: str, via_proxy_first: bool) -> bytes:
        if calls is not None:
            calls.append((url, via_proxy_first))
        r = responses[url]
        if isinstance(r, Exception):
            raise r
        return r

    return download


async def test_refresh_replaces_placeholders_and_honours_the_detour(tmp_path):
    ensure_present([BIN, SRC], tmp_path)
    calls: list = []
    dl = _downloader({BIN["url"]: REAL_SRS, SRC["url"]: b'{"version":1,"rules":[{}]}'}, calls)
    res = await refresh([BIN, SRC], tmp_path, dl)
    assert res == {"geoip-x": "updated", "list": "updated"}
    assert local_path(tmp_path, BIN).read_bytes() == REAL_SRS
    assert (BIN["url"], True) in calls  # download_detour: proxy → VPN first
    assert (SRC["url"], False) in calls  # no detour → direct first


async def test_failed_download_keeps_what_is_there(tmp_path):
    local_path(tmp_path, BIN).parent.mkdir(parents=True, exist_ok=True)
    local_path(tmp_path, BIN).write_bytes(REAL_SRS)
    os.utime(local_path(tmp_path, BIN), (0, 0))  # stale → will try
    res = await refresh([BIN], tmp_path, _downloader({BIN["url"]: OSError("node dead")}))
    assert res["geoip-x"].startswith("failed")
    assert local_path(tmp_path, BIN).read_bytes() == REAL_SRS


@pytest.mark.parametrize(
    ("rs", "body"),
    [
        (BIN, b"<html>blocked</html>"),
        (SRC, b"<html>blocked</html>"),
        (SRC, b'{"no": "rules"}'),
    ],
)
async def test_garbage_never_replaces_a_working_file(tmp_path, rs, body):
    """A block page swapped in would be live-reloaded into a broken set and make
    the next start FATAL."""
    path = local_path(tmp_path, rs)
    path.parent.mkdir(parents=True, exist_ok=True)
    good = REAL_SRS if rs is BIN else b'{"version":1,"rules":[]}'
    path.write_bytes(good)
    os.utime(path, (0, 0))
    res = await refresh([rs], tmp_path, _downloader({rs["url"]: body}))
    assert res[rs["tag"]].startswith("failed")
    assert path.read_bytes() == good
    assert not list(tmp_path.glob("*.new"))


async def test_fresh_files_are_not_downloaded(tmp_path):
    path = local_path(tmp_path, BIN)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(REAL_SRS)
    calls: list = []
    res = await refresh([BIN], tmp_path, _downloader({BIN["url"]: REAL_SRS}, calls))
    assert res == {"geoip-x": "fresh"} and calls == []


async def test_a_placeholder_is_never_fresh(tmp_path):
    ensure_present([BIN], tmp_path)
    assert is_placeholder(local_path(tmp_path, BIN))
    res = await refresh([BIN], tmp_path, _downloader({BIN["url"]: REAL_SRS}))
    assert res == {"geoip-x": "updated"}


async def test_unchanged_download_does_not_swap_the_file(tmp_path):
    path = local_path(tmp_path, BIN)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(REAL_SRS)
    os.utime(path, (0, 0))
    ino = path.stat().st_ino
    res = await refresh([BIN], tmp_path, _downloader({BIN["url"]: REAL_SRS}))
    assert res == {"geoip-x": "unchanged"}
    assert path.stat().st_ino == ino  # no rename → sing-box does not reload
    assert time.time() - path.stat().st_mtime < 60  # age check restarted


async def test_sing_box_gets_the_last_word_on_a_binary(tmp_path):
    fake = tmp_path / "sing-box"
    fake.write_text("#!/bin/sh\necho 'decode: bad rule-set' >&2\nexit 1\n")
    fake.chmod(0o755)
    ensure_present([BIN], tmp_path / "rs")
    res = await refresh(
        [BIN], tmp_path / "rs", _downloader({BIN["url"]: REAL_SRS}), sing_box_bin=fake
    )
    assert "bad rule-set" in res["geoip-x"]
    assert is_placeholder(local_path(tmp_path / "rs", BIN))


def test_prune_spares_young_files(tmp_path):
    ensure_present([BIN, SRC], tmp_path)
    prune([BIN], tmp_path)  # SRC's file was just written: must survive
    assert local_path(tmp_path, SRC).exists()
    prune([BIN], tmp_path, now=time.time() + rulesets.PRUNE_MIN_AGE_S + 1)
    assert not local_path(tmp_path, SRC).exists()
    assert local_path(tmp_path, BIN).exists()
