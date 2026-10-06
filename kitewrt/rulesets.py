"""Local copies of the user's remote rule-sets.

The user's rules may reference `type: remote` rule-sets (geo data, block lists)
that sing-box downloads itself. That made **startup depend on the network**:
sing-box 1.13 with no cached copy of a remote rule-set downloads it before it
binds a single inbound, and exits FATAL ("initial rule-set") when the download
fails. With `download_detour` pointing at the selector, that download rides the
active node — so a dead node plus a missing cache (a fresh install, a dropped
cache.db, a rule-set newly added to the rules) meant no listener, a procd crash
loop, and a LAN with no DNS at all. Measured on the live router, end to end.

So kitewrt owns the download now:

* Every remote rule-set is rewritten to `type: local`, pointing at a file in
  `<base>/rulesets/` (under `/etc/kitewrt/data`, so it survives a sysupgrade
  via the installer's keep.d entry). The file name is derived from the URL, so
  the generated config — and with it the structural key — does not change when
  the contents do.
* A missing file is replaced by an **empty** rule-set before sing-box ever sees
  the config. An empty set matches nothing: the rules that use it are inert
  until the real data arrives, which is a far better failure than an outage.
  Deliberately generic — no country's data is bundled.
* A background pump downloads the real files — the way the user's
  `download_detour` asks first, then the other way — validates them, and
  swaps them in with a rename. sing-box watches local rule-set files and
  reloads them in place (measured on 1.13.16: a placeholder replaced by
  rename took effect with no restart), so an update costs no restart either.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import time
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# `sing-box rule-set compile` of `{"version": 1, "rules": []}` (sing-box 1.13):
# the "SRS" magic, format version 1, then a zlib stream of an empty set. Kept as
# bytes so a placeholder can be written without the binary (and in tests).
EMPTY_SRS = bytes.fromhex("5352530178da6200040000ffff00010001")
EMPTY_SOURCE = b'{"version": 1, "rules": []}\n'

# Geo rule-sets are tens of KB to a few MB; this only stops a wrong URL from
# filling the overlay.
MAX_RULESET_BYTES = 32 << 20

# A file younger than this is not re-downloaded. sing-box's own default
# `update_interval` for a remote rule-set is one day.
MAX_AGE_S = 24 * 3600

Download = Callable[[str, bool], Awaitable[bytes]]
"""`download(url, via_proxy_first)` → body. Raises on failure."""


def ruleset_dir(base: str | Path) -> Path:
    return Path(base) / "rulesets"


def _format(rule_set: dict[str, Any]) -> str:
    fmt = rule_set.get("format")
    if fmt in ("binary", "source"):
        return str(fmt)
    # sing-box infers it from the extension when the field is omitted.
    path = urlsplit(str(rule_set.get("url", ""))).path
    return "source" if path.endswith(".json") else "binary"


def _is_remote(rule_set: dict[str, Any]) -> bool:
    return rule_set.get("type") == "remote" and bool(rule_set.get("url"))


def local_path(directory: str | Path, rule_set: dict[str, Any]) -> Path:
    """Where a remote rule-set lives locally. Keyed on the URL (not the tag), so
    two rules documents naming the same data share one file, and a changed URL
    never inherits a stale file."""
    digest = hashlib.sha256(str(rule_set["url"]).encode()).hexdigest()[:16]
    ext = "srs" if _format(rule_set) == "binary" else "json"
    return Path(directory) / f"{digest}.{ext}"


def localize(rule_sets: Sequence[dict[str, Any]], directory: str | Path) -> list[dict[str, Any]]:
    """Rewrite every remote rule-set as a local one. Others pass through."""
    out: list[dict[str, Any]] = []
    for rs in rule_sets:
        if not _is_remote(rs):
            out.append(rs)
            continue
        out.append(
            {
                "type": "local",
                "tag": rs["tag"],
                "format": _format(rs),
                "path": str(local_path(directory, rs)),
            }
        )
    return out


def _placeholder(rule_set: dict[str, Any]) -> bytes:
    return EMPTY_SRS if _format(rule_set) == "binary" else EMPTY_SOURCE


def is_placeholder(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return False
    return data in (EMPTY_SRS, EMPTY_SOURCE)


def ensure_present(rule_sets: Sequence[dict[str, Any]], directory: str | Path) -> list[str]:
    """Write an empty placeholder for every remote rule-set with no local file.
    Returns the tags that got one. Must run before a config naming them is
    checked or started: a missing local file is as fatal as a failed download."""
    placed: list[str] = []
    for rs in rule_sets:
        if not _is_remote(rs):
            continue
        path = local_path(directory, rs)
        if path.exists():
            continue
        try:
            _atomic_write(path, _placeholder(rs))
        except OSError as exc:
            logger.error("could not write a placeholder for rule-set %r: %s", rs.get("tag"), exc)
            continue
        placed.append(str(rs.get("tag")))
    if placed:
        logger.warning(
            "rule-sets %s have no local copy yet; starting with empty placeholders "
            "(their rules match nothing until the download lands)",
            ", ".join(placed),
        )
    return placed


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        mv = memoryview(data)
        while mv:
            mv = mv[os.write(fd, mv) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    with contextlib.suppress(OSError):
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


async def _sing_box_accepts(path: Path, sing_box_bin: str | Path | None) -> tuple[bool, str]:
    """Ask sing-box itself whether a compiled rule-set is readable. A file it
    cannot read would be live-reloaded into a broken set and, worse, make the
    next start FATAL — so it never replaces a working one."""
    if sing_box_bin is None or not Path(sing_box_bin).is_file():
        return True, ""
    out = path.with_name(path.name + ".check.json")
    try:
        proc = await asyncio.create_subprocess_exec(
            str(sing_box_bin),
            "rule-set",
            "decompile",
            "--output",
            str(out),
            str(path),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False, "sing-box rule-set decompile timed out"
        if proc.returncode != 0:
            return False, " ".join((stdout or b"").decode(errors="replace").split())[:200]
        return True, ""
    finally:
        with contextlib.suppress(OSError):
            out.unlink()


async def _validate(
    path: Path, rule_set: dict[str, Any], sing_box_bin: str | Path | None
) -> tuple[bool, str]:
    data = path.read_bytes()
    if _format(rule_set) == "binary":
        if not data.startswith(b"SRS"):
            return False, "not a compiled rule-set (no SRS header)"
        return await _sing_box_accepts(path, sing_box_bin)
    try:
        doc = json.loads(data)
    except ValueError as exc:
        return False, f"not JSON: {exc}"
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        return False, "not a source rule-set (no `rules` list)"
    return True, ""


def needs_download(path: Path, *, max_age_s: float = MAX_AGE_S, now: float | None = None) -> bool:
    if not path.exists() or is_placeholder(path):
        return True
    age = (time.time() if now is None else now) - path.stat().st_mtime
    return age >= max_age_s


async def refresh(
    rule_sets: Sequence[dict[str, Any]],
    directory: str | Path,
    download: Download,
    *,
    sing_box_bin: str | Path | None = None,
    max_age_s: float = MAX_AGE_S,
    force: bool = False,
) -> dict[str, str]:
    """Download every remote rule-set that is missing, a placeholder, or older
    than `max_age_s`, and swap it in atomically. Never raises.

    Returns {tag: "updated" | "unchanged" | "fresh" | "failed: <why>"}.
    """
    results: dict[str, str] = {}
    for rs in rule_sets:
        if not _is_remote(rs):
            continue
        tag = str(rs.get("tag"))
        path = local_path(directory, rs)
        if not force and not needs_download(path, max_age_s=max_age_s):
            results[tag] = "fresh"
            continue
        via_proxy_first = rs.get("download_detour") not in (None, "", "direct")
        try:
            body = await download(str(rs["url"]), via_proxy_first)
        except Exception as exc:  # any failure is a retry later, never a crash
            results[tag] = f"failed: {exc}"
            logger.warning("rule-set %r download failed: %s", tag, exc)
            continue
        new = path.with_name(path.name + ".new")
        try:
            _atomic_write(new, body)
            ok, why = await _validate(new, rs, sing_box_bin)
            if not ok:
                results[tag] = f"failed: {why}"
                logger.warning("rule-set %r download rejected: %s", tag, why)
                continue
            if path.exists() and path.read_bytes() == body:
                # Touch it so the age check restarts; no swap, no reload.
                os.utime(path)
                results[tag] = "unchanged"
                continue
            os.replace(new, path)
            results[tag] = "updated"
            logger.info("rule-set %r updated (%d bytes)", tag, len(body))
        except OSError as exc:
            results[tag] = f"failed: {exc}"
            logger.warning("rule-set %r could not be stored: %s", tag, exc)
        finally:
            with contextlib.suppress(OSError):
                new.unlink()
    return results


# A file this young is never pruned. The rule-sets in a snapshot can lag the
# data plane by an apply: a placeholder written for a set the user added a
# second ago must not be deleted by a pump holding the previous list — a
# missing local file is fatal at startup.
PRUNE_MIN_AGE_S = 3600


def prune(
    rule_sets: Sequence[dict[str, Any]], directory: str | Path, *, now: float | None = None
) -> None:
    """Delete local files no current rule-set refers to (and old enough)."""
    keep = {local_path(directory, rs).name for rs in rule_sets if _is_remote(rs)}
    d = Path(directory)
    if not d.is_dir():
        return
    t = time.time() if now is None else now
    for f in d.iterdir():
        if f.suffix not in (".srs", ".json") or f.name in keep:
            continue
        with contextlib.suppress(OSError):
            if t - f.stat().st_mtime >= PRUNE_MIN_AGE_S:
                f.unlink()
