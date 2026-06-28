"""The sing-box data plane behind the apply pipeline.

`ApplyPipeline` owns the worker loop + signal coalescing; the data plane owns
*how* an apply is carried out:

* A *structural* change (servers / rules / DNS) regenerates config.json and
  reloads sing-box.
* A pure *selection* change (pick server / on-off) is a live Clash API call —
  no process restart, no netfilter flush.

The `DataPlane` protocol is kept (rather than inlining) so the apply pipeline
and the rules route stay decoupled from the concrete plane and remain easy to
test with fakes.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from kitewrt.rules import parse_singbox_rules
from kitewrt.singbox.clash import ClashClient, ClashError
from kitewrt.singbox.config import (
    SELECTOR_TAG,
    build_config,
    selector_default,
)
from kitewrt.singbox.service import SingBoxService, write_config
from kitewrt.state import Data, State

logger = logging.getLogger(__name__)


async def reassert_selector(
    clash: ClashClient,
    selector_tag: str,
    target: str,
    *,
    attempts: int,
    delay: float,
    max_seconds: float | None = None,
) -> bool:
    """Select `target` on the selector and CONFIRM it took, retrying within a
    budget. Returns True once `clash.current == target`, False if it never
    converged.

    Meant to run *inside* the kill-switch bracket after a restart, so the DROP
    is held until traffic is actually flowing through the intended outbound —
    never lifted on a slow warmup. sing-box restores the selector from cache_file
    on restart; on the watchdog's cache-drop retry path the cache is gone and the
    selector falls back to the on-disk `default` (possibly a stale `direct`) — so
    re-assert explicitly rather than trust the restore.

    `max_seconds` caps the total wall-clock: the normal warmup fails *fast*
    (connection refused → quick ClashError), but a sing-box whose Clash API
    accepts the connection then hangs would otherwise let `attempts` × the
    client timeout stretch to minutes of FORWARD DROP (LAN blackout). The cap
    bounds that; lifting after it is no less safe than exhausting `attempts`
    (the watchdog then restarts a genuinely wedged sing-box, re-engaging the
    guard). None = no cap (the default, used by tests with instant fakes).
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max_seconds if max_seconds is not None else None
    for _ in range(attempts):
        try:
            if await clash.healthy():
                await clash.select(selector_tag, target)
                if await clash.current(selector_tag) == target:
                    return True  # confirmed on target → safe to lift the guard
        except ClashError as exc:
            logger.debug("selector re-assert retry: %s", exc)
        if deadline is not None and loop.time() >= deadline:
            return False
        await asyncio.sleep(delay)
    return False


class DataPlane(Protocol):
    """What the apply pipeline and the rules route need from a data plane."""

    def parse_rules(self, raw: bytes | str) -> dict[str, list[dict[str, Any]]]: ...

    async def apply(self, snap: Data) -> tuple[bool, str]: ...

    async def ensure_materialized(self, snap: Data) -> tuple[bool, str]: ...


class SingBoxDataPlane:
    """One sing-box process; structural change → reload, selection → live API."""

    def __init__(
        self,
        service: SingBoxService,
        clash: ClashClient,
        *,
        config_path: str | Path,
        selector_tag: str = SELECTOR_TAG,
        reselect_attempts: int = 30,
        reselect_delay: float = 0.5,
        reselect_max_seconds: float = 30.0,
    ):
        self._service = service
        self._clash = clash
        self._config_path = config_path
        self._selector = selector_tag
        # Post-reload selector-confirm budget (~15s default), held inside the
        # kill-switch bracket. Generous so a cold Clash API on a loaded A53 still
        # confirms before the guard lifts; tests pass a 0 delay. The wall-clock
        # cap bounds the worst case (a hung-but-connected Clash API) so the DROP
        # can't blackout the LAN for minutes.
        self._reselect_attempts = reselect_attempts
        self._reselect_delay = reselect_delay
        self._reselect_max_seconds = reselect_max_seconds
        # Structural fingerprint of the last-written config (servers/rules/dns,
        # excluding the selection). None until the first apply.
        self._last_key: str | None = None
        # Whether we've attempted the one-time startup seed of _last_key from
        # the on-disk config (see apply). Distinguishes "never applied" (seed
        # OK) from "_last_key reset to None after a failed reload" (must NOT
        # re-seed — force a clean reload).
        self._seeded = False

    def parse_rules(self, raw: bytes | str) -> dict[str, list[dict[str, Any]]]:
        return parse_singbox_rules(raw)

    async def apply(self, snap: Data) -> tuple[bool, str]:
        cfg = build_config(snap)
        key = _structural_key(cfg)
        target = selector_default(snap)

        if not snap.vpn_on:
            # Off-state: the tun stays up (auto_route keeps capturing), we just
            # point the selector at `direct` so captured traffic egresses
            # unproxied. Pure live switch — no restart, no capture teardown.
            # If sing-box isn't running there's nothing to switch; a later
            # vpn-on apply (or the watchdog) will start it.
            if not await self._service.is_running():
                return True, ""
            try:
                await self._clash.select(self._selector, "direct")
            except ClashError as exc:
                return False, f"clash select direct: {exc}"
            return True, ""

        # vpn-on. Either reload (structural change / not running) or switch live.
        running = await self._service.is_running()
        # First apply after a daemon (re)start: seed the key from the config
        # already on disk so an unchanged structure doesn't trigger a needless
        # reload (process restart + the fail-closed window). At startup the
        # running sing-box was launched from exactly this file, so it's a valid
        # baseline. One-shot (guarded by _seeded), so a _last_key reset after a
        # failed reload still forces a clean reload rather than re-seeding.
        if not self._seeded:
            self._seeded = True
            if running and self._last_key is None:
                self._last_key = self._disk_key()

        if self._last_key != key or not running:
            # _reload re-asserts the selector to `target` inside the kill-switch
            # bracket (a reload restores the selector from cache_file, which can
            # be a stale `direct`; re-asserting before the DROP lifts keeps the
            # window from leaking).
            ok, msg = await self._reload(cfg, key, target)
            if not ok:
                return ok, msg
        else:
            try:
                await self._clash.select(self._selector, target)
            except ClashError as exc:
                logger.warning("clash select failed (%s); falling back to reload", exc)
                ok, msg = await self._reload(cfg, key, target)
                if not ok:
                    return ok, msg

        # Capture follows the process: sing-box's tun + auto_route come up with
        # it and go down with it, so there's nothing extra to assert here.
        return True, ""

    async def ensure_materialized(self, snap: Data) -> tuple[bool, str]:
        """Guarantee sing-box is running with a config that contains every
        outbound in `snap`, so all servers are delay-testable by tag — *without*
        changing the on/off intent.

        Auto-select needs this: a server's outbound is only dialable once it's in
        the *running* config, but adding a subscription deliberately skips the
        reload (so it doesn't disrupt the live connection), and when the VPN is
        off sing-box may not be running at all. Reloads only when the running
        structure is stale or sing-box is down — the common case (active sub
        already materialized) is a no-op, so a plain "find fastest" stays a pure
        live test with no restart blip. After a reload the selector is restored
        to its intended default (direct when off, the active server when on)."""
        cfg = build_config(snap)
        key = _structural_key(cfg)
        if await self._service.is_running() and self._disk_key() == key:
            return True, ""  # running config already has every outbound
        # _reload re-asserts the selector (selector_default) inside the
        # kill-switch bracket.
        ok, msg = await self._reload(cfg, key, selector_default(snap))
        if not ok:
            return False, msg
        # A fresh restart registers the selector (and answers /version) a beat
        # before every per-server outbound appears in the proxy table, so a
        # delay-test fired right now would 404 on nodes that aren't ready yet.
        # Wait for them to register before returning to the caller.
        await self._await_outbounds_ready(cfg)
        return True, ""

    async def _await_outbounds_ready(self, cfg: dict[str, Any]) -> None:
        """Poll /proxies until every server outbound in `cfg` is registered (so
        an immediately-following delay-test doesn't race sing-box's warmup).
        Best-effort: gives up after ~8s and lets the caller proceed — a node
        that's still missing then just reads 'down', no worse than before."""
        want = {
            ob["tag"]
            for ob in cfg.get("outbounds", [])
            if ob.get("type") not in ("selector", "direct")
        }
        if not want:
            return
        for _ in range(27):  # ~8s budget at 0.3s/poll
            have = await self._clash.proxies()
            if all(tag in have for tag in want):
                return
            await asyncio.sleep(0.3)

    async def _select_after_reload(self, target: str) -> None:
        """Re-assert the selector to `target` after a reload, inside the
        kill-switch bracket (the `after` hook). Gives up only after the full
        budget (sing-box is then likely wedged; the watchdog takes over)."""
        if not await reassert_selector(
            self._clash,
            self._selector,
            target,
            attempts=self._reselect_attempts,
            delay=self._reselect_delay,
            max_seconds=self._reselect_max_seconds,
        ):
            logger.warning("post-reload selector not confirmed on %r; lifting guard", target)

    def _disk_key(self) -> str | None:
        """Structural key of the config currently on disk (None if unreadable)."""
        return _read_disk_key(self._config_path, _structural_key)

    async def _reload(self, cfg: dict[str, Any], key: str, target: str) -> tuple[bool, str]:
        """Stage → validate → promote → restart, with rollback.

        A config sing-box rejects must NEVER replace the running one: a bad
        rules/DNS edit would otherwise fail-close the whole LAN (strict_route
        drops captured traffic) with no way back. So we validate a staged copy
        with `sing-box check` first, and keep the previous config as last-good to
        restore if a *promoted* config still fails to come up.

        The selector is re-asserted to `target` *inside* the restart's
        kill-switch bracket (via the `after` hook), so the window between restart
        and reconverge can't leak via whatever sing-box restored from cache_file.
        """
        cfg_path = Path(self._config_path)
        staging = cfg_path.with_suffix(cfg_path.suffix + ".staging")
        backup = cfg_path.with_suffix(cfg_path.suffix + ".last-good")
        try:
            write_config(cfg, staging)
        except Exception as exc:
            return False, f"write config failed: {exc}"

        ok, msg = await self._service.check_config(staging)
        if not ok:
            staging.unlink(missing_ok=True)  # running config untouched
            self._last_key = None
            return False, f"config rejected: {msg}"

        # Keep the current live config as last-good, then promote atomically.
        if cfg_path.exists():
            try:
                shutil.copyfile(cfg_path, backup)
            except OSError:
                pass
        try:
            staging.replace(cfg_path)
        except OSError as exc:
            self._last_key = None
            return False, f"promote config failed: {exc}"

        async def _reselect() -> None:
            await self._select_after_reload(target)

        ok, msg = await self._service.restart(after=_reselect)
        if not ok:
            # A corrupt cache.db (unclean power-off mid-write) can wedge startup;
            # drop it (derived data, safe to lose) and retry once.
            await self._service.drop_cache()
            ok, msg = await self._service.restart(after=_reselect)
        if not ok and backup.exists():
            # The promoted config won't come up: restore last-good and restart so
            # the LAN recovers instead of staying dark behind strict_route.
            logger.warning("reload failed (%s); restoring last-good config", msg)
            try:
                shutil.copyfile(backup, cfg_path)
            except OSError:
                pass
            await self._service.restart(after=_reselect)

        self._last_key = key if ok else None
        return ok, ("" if ok else f"sing-box: {msg}")


class SingBoxWatchdogDeps:
    """Watchdog deps for the sing-box plane: a process that's alive but whose
    Clash API is unresponsive counts as down, so a wedged sing-box (tun up,
    control plane stuck) gets recovered too — not just an outright crash."""

    def __init__(
        self,
        state: State,
        service: SingBoxService,
        clash: ClashClient,
        *,
        selector_tag: str = SELECTOR_TAG,
        reselect_attempts: int = 30,
        reselect_delay: float = 0.5,
        reselect_max_seconds: float = 30.0,
    ):
        self._state = state
        self._service = service
        self._clash = clash
        self._selector = selector_tag
        self._reselect_attempts = reselect_attempts
        self._reselect_delay = reselect_delay
        self._reselect_max_seconds = reselect_max_seconds

    def vpn_on(self) -> bool:
        return self._state.snapshot().vpn_on

    def applying(self) -> bool:
        return self._state.snapshot().applying

    async def is_running(self) -> bool:
        if not await self._service.is_running():
            return False
        return await self._clash.healthy()

    async def restart(self) -> tuple[bool, str]:
        # Re-assert the intended selector inside the kill-switch bracket, exactly
        # like the apply pipeline's reload does. Without it, a recovery restart
        # (especially the cache-drop path below, which wipes store_selected)
        # would come up on whatever the on-disk `selector.default` holds —
        # possibly a stale `direct`, silently routing vpn-on LAN traffic
        # unproxied during the very window the watchdog is meant to heal.
        target = selector_default(self._state.snapshot())

        async def _reselect() -> None:
            await reassert_selector(
                self._clash,
                self._selector,
                target,
                attempts=self._reselect_attempts,
                delay=self._reselect_delay,
                max_seconds=self._reselect_max_seconds,
            )

        ok, msg = await self._service.restart(after=_reselect)
        if not ok:
            # A corrupt cache.db can wedge startup after an unclean power-off
            # (the #1 home "reboot" is unplugging the router); drop it and retry
            # once so the watchdog self-heals a reboot-time brick instead of
            # looping on the same failure.
            await self._service.drop_cache()
            ok, msg = await self._service.restart(after=_reselect)
        return ok, msg


def _structural_key(cfg: dict[str, Any]) -> str:
    """Stable fingerprint of everything that requires a reload.

    The selector's `default` (which encodes the current server / on-off) is
    normalised out, so a pure selection change does NOT look structural and
    routes to the live Clash switch instead of a process restart.
    """
    c = copy.deepcopy(cfg)
    for ob in c.get("outbounds", []):
        if ob.get("type") == "selector":
            ob["default"] = ""
    return json.dumps(c, sort_keys=True)


def _read_disk_key(path: str | Path, keyfn: Callable[[dict[str, Any]], str]) -> str | None:
    """Apply `keyfn` to the JSON config at `path`; None if it can't be read or
    parsed (→ the caller treats the on-disk config as 'changed' and reloads).
    Used by _disk_key (structural fingerprint)."""
    try:
        return keyfn(json.loads(Path(path).read_text()))
    except (OSError, ValueError):
        return None
