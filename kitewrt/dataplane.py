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
import contextlib
import copy
import json
import logging
import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Protocol

from kitewrt import diag, divert, killswitch, rulesets
from kitewrt.endpoints import server_addresses
from kitewrt.rules import parse_singbox_rules
from kitewrt.rulesets import ensure_present
from kitewrt.singbox.clash import ClashClient, ClashError
from kitewrt.singbox.config import (
    SELECTOR_TAG,
    active_tag,
    build_config,
    selector_default,
)
from kitewrt.singbox.service import SingBoxService, write_config
from kitewrt.state import ApplyResult, Data, State, now_iso

logger = logging.getLogger(__name__)


def _atomic_private_copy(source: Path, destination: Path) -> None:
    """Keep rollback bytes private and whole even on partial writes/ENOSPC."""
    fd, name = tempfile.mkstemp(
        prefix=destination.name + ".", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_:
            shutil.copyfileobj(input_, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)


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

    Runs as the `after` hook of `SingBoxService.restart`, i.e. after the tproxy
    listener is confirmed back and before the restart reports success. INPUT
    guards retain protection while a listener may restore a cached selector.
    The intent-aware controller releases them only after selector and capture
    readiness are verified. Re-assert explicitly rather than trusting either
    cache_file or the on-disk default, which may contain a stale `direct`.

    `max_seconds` caps the total wall-clock: the normal warmup fails *fast*
    (connection refused → quick ClashError), but a sing-box whose Clash API
    accepts the connection then hangs would otherwise let `attempts` × the
    client timeout stretch to minutes — during which the restart has not
    returned and the apply is still in flight, so the watchdog keeps deferring.
    Giving up after the cap is no less safe than exhausting `attempts`: the
    watchdog then restarts a genuinely wedged sing-box. None = no cap (the
    default, used by tests with instant fakes).
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

    def parse_rules(self, raw: bytes | str) -> dict[str, Any]: ...

    async def apply(self, snap: Data) -> tuple[bool, str]: ...

    async def ensure_materialized(self, snap: Data) -> tuple[bool, str]: ...


async def _release_ready_guards(
    state: State,
    clash: ClashClient,
    selector: str,
    capture_ready: Callable[[], Awaitable[bool]],
) -> tuple[bool, str]:
    """Exclude both managed restarts and procd launches while verifying readiness."""
    async with killswitch.readiness_lock():
        return await _release_ready_guards_locked(state, clash, selector, capture_ready)


async def _release_ready_guards_locked(
    state: State,
    clash: ClashClient,
    selector: str,
    capture_ready: Callable[[], Awaitable[bool]],
) -> tuple[bool, str]:
    for _ in range(3):
        snap = state.snapshot()
        revision = state.egress_revision
        target = active_tag(snap) if snap.vpn_on else "direct"
        try:
            selected = await clash.current(selector)
        except Exception:
            return False, "selector readiness could not be confirmed; protection retained"
        if target is None or selected != target or state.egress_revision != revision:
            return False, "VPN intent changed before readiness; protection retained"
        if not await capture_ready():
            return False, "LAN capture readiness could not be confirmed; protection retained"
        if state.egress_revision != revision:
            if state.snapshot().vpn_on:
                await killswitch.prepare_reload(divert.TPROXY_MARK)
                await killswitch.prepare_boot()
            return False, "VPN intent changed during capture readiness; protection retained"
        # A procd launch (including automatic respawn) also installs the
        # exact-mark INPUT guard. An unchanged config takes the live-select
        # path, so it must release this only after the same confirmation.
        released_input = await killswitch.release_reload(divert.TPROXY_MARK)
        if state.egress_revision != revision:
            if state.snapshot().vpn_on:
                await killswitch.prepare_reload(divert.TPROXY_MARK)
                await killswitch.prepare_boot()
            return False, "VPN intent changed during protection cleanup; retry current state"
        if released_input and await killswitch.sweep():
            if state.egress_revision == revision:
                return True, ""
            if state.snapshot().vpn_on:
                await killswitch.prepare_reload(divert.TPROXY_MARK)
                await killswitch.prepare_boot()
            return False, "VPN intent changed during protection cleanup; retry current state"
        await asyncio.sleep(0.1)
    return False, "boot protection could not be released after readiness"


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
        ruleset_dir: str | Path | None = None,
        diag_dir: str | Path | None = None,
        unusable_checks: int = 3,
        unusable_delay: float = 2.0,
        state: State | None = None,
    ):
        self._state = state
        self._operation_mutex: asyncio.Lock | None = None
        self._service = service
        self._diag_dir = diag_dir
        # See _still_unusable. Tests pass a 0 delay.
        self._unusable_checks = unusable_checks
        self._unusable_delay = unusable_delay
        self._clash = clash
        self._config_path = config_path
        # Where remote rule-sets are kept locally (kitewrt.rulesets). None keeps
        # them remote — tests, and anything that builds a config for display.
        self._ruleset_dir = ruleset_dir
        self._selector = selector_tag
        # Post-reload selector-confirm budget (~15s default: 30 attempts at
        # 0.5s), spent inside the restart's `after` hook. Generous so a cold
        # Clash API on a loaded A53 still confirms before the restart reports
        # success; tests pass a 0 delay. The 30s wall-clock cap bounds the worst
        # case (a hung-but-connected Clash API) so one apply can't sit in flight
        # for minutes with the watchdog deferring behind it.
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
        # See _reload_lock: `/test` and `/auto-select` can reload concurrently
        # with the apply pipeline, and they share config files on disk.
        self._reload_mutex: asyncio.Lock | None = None

    def parse_rules(self, raw: bytes | str) -> dict[str, Any]:
        return parse_singbox_rules(raw)

    def _operation_lock(self) -> asyncio.Lock:
        # An observation route can materialize while the apply worker is busy.
        # Serialize whole operations, including live selects and capture, not
        # only file replacement. Build from current intent after acquiring it.
        if self._operation_mutex is None:
            self._operation_mutex = asyncio.Lock()
        return self._operation_mutex

    def _current_snapshot(self, fallback: Data) -> Data:
        return self._state.snapshot() if self._state is not None else fallback

    async def apply(self, snap: Data) -> tuple[bool, str]:
        async with self._operation_lock():
            snap = self._current_snapshot(snap)
            if snap.vpn_on and getattr(self._service, "_capture_enabled", False):
                # Validation can fail before a restart ever arms its guard.
                # Protect an existing direct selector (or absent capture) first.
                async with self._service.op_lock():
                    if not await killswitch.prepare_reload(divert.TPROXY_MARK):
                        return False, "could not protect VPN-on configuration apply"
                    if (
                        await self._service.capture_state() is not True
                        and not await killswitch.prepare_boot()
                    ):
                        return False, "could not protect missing LAN capture during apply"
            return await self._apply_locked(self._current_snapshot(snap))

    async def _apply_locked(self, snap: Data) -> tuple[bool, str]:
        # Refresh the bypass list before anything installs the capture: it is
        # rebuilt from this on every ensure_capture(), including the watchdog's.
        # The rules' bypass list plus the VPN servers themselves — see
        # endpoints.server_addresses for why a device's own tunnel to one of
        # them should not ride inside ours.
        self._service.set_bypass(
            list(dict.fromkeys([*snap.rules_bypass_address, *server_addresses(snap)]))
        )
        cfg = self._build(snap)
        key = _structural_key(cfg)
        target = selector_default(snap)

        if not snap.vpn_on:
            # Off-state: keep the capture, just point the selector at `direct`.
            #
            # Tearing it down looks safer and isn't. sing-box hands out fake IPs
            # (198.18.0.0/15) with a 600 s TTL, and only sing-box can map them
            # back to a domain. Drop the capture and every client that resolved
            # anything in the last ten minutes has a cached address that now
            # routes nowhere — a guaranteed outage on every toggle-off, plus
            # those addresses leaking to the ISP. Keeping the capture means
            # "off" egresses direct through sing-box, which is what it meant
            # under the tun too.
            #
            # The risk this leaves — a crash-looping sing-box black-holing the
            # LAN with nobody watching — is handled by the watchdog, which
            # supervises whenever the capture is installed, not only when the
            # VPN is on.
            #
            # Except when sing-box is not there to keep. Then the capture is
            # not preserving anything — the fake IPs it would map back died
            # with the process — and a capture with no listener behind it
            # black-holes the whole LAN. "VPN off" must always mean "plain
            # internet": it is the one control a user has when the tunnel is
            # broken. Measured: with the active node dead and the rule-set cache
            # gone, sing-box crash-looped and this branch returned ok over a
            # fully dark LAN, which the watchdog only undid minutes later.
            if not await self._service.is_running():
                if await self._service.capture_state() is False:
                    # Nothing running, nothing captured: already a plain
                    # router (the state a previous fallback leaves). Quiet.
                    if self._state is not None and getattr(
                        self._service, "_capture_enabled", False
                    ):
                        return await self._service.stop(
                            may_release=lambda: not self._state.snapshot().vpn_on
                        )
                    return True, ""
                if await self._still_unusable():
                    return await self._fall_back_direct("sing-box is not running")

            # "Keep the capture" above is the intent, but nothing re-established
            # it: our own shutdown removes it (a live capture with no supervised
            # listener is worse than none) while sing-box, supervised by procd,
            # keeps running. Every daemon restart with the VPN off therefore
            # left the pair half-formed, and neither this branch nor the
            # watchdog put it back.
            #
            # That half-state is not "degraded", it is broken. sing-box's
            # transparent UDP sockets stay bound to the LAN resolver address
            # from earlier tproxy sessions; with the capture gone they receive
            # client DNS directly and answer nothing, so dnsmasq -- bound to the
            # same address -- never sees the query. Observed on the live router:
            # ~55 sockets on 192.168.8.1:53, every receive queue full, the whole
            # LAN unable to resolve while the dashboard stayed green.
            #
            # Re-asserting the capture does NOT clear it. Measured on a 5.4
            # kernel with a socket wedged onto the LAN resolver address:
            #
            #   wedge, no capture ............. client DNS times out
            #   wedge + capture re-asserted ... still times out
            #   wedge closed, capture up ...... resolves
            #
            # TPROXY sits in mangle/PREROUTING and looks like it should win, and
            # it does not. Only recycling the process closes those sockets --
            # hence restart() rather than ensure_capture() alone.
            #
            # The config on disk must follow the structure even with the VPN
            # off. Off-applies used to skip this entirely, so a rules change
            # (a rule-set dropped, a set's kind learned) never reached
            # config.json: an hour later the rule-set pump pruned a file the
            # stale config still named, and the next sing-box restart — the
            # watchdog's, a recycle, a reboot — was FATAL (red-team finding).
            if self._disk_key() != key:
                ok, msg = await self._reload(cfg, key, target)
                if not ok:
                    return await self._fall_back_direct(f"reload failed: {msg}")
                if not await self._service.ensure_capture():
                    return await self._fall_back_direct("LAN capture could not be installed")
                return await self._finish_off_ready()

            # Only a *definite* False recycles. `capture_state()` returns None
            # when it could not read the ruleset at all, which happens whenever
            # another writer holds the xtables lock past our `-w 5` — someone
            # else's fw3 reload would otherwise cost a sing-box restart.
            if await self._service.capture_state() is False:
                logger.warning(
                    "sing-box is running with no LAN capture; restarting it to "
                    "clear the stale transparent sockets that black-hole LAN DNS"
                )

                # `after=`, like every other restart site in this file. sing-box's
                # init script returns as soon as procd has forked it, well before
                # the Clash API accepts connections (measured at 0.2 s on an idle
                # x86 VM with one outbound, and this router has 23 plus rule-sets).
                # A bare select here raced that and always lost, which aborted the
                # apply *before* it could install the capture -- the repair never
                # ran, and toggling the VPN off left the selector on the proxy
                # server with the LAN still tunnelled.
                async def _reselect_direct() -> None:
                    await self._select_latest_after_reload(cfg, target)

                ok, msg = await self._service.restart(after=_reselect_direct)
                if not ok:
                    return await self._fall_back_direct(
                        f"restart to clear the LAN DNS black-hole failed: {msg}"
                    )
            else:
                try:
                    await self._clash.select(self._selector, "direct")
                except ClashError as exc:
                    # A process whose control plane does not answer is the
                    # crash-loop case (procd's pidfile can name a process that
                    # is about to FATAL) or a wedge — or just mid-restart, so
                    # look again before giving it up.
                    if await self._still_unusable():
                        return await self._fall_back_direct(f"clash select direct: {exc}")
                    try:
                        await self._clash.select(self._selector, "direct")
                    except ClashError as exc2:
                        return await self._fall_back_direct(f"clash select direct: {exc2}")

            if not await self._service.ensure_capture():
                return await self._fall_back_direct("LAN capture could not be installed")
            return await self._finish_off_ready()

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
            # _reload re-asserts the selector to `target` in the restart's
            # `after` hook (a reload restores the selector from cache_file,
            # which can be a stale `direct`; re-asserting before the restart
            # reports success keeps the VPN from coming back up routing direct).
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

        # Assert the capture on EVERY vpn-on apply, not just when we restarted
        # sing-box. Nothing else installs it: on a reboot procd starts sing-box
        # and then the daemon, the config is unchanged, so no reload happens and
        # the branch above never runs — the VPN would come up looking healthy
        # with every LAN packet going straight out the WAN. It also heals a
        # capture that `/etc/init.d/firewall restart` flushed. On fw3 a restart
        # rebuilds the whole mangle table and takes our chain with it; a plain
        # `reload` leaves us alone. On fw4 neither does — it rebuilds only
        # `table inet fw4`, and our chain lives in `table ip mangle`. Both
        # measured; see docs/openwrt-notes.md.
        #
        # ensure_capture() is idempotent and skips the work when the live rules
        # already match, so this costs one ruleset read in the common case.
        if not await self._service.ensure_capture():
            # Fail loudly. Silently continuing means "VPN on" in the UI while
            # the LAN egresses unproxied — the exact failure this tool exists
            # to prevent, and invisible without an error to surface.
            return False, "LAN capture could not be installed (traffic is NOT being proxied)"
        return await self._finish_ready()

    async def _finish_ready(self) -> tuple[bool, str]:
        if self._state is None:
            return True, ""
        async with self._service.op_lock():
            return await _release_ready_guards(
                self._state, self._clash, self._selector, self._service.ensure_capture
            )

    async def _finish_off_ready(self) -> tuple[bool, str]:
        ok, msg = await self._finish_ready()
        if ok:
            return True, ""
        return await self._fall_back_direct(f"off-state readiness failed: {msg}")

    def _build(self, snap: Data) -> dict[str, Any]:
        """The config for `snap`, with remote rule-sets made local — and their
        files guaranteed to exist, since a missing local file is as fatal at
        startup as the failed download it replaces."""
        if self._ruleset_dir is None:
            return build_config(snap)
        ensure_present(snap.rule_sets, self._ruleset_dir)
        return build_config(
            snap,
            ruleset_dir=self._ruleset_dir,
            ruleset_kinds=rulesets.kinds(snap.rule_sets, self._ruleset_dir),
        )

    async def _still_unusable(self) -> bool:
        """Is sing-box really down, or caught mid-restart?

        A single failed reading used to be enough to stop it. But the watchdog
        restarts sing-box on its own schedule, and an off-apply landing in that
        window saw a pid with no Clash API yet — so it stopped a process that
        was seconds from healthy, and stranded every fake IP a client held
        (red-team finding). Wait out any in-flight operation, then require
        three bad readings in a row."""
        async with self._service.op_lock():
            pass
        for attempt in range(self._unusable_checks):
            if await self._service.is_running() and await self._clash.healthy():
                return False
            if attempt + 1 < self._unusable_checks:
                await asyncio.sleep(self._unusable_delay)
        return True

    async def _fall_back_direct(self, reason: str) -> tuple[bool, str]:
        """VPN off and sing-box cannot carry the LAN: become a plain router.

        `service.stop()` removes the capture *first*, then stops the process so
        procd stops respawning it. Leaving it to respawn would bring back the
        other half-state — a listener with no capture — whose stale transparent
        sockets swallow LAN DNS (see the black-hole notes above). The next
        vpn-on apply finds it not running and starts it again.

        Reported as a failure (ok=False) under its own message, which the
        dashboard titles "VPN off — running without sing-box": the user asked
        for "off" and has internet, but the data plane is broken and turning
        the VPN back on may fail. The snapshot is taken *after* the LAN is
        released — it can take seconds, and the LAN was dark while it did.
        """
        if self._state is not None and self._state.snapshot().vpn_on:
            return False, "VPN intent changed during off-state recovery; capture preserved"
        logger.error("VPN off and sing-box unusable (%s); running the LAN direct", reason)
        if self._state is not None:
            stopped, stop_msg = await self._service.stop(
                may_release=lambda: not self._state.snapshot().vpn_on
            )
            if not stopped:
                return False, f"off-state recovery did not release traffic: {stop_msg}"
        else:
            await self._service.stop()
        if self._diag_dir is not None:
            await diag.snapshot(self._diag_dir, f"VPN off, running direct: {reason}")
        return False, f"{FALLBACK_DIRECT_MSG} ({reason})"

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
        async with self._operation_lock():
            return await self._materialize_locked(self._current_snapshot(snap))

    async def _materialize_locked(self, snap: Data) -> tuple[bool, str]:
        # is_running may await a control request while a user changes settings.
        # The supplied route snapshot is not authoritative after that await.
        running = await self._service.is_running()
        snap = self._current_snapshot(snap)
        cfg = self._build(snap)
        key = _structural_key(cfg)
        if running and self._disk_key() == key:
            return True, ""  # running config already has every outbound
        # _reload re-asserts the selector (selector_default) in the restart's
        # `after` hook.
        ok, msg = await self._reload(cfg, key, selector_default(snap))
        if not ok:
            return False, msg
        # A fresh restart registers the selector (and answers /version) a beat
        # before every per-server outbound appears in the proxy table, so a
        # delay-test fired right now would 404 on nodes that aren't ready yet.
        # Wait for them to register before returning to the caller.
        await self._await_outbounds_ready(cfg)
        if self._state is not None and not self._state.snapshot().vpn_on:
            return await self._finish_off_ready()
        return await self._finish_ready()

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
        """Re-assert the selector to `target` after a reload, from the restart's
        `after` hook. Gives up only after the full budget (sing-box is then
        likely wedged; the watchdog takes over)."""
        if not await reassert_selector(
            self._clash,
            self._selector,
            target,
            attempts=self._reselect_attempts,
            delay=self._reselect_delay,
            max_seconds=self._reselect_max_seconds,
        ):
            raise RuntimeError(f"post-reload selector not confirmed on {target!r}")

    def _current_reload_target(self, cfg: dict[str, Any], fallback: str) -> str:
        if self._state is None:
            return fallback
        snap = self._state.snapshot()
        target = active_tag(snap) if snap.vpn_on else "direct"
        selector = next(
            (ob for ob in cfg.get("outbounds", []) if ob.get("tag") == self._selector), {}
        )
        if target is None or target not in selector.get("outbounds", []):
            raise RuntimeError("VPN intent changed; intended node is absent from running config")
        return target

    async def _select_latest_after_reload(self, cfg: dict[str, Any], fallback: str) -> None:
        # Intent may change while procd starts the listener or Clash confirms a
        # selection. Never finish an old off-state observation with direct after
        # a newer on intent; validate against the config this restart loaded.
        for _ in range(3):
            revision = self._state.egress_revision if self._state is not None else None
            target = self._current_reload_target(cfg, fallback)
            await self._select_after_reload(target)
            if self._state is None or (
                self._state.egress_revision == revision
                and self._current_reload_target(cfg, fallback) == target
            ):
                return
        raise RuntimeError("VPN intent kept changing during selector confirmation")

    def _disk_key(self) -> str | None:
        """Structural key of the config currently on disk (None if unreadable)."""
        return _read_disk_key(self._config_path, _structural_key)

    def _reload_lock(self) -> asyncio.Lock:
        """Serialises `_reload`. Built lazily because on python 3.9 an
        asyncio.Lock binds to the running loop at construction."""
        if self._reload_mutex is None:
            self._reload_mutex = asyncio.Lock()
        return self._reload_mutex

    async def _rollback_target(self, backup: Path, desired: str | None = None) -> str:
        """Recover the previous intended proxy, never invent a node or use direct."""
        try:
            cfg = json.loads(backup.read_text())
            outbounds = cfg["outbounds"]
            selector = next(
                ob
                for ob in outbounds
                if ob.get("type") == "selector" and ob.get("tag") == self._selector
            )
            members = selector["outbounds"]
            if not isinstance(members, list) or not all(isinstance(tag, str) for tag in members):
                raise ValueError("invalid previous selector members")
            # Concrete proxy outbounds only: a selector or direct alias is not
            # evidence that a previously chosen target preserves VPN-on intent.
            proxies = {
                ob["tag"]
                for ob in outbounds
                if isinstance(ob.get("tag"), str)
                and ob.get("type") not in (None, "selector", "urltest", "direct", "block", "dns")
                and ob["tag"] in members
            }
        except (ValueError, KeyError, TypeError, AttributeError, StopIteration) as exc:
            raise ValueError("previous config has no safe rollback selector") from exc
        try:
            current = await self._clash.current(self._selector)
        except Exception:
            current = None
        if current in proxies:
            return current
        default = selector.get("default")
        if isinstance(default, str) and default in proxies:
            return default
        # A normal off -> on transition can have direct as both old values.
        # The explicit requested target is safe if the restored config already
        # contains it; unlike picking its first member, this preserves intent.
        if desired is not None and desired in proxies:
            return desired
        raise ValueError("previous config has no confirmed proxy rollback target")

    async def _reload(self, cfg: dict[str, Any], key: str, target: str) -> tuple[bool, str]:
        """Serialising wrapper — see `_reload_locked` for what it does.

        Reachable from two places that do not know about each other: the apply
        pipeline (which serialises itself) and `ensure_materialized`, called
        straight from the `/test` and `/auto-select` routes with no `applying`
        flag and no queue. Two concurrent reloads write the same staging and
        last-good paths and restart the same process — so a click on "test"
        during an apply could promote a half-written config, and the rollback
        would restore the wrong last-good.
        """
        async with self._reload_lock():
            if self._state is not None:
                current = self._state.snapshot()
                cfg = self._build(current)
                key = _structural_key(cfg)
                target = selector_default(current)
            return await self._reload_locked(cfg, key, target)

    async def _reload_locked(self, cfg: dict[str, Any], key: str, target: str) -> tuple[bool, str]:
        """Stage → validate → promote → restart, with rollback.

        A config sing-box rejects must NEVER replace the running one: a bad
        rules/DNS edit would otherwise fail-close the whole LAN (the capture
        drops captured traffic) with no way back. So we validate a staged copy
        with `sing-box check` first, and keep the previous config as last-good to
        restore if a *promoted* config still fails to come up.

        The selector is re-asserted to `target` via the restart's `after` hook,
        so the restart does not report success while sing-box is still on
        whatever it restored from cache_file. The capture stays installed for
        the whole restart, so the window drops rather than leaks — which is why
        no kill-switch bracket is needed here (see `SingBoxService._guarded`).
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

        if self._state is not None:
            current = self._build(self._state.snapshot())
            if _structural_key(current) != key:
                staging.unlink(missing_ok=True)
                return False, "settings changed during config validation; retry with current state"
            try:
                target = self._current_reload_target(cfg, target)
            except RuntimeError as exc:
                staging.unlink(missing_ok=True)
                return False, str(exc)

        # Never risk replacing the live config without a complete private
        # rollback copy. A failed copy must leave the previous backup untouched.
        backup_ready = False
        rollback_target: str | None = "direct"
        if cfg_path.exists():
            try:
                _atomic_private_copy(cfg_path, backup)
                backup_ready = True
                if target != "direct":
                    try:
                        rollback_target = await self._rollback_target(backup, target)
                    except ValueError:
                        # An old off config may not contain a newly added node.
                        # The candidate can still repair it: launch guards make
                        # failure safe even when no old proxy can be restarted.
                        rollback_target = None
            except OSError as exc:
                staging.unlink(missing_ok=True)
                self._last_key = None
                return False, f"backup config failed: {exc}"
        # Reading the previous selector can itself await the controller. A
        # newer structural intent must not be overwritten after that wait.
        if self._state is not None and _structural_key(self._build(self._state.snapshot())) != key:
            staging.unlink(missing_ok=True)
            return False, "settings changed while preparing rollback; retry current state"
        try:
            staging.replace(cfg_path)
        except OSError as exc:
            self._last_key = None
            return False, f"promote config failed: {exc}"

        async def _reselect() -> None:
            await self._select_latest_after_reload(cfg, target)

        ok, msg = await self._service.restart(after=_reselect)
        if not ok:
            # A corrupt cache.db (unclean power-off mid-write) can wedge startup:
            # retry once without it. Quarantined, not deleted — the cache is what
            # lets sing-box start without downloading its rule-sets, so losing
            # it when it was not the cause makes every later start (including
            # the last-good rollback below) depend on the network.
            ok, msg = await self._service.restart_without_cache(after=_reselect)
        if not ok and backup_ready:
            # The promoted config won't come up: restore last-good and restart so
            # the LAN recovers instead of staying dark behind a listener-less capture.
            logger.warning("reload failed (%s); restoring last-good config", msg)
            try:
                _atomic_private_copy(backup, cfg_path)
            except OSError as exc:
                self._last_key = None
                return False, f"rollback config failed: {exc}"

            try:
                restored_cfg = json.loads(cfg_path.read_text())
            except (OSError, ValueError):
                restored_cfg = {}
            if (
                rollback_target is None
                and self._state is not None
                and not self._state.snapshot().vpn_on
            ):
                # Explicit off arriving during the failed candidate authorizes
                # direct, but only if that old config actually has the member.
                outbounds = (
                    restored_cfg.get("outbounds", []) if isinstance(restored_cfg, dict) else []
                )
                if not isinstance(outbounds, list):
                    outbounds = []
                if any(
                    isinstance(ob, dict)
                    and ob.get("type") == "selector"
                    and ob.get("tag") == self._selector
                    and isinstance(ob.get("outbounds"), list)
                    and "direct" in ob["outbounds"]
                    for ob in outbounds
                ):
                    rollback_target = "direct"
            if rollback_target is None:
                stopped, stop_msg = await self._service.stop_protected()
                self._last_key = None
                detail = "previous config restored; no safe proxy rollback target; protected stop"
                if not stopped:
                    detail += f" failed: {stop_msg}"
                return False, f"sing-box: {msg}; {detail}"

            async def _restore_select() -> None:
                await self._select_latest_after_reload(restored_cfg, rollback_target)

            restored, restore_msg = await self._service.restart(after=_restore_select)
            if restored and self._state is not None:
                restored, restore_msg = await self._finish_ready()
            if not restored:
                msg = f"{msg}; rollback service failed: {restore_msg}"

        self._last_key = key if ok else None
        return ok, ("" if ok else f"sing-box: {msg}")


# Bound on the watchdog's active-node exit probe. Generous (this isn't the
# latency-sensitive autoselect path) so a merely-slow-but-working node isn't
# flagged unreachable; the two-tick debounce in the watchdog covers transients.
_REACHABLE_TIMEOUT_MS = 4000

# The exact banner the watchdog raises for a lost capture. A constant because
# the clear path matches on it: anything else in `last_error` is a real apply
# error and must not be wiped.
_CAPTURE_LOST_MSG = "LAN capture was lost and could not be restored (traffic is NOT being proxied)"

# The self-healed case, which is a *different* event and deserves its own
# wording. Reusing the message above said "could not be restored" about a
# capture that had just been restored, and cost two durable writes (the raise
# and the immediate clear) for one gap.
_CAPTURE_GAP_MSG = "LAN capture was lost and restored — traffic was briefly unproxied"


# Data-plane faults the watchdog raises on its own, outside any apply. Before
# these existed a crash-looping sing-box or a dead active node wrote nothing to
# `last_error`: after the outage that motivated them, `state.json` read
# `last_apply.ok: true` with an empty error over a LAN that had been dark.
# Matched verbatim by web/src/health.ts (pinned by a test, like the two above).
_SINGBOX_DOWN_MSG = (
    "sing-box is down and could not be restarted — the LAN has no internet "
    "while the VPN is on (turning the VPN off restores direct internet)"
)
_NODE_UNREACHABLE_MSG = (
    "The active server is unreachable — sing-box is up but traffic is not "
    "leaving; pick another server"
)
# What a VPN-off apply reports when it had to run the LAN without sing-box.
# Prefix-matched by web/src/health.ts (the reason follows in parentheses).
FALLBACK_DIRECT_MSG = "VPN is off and sing-box is not working — the LAN runs direct without it"

_FAULT_MSGS = {"singbox_down": _SINGBOX_DOWN_MSG, "node_unreachable": _NODE_UNREACHABLE_MSG}


# How far ahead of us a stored timestamp must be to read as a wrong clock
# rather than an apply that landed while we were writing. An hour is far past
# any plausible in-flight apply and far short of the years a stuck RTC gives.
_CLOCK_SKEW_S = 3600


def _skew_horizon(now: str) -> str:
    from datetime import datetime, timedelta, timezone

    try:
        parsed = datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return now
    return (parsed + timedelta(seconds=_CLOCK_SKEW_S)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _may_overwrite(d: Data, since: str, now: str) -> bool:
    """May the watchdog's capture banner replace `d.last_apply`?

    Not while an apply is in flight, and not if one recorded a result after
    this tick began — its message is the one the user just asked for.

    The future-timestamp escape matters on a router: there is no RTC,
    `sysfixtime` restores the clock from a file mtime at boot, and `now_iso()`
    is second-precision. A stored timestamp from the future would otherwise
    suppress the banner permanently, which is the outage this reports. But it
    has to mean "the clock was wrong", not "landed a second after we sampled
    `now`" — `now` is read before `update()` takes the state lock and fsyncs,
    so a real apply can legitimately land just after it, and treating that as
    stale would clobber the message the user is waiting for.
    """
    if d.applying:
        return False
    if d.last_apply is None:
        return True
    return d.last_apply.at < since or d.last_apply.at > _skew_horizon(now)


class SingBoxWatchdogDeps:
    """Watchdog deps for the sing-box plane: a process that's alive but whose
    Clash API is unresponsive counts as down, so a wedged sing-box (tproxy
    listener still bound, control plane stuck) gets recovered too — not just an
    outright crash."""

    def __init__(
        self,
        state: State,
        service: SingBoxService,
        clash: ClashClient,
        *,
        capture_sink: Callable[[bool | None], None] | None = None,
        selector_tag: str = SELECTOR_TAG,
        reselect_attempts: int = 30,
        reselect_delay: float = 0.5,
        reselect_max_seconds: float = 30.0,
        diag_dir: str | Path | None = None,
        config_path: str | Path | None = None,
    ):
        self._config_path = Path(config_path) if config_path is not None else None
        self._state = state
        self._capture_sink = capture_sink
        self._diag_dir = diag_dir
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

    async def ensure_capture(self) -> bool:
        """Observe selector, restore capture and release guards as one operation."""
        if getattr(self._service, "_capture_enabled", False):
            async with self._service.op_lock():
                return await self._ensure_capture_locked()
        return await self._ensure_capture_locked()

    async def _ensure_capture_locked(self) -> bool:
        snap = self._state.snapshot()
        if snap.vpn_on:
            revision = getattr(self._state, "egress_revision", 0)
            target = active_tag(snap)
            if target is None:
                return False
            try:
                selected = await self._clash.current(self._selector)
            except Exception:
                return False
            if (
                selected != target
                or getattr(self._state, "egress_revision", 0) != revision
                or not self._state.snapshot().vpn_on
            ):
                return False
        if not getattr(self._service, "_capture_enabled", False):
            return await self._service.ensure_capture()
        ready, _message = await _release_ready_guards(
            self._state, self._clash, self._selector, self._service.ensure_capture
        )
        return ready

    async def remove_capture(self) -> None:
        """Un-capture the LAN. The watchdog's last resort when sing-box is gone
        for good and the VPN is off — see its give-up path.

        Stops sing-box too (capture first, then the process). Removing only the
        capture left procd respawning a crash-looping sing-box, and the first
        respawn that did come up sat on the LAN resolver address with no
        capture — the DNS black-hole half-state."""
        if self._state.snapshot().vpn_on:
            return
        if getattr(self._service, "_capture_enabled", False):
            await self._service.stop(may_release=lambda: not self._state.snapshot().vpn_on)
        else:
            await self._service.stop()

    async def report_capture_lost(self, since: str) -> bool:
        """Put a lost capture on the dashboard.

        `last_apply`/`last_error` is the UI's error channel and this is exactly
        the class of thing it exists for: the LAN is not being proxied. The
        watchdog path used to only write a log line, so the realistic failure
        (a `firewall restart` flushed mangle, re-install then failed) left a
        green "Connected" over a fully unproxied LAN.

        `since` is when the watchdog's tick began. An apply can start and
        finish inside the ~15s `ensure_capture` spends waiting for a listener,
        and its message — "sing-box rejected the config: bad TLS server_name
        on 'nl-1'" — is the one the user just asked for. Anything recorded
        after `since` therefore wins, and this write is dropped.

        **Returns whether the write landed**, so the caller only latches its
        edge trigger on success. Latching regardless meant a dropped write
        silenced the banner for the whole episode — and `now_iso()` is
        second-precision, so an apply that finished *before* the tick, in the
        same second, dropped it. That restored the green-dashboard-over-an-
        unproxied-LAN failure this whole path exists to prevent.
        """
        now = now_iso()
        if not _may_overwrite(self._state.snapshot(), since, now):
            # Checked before `update()`, which fsyncs the file *and* the
            # directory unconditionally — so a guard that only lived inside
            # `mutate` burned a durable write on every 30s tick for as long as
            # the condition held, while showing the user nothing.
            return False

        result = ApplyResult(at=now, ok=False, msg=_CAPTURE_LOST_MSG)
        wrote = False

        def mutate(d: Data) -> None:
            nonlocal wrote
            if not _may_overwrite(d, since, now):
                return  # a real apply landed during our tick; leave its message
            d.last_apply = result
            d.last_error = _CAPTURE_LOST_MSG
            wrote = True

        await self._state.update(mutate)
        return wrote

    async def report_fault(self, since: str, kind: str) -> bool:
        """Put a watchdog-detected data-plane fault on the dashboard.

        Same channel, guards and return contract as `report_capture_lost`: it
        never overwrites a result an apply recorded after `since`, and it
        returns whether the write landed so the caller latches only on success.
        """
        msg = _FAULT_MSGS[kind]
        now = now_iso()
        snap = self._state.snapshot()
        if snap.last_error == msg:
            # Already up: no write. This is what lets the watchdog call it on
            # every failing tick (so a banner an apply wiped comes back) without
            # an fsync every 30 s.
            return True
        if not _may_overwrite(snap, since, now):
            return False
        wrote = False
        fresh: list[bool] = []  # set when this call raised it (vs. already up)

        def mutate(d: Data) -> None:
            nonlocal wrote
            if not _may_overwrite(d, since, now):
                return
            if d.last_error == msg:
                wrote = True  # already up (e.g. raised before a daemon restart)
                return
            d.last_apply = ApplyResult(at=now, ok=False, msg=msg)
            d.last_error = msg
            wrote = True
            fresh.append(True)

        await self._state.update(mutate)
        if fresh and self._diag_dir is not None:
            # Once per episode: the evidence is in RAM-only logs right now.
            await diag.snapshot(
                self._diag_dir,
                f"watchdog: {kind}",
                state=snap,
                clash=self._clash,
                selector=self._selector,
            )
        return wrote

    async def clear_fault(self, kind: str) -> None:
        """Clear a fault `report_fault` raised — and only that message, so a real
        apply error that landed in between is never wiped. A no-op write-free
        read when it is not up, so calling it on every healthy tick is cheap."""
        msg = _FAULT_MSGS[kind]
        if self._state.snapshot().last_error != msg:
            return

        def mutate(d: Data) -> None:
            if d.last_error != msg:
                return
            d.last_error = ""
            d.last_apply = ApplyResult(
                at=now_iso(), ok=True, msg="recovered: " + msg.split(" — ")[0]
            )

        await self._state.update(mutate)

    async def report_capture_gap(self, since: str) -> None:
        """Record a capture gap that the tick already healed.

        `/etc/init.d/firewall restart` flushes mangle and takes the capture with
        it; the next tick puts it back. Measured on a real kernel with a sniffer
        on the WAN, that window was 4-21 s of forwarded plaintext and — the part
        with no visible symptom — every LAN DNS query going to the ISP resolver
        in the clear. It has to leave a mark even though the VPN is working
        again by the time anyone looks.

        `ok=True`, deliberately: a red "failed" banner over a now-healthy VPN is
        what `report_capture_restored` exists to remove. This is a note about
        the past, not a current fault.
        """
        now = now_iso()
        if not _may_overwrite(self._state.snapshot(), since, now):
            return  # a real apply landed during our tick; leave its message

        def mutate(d: Data) -> None:
            if not _may_overwrite(d, since, now):
                return
            d.last_apply = ApplyResult(at=now, ok=True, msg=_CAPTURE_GAP_MSG)

        await self._state.update(mutate)

    async def report_capture_restored(self) -> None:
        """Clear the banner `report_capture_lost` raised, and nothing else.

        The watchdog's own recovery is not an apply, so without this the
        message survived until the *user* triggered one — meaning the very
        scenario this exists for (one tick fails after a `firewall restart`,
        the next succeeds) left a permanent red "traffic is NOT being proxied"
        over a fully working VPN. Guarded on the exact message so a real apply
        error that landed in between is never silently wiped.
        """

        def mutate(d: Data) -> None:
            if d.last_error != _CAPTURE_LOST_MSG:
                return
            d.last_error = ""
            d.last_apply = ApplyResult(at=now_iso(), ok=True, msg="LAN capture restored")

        await self._state.update(mutate)

    async def capture_installed(self) -> bool | None:
        """Whether the LAN is currently captured — True / False / **None** for
        "could not tell" (the xtables lock was held past our wait).

        The watchdog needs this to decide whether sing-box is worth
        supervising while the VPN is off: with a capture up and no listener
        behind it, TPROXY black-holes every LAN TCP connection. It now also
        decides whether to *recycle* sing-box, which is destructive, so the
        unknown case stays distinct instead of collapsing into False.
        """
        return await divert.installed_state()

    def record_capture_state(self, state: bool | None) -> None:
        """Publish what the tick just observed, so the UI can tell "the VPN is
        on" from "traffic is actually being captured".

        Those are different facts and the difference is the failure class this
        project keeps finding: a `firewall restart` flushes the capture and the
        LAN egresses in the clear while the dashboard still says Connected. The
        watchdog is already the only thing that probes this, so routing its
        answer here costs nothing — probing again in the metrics pump would be a
        fork per second, competing for the xtables lock.
        """
        if self._capture_sink is not None:
            self._capture_sink(state)

    async def process_alive(self) -> bool:
        """Whether the sing-box process exists at all.

        Deliberately NOT `is_running()`, which also requires a healthy Clash
        API. A sing-box wedged badly enough to sit on the LAN resolver port and
        answer nothing is exactly the one whose API stops responding, so the
        stricter probe would skip the branch in the worst case it exists for.
        """
        return await self._service.is_running()

    async def active_reachable(self) -> bool | None:
        """Delay-probe the active node's real exit path (same Clash mechanism as
        autoselect) so the watchdog can tell a dead-but-process-healthy node from
        a working one.

        None when there's nothing to probe (vpn off / no active server). Never
        raises: a controller hiccup reads as None ("can't tell"), not a failure,
        so it won't trip a false unreachable warning.
        """
        try:
            revision = getattr(self._state, "egress_revision", 0)
            snap = self._state.snapshot()
            if not snap.vpn_on or snap.applying:
                return None
            tag = active_tag(snap)
            if tag is None:
                return None
            result = await self._clash.probe_delay(tag, timeout_ms=_REACHABLE_TIMEOUT_MS)
            current = self._state.snapshot()
            # A selection/apply that landed while the request was in flight
            # makes this result about a previous intent, not the current node.
            if (
                getattr(self._state, "egress_revision", 0) != revision
                or current.applying
                or not current.vpn_on
                or current.active_server != snap.active_server
                or current.last_apply != snap.last_apply
            ):
                return None
            return result.reachable
        except Exception:
            logger.debug("active_reachable probe errored", exc_info=True)
            return None

    async def resync_selector(self) -> bool | None:
        """Make sing-box's selector agree with the user's intent. True if it had
        to be corrected, False if it already agreed, None if it could not be read.

        Nothing checked this, and the gap is the project's defining failure in
        its purest form. Measured on a stock 23.05 router: with `vpn_on` true, a
        healthy process and the capture installed, the selector sat on `direct`
        for 75 s across more than two watchdog ticks — every LAN packet leaving
        via the ISP — while `/api/state` reported `vpn_on: true` and
        `last_apply.ok: true`, and `/api/exit-ip` returned the user's own ISP
        address *next to* `vpn_on: true`. The capture was installed the whole
        time, so every existing check was satisfied: they all ask whether
        traffic is diverted into sing-box, and none asks where sing-box then
        sends it.

        The realistic trigger is a restart whose `after=` hook never ran —
        `SingBoxService._guarded` skips it when the tproxy listener does not
        appear inside its timeout, which is exactly what a slow first start on
        23.05/24.10 looks like. sing-box then restores the selector from
        `cache_file`, which holds `direct` whenever the VPN was last off. But
        the point of checking the *state* rather than patching that path is that
        it heals every cause, including the ones nobody has thought of.
        """
        target = selector_default(self._state.snapshot())
        try:
            now = await self._clash.current(self._selector)
        except ClashError:
            logger.debug("selector read failed", exc_info=True)
            return None
        if now == target:
            return False
        logger.warning(
            "sing-box selector is %r but should be %r; re-asserting "
            "(traffic was not going where the dashboard says)",
            now,
            target,
        )
        if getattr(
            self._service, "_capture_enabled", False
        ) and not await killswitch.prepare_reload(divert.TPROXY_MARK):
            return None
        try:
            await self._reselect_latest()
        except Exception:
            logger.warning("current selector intent could not be confirmed", exc_info=True)
            return None
        return True

    async def _reselect_latest(self) -> None:
        for _ in range(3):
            revision = self._state.egress_revision
            snap = self._state.snapshot()
            target = active_tag(snap) if snap.vpn_on else "direct"
            if target is None:
                raise RuntimeError("VPN is on without a current intended node")
            if self._config_path is not None:
                try:
                    cfg = json.loads(self._config_path.read_text())
                    selector = next(
                        ob for ob in cfg["outbounds"] if ob.get("tag") == self._selector
                    )
                    if target not in selector.get("outbounds", []):
                        raise ValueError("intended node missing")
                except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
                    raise RuntimeError(
                        "current intended node is absent from running config"
                    ) from exc
            confirmed = await reassert_selector(
                self._clash,
                self._selector,
                target,
                attempts=self._reselect_attempts,
                delay=self._reselect_delay,
                max_seconds=self._reselect_max_seconds,
            )
            if not confirmed:
                raise RuntimeError(f"post-restart selector not confirmed on {target!r}")
            if self._state.egress_revision == revision:
                return
        raise RuntimeError("VPN intent kept changing during watchdog selector confirmation")

    async def restart(self) -> tuple[bool, str]:
        # Re-assert the intended selector in the restart's `after` hook, exactly
        # like the apply pipeline's reload does. Without it, a recovery restart
        # (especially the cache-drop path below, which wipes the cached pick)
        # would come up on whatever the on-disk `selector.default` holds —
        # possibly a stale `direct`, silently routing vpn-on LAN traffic
        # unproxied during the very window the watchdog is meant to heal.
        async def _reselect() -> None:
            await self._reselect_latest()

        ok, msg = await self._service.restart(after=_reselect)
        if not ok:
            # A corrupt cache.db can wedge startup after an unclean power-off
            # (the #1 home "reboot" is unplugging the router): retry once without
            # it. `restart_without_cache` puts it back if that does not help,
            # which is the difference between a dead node being an outage until
            # it returns and an outage for good — see its docstring.
            ok, msg = await self._service.restart_without_cache(after=_reselect)
        if (
            ok
            and getattr(self._service, "_capture_enabled", False)
            and not await self.ensure_capture()
        ):
            return False, "capture/selector readiness failed after watchdog restart"
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
