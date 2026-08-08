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
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from kitewrt import divert
from kitewrt.rules import parse_singbox_rules
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
    listener is confirmed back and before the restart reports success. There is
    no kill-switch bracket around a restart any more (see
    `SingBoxService._guarded`); what makes the window safe is that the capture
    stays installed and TPROXY with no listener drops. This hook is about
    *correctness* rather than leak protection: sing-box restores the selector
    from cache_file on restart, and on the watchdog's cache-drop retry path the
    cache is gone and the selector falls back to the on-disk `default` (possibly
    a stale `direct`) — so re-assert explicitly rather than trust the restore.

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

    async def apply(self, snap: Data) -> tuple[bool, str]:
        # Refresh the bypass list before anything installs the capture: it is
        # rebuilt from this on every ensure_capture(), including the watchdog's.
        self._service.set_bypass(snap.rules_bypass_address)
        cfg = build_config(snap)
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
            if not await self._service.is_running():
                return True, ""

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
                    await self._select_after_reload(target)

                ok, msg = await self._service.restart(after=_reselect_direct)
                if not ok:
                    return False, f"restart to clear the LAN DNS black-hole failed: {msg}"
            else:
                try:
                    await self._clash.select(self._selector, "direct")
                except ClashError as exc:
                    return False, f"clash select direct: {exc}"

            if not await self._service.ensure_capture():
                return False, "LAN capture could not be installed (LAN DNS may be black-holed)"
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
            logger.warning("post-reload selector not confirmed on %r; lifting guard", target)

    def _disk_key(self) -> str | None:
        """Structural key of the config currently on disk (None if unreadable)."""
        return _read_disk_key(self._config_path, _structural_key)

    def _reload_lock(self) -> asyncio.Lock:
        """Serialises `_reload`. Built lazily because on python 3.9 an
        asyncio.Lock binds to the running loop at construction."""
        if self._reload_mutex is None:
            self._reload_mutex = asyncio.Lock()
        return self._reload_mutex

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

        # Keep the current live config as last-good, then promote atomically.
        if cfg_path.exists():
            with contextlib.suppress(OSError):
                shutil.copyfile(cfg_path, backup)
                # `copyfile` copies contents, not mode, so the backup landed
                # 0644 while the config it duplicates is deliberately 0600 —
                # and it holds the same VLESS UUIDs, trojan/hysteria passwords
                # and Reality keys. Root-owned but world-readable, on a box
                # where dnsmasq runs as `nobody`. That is a router-local
                # privilege boundary, not the LAN one the trust model waives.
                os.chmod(backup, 0o600)
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
            # the LAN recovers instead of staying dark behind a listener-less capture.
            logger.warning("reload failed (%s); restoring last-good config", msg)
            with contextlib.suppress(OSError):
                shutil.copyfile(backup, cfg_path)
            await self._service.restart(after=_reselect)

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
    ):
        self._state = state
        self._capture_sink = capture_sink
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
        """Re-assert the LAN capture. Idempotent and cheap when it's already
        right (one ruleset read), so the watchdog can just call it every tick."""
        return await self._service.ensure_capture()

    async def remove_capture(self) -> None:
        """Un-capture the LAN. The watchdog's last resort when sing-box is gone
        for good and the VPN is off — see its give-up path."""
        await self._service.remove_capture()

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
            snap = self._state.snapshot()
            if not snap.vpn_on:
                return None
            tag = active_tag(snap)
            if tag is None:
                return None
            ms = await self._clash.delay(tag, timeout_ms=_REACHABLE_TIMEOUT_MS)
            return ms is not None
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
        await reassert_selector(
            self._clash,
            self._selector,
            target,
            attempts=self._reselect_attempts,
            delay=self._reselect_delay,
            max_seconds=self._reselect_max_seconds,
        )
        return True

    async def restart(self) -> tuple[bool, str]:
        # Re-assert the intended selector in the restart's `after` hook, exactly
        # like the apply pipeline's reload does. Without it, a recovery restart
        # (especially the cache-drop path below, which wipes the cached pick)
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
