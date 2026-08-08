"""Persistent state of the kitewrt daemon.

Single JSON file under the daemon's data directory. Durable atomic writes
(write-temp → fsync → rename → dir-fsync, mode 0o600) so neither a crash nor an
unclean power-off can corrupt or zero out saved state. Older schema versions are
migrated forward where safe (see `_migrate`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError

from kitewrt.vless import Server

logger = logging.getLogger(__name__)

# v2: multi-subscription support (each subscription becomes its own UI card).
# v3: data plane moved to sing-box — DNS lives in the sing-box config (no
#     router-DoH round-trip). dns.direct_dns + dns.doh_url are the two
#     user-editable resolvers (both default Cloudflare). All fields have
#     defaults, so an older on-disk file still loads.
# Older files are migrated forward where safe: pydantic defaults new fields and
# ignores removed ones, so a forward-compatible file (e.g. v2) keeps its
# subscriptions/credentials/DNS across a bump. Only a genuinely incompatible
# shape (the v1 tell: vpn_on with no servers) resets to defaults. See _migrate.
SCHEMA_VERSION = 3

# How many rules-document warnings to keep. They are persisted and sent whole in
# every state response, so an unbounded list is a permanent multi-megabyte
# payload — measured at 2.7 MB from one 20,000-rule document. `rules_skipped_count`
# carries the number; these are a sample of the reasons.
_MAX_WARNINGS = 25


class Subscription(BaseModel):
    """One source of VLESS servers.

    Source may be an HTTP(S) URL (which kitewrt fetches), or a literal
    `vless://...` URI (parsed inline; refresh is a no-op).
    """

    id: str
    label: str
    source: str
    fetched_at: str
    servers: list[Server] = Field(default_factory=list)


class ActiveServerRef(BaseModel):
    """Pointer to one server inside one subscription.

    Composite key because two subscriptions can in principle contain the same
    host:port — making this composite also means deleting a subscription
    cleanly resets the active server when the active selection was inside it.
    """

    subscription_id: str
    server_id: str


class ApplyResult(BaseModel):
    """Outcome of the most recent sing-box apply cycle.

    Persisted so the UI can show a non-transient status — earlier we wiped
    `last_error` on the next successful apply, which made transient failures
    invisible if the user kept clicking.
    """

    at: str
    ok: bool
    msg: str


# DoH endpoint for foreign domains AND the proxy/VPN server-domain bootstrap
# (`dns-bootstrap`). IP-literal on purpose: the bootstrap dials it to resolve
# server *domains*, so a hostname here would itself need resolving (a loop); an
# IP needs none and, queried numerically, dodges SNI-based blocking.
DEFAULT_DOH_URL = "https://1.1.1.1/dns-query"
# Universal default for the direct resolver — Cloudflare plain-UDP. Serves only
# DIRECT/regional domains (set it to a regional resolver in the UI if you rely
# on region-specific GeoDNS); foreign VPN endpoints are bootstrapped over the
# encrypted DoH above, not this.
DEFAULT_DIRECT_DNS = "1.1.1.1"


class PingResult(BaseModel):
    """Latest delay-test result for a single server.

    Named "ping" for the UI badge, but it is not an ICMP or TCP ping: it is the
    proxy delay-test in `autoselect.rank_by_delay` — sing-box dials the server's
    outbound and times an HTTP-204 round-trip. Both "Test" and "⚡ Fastest"
    write here.

    `ms` is None when the probe timed out or the connect failed — the UI
    renders that as "down". `at` lets the UI show when the measurement
    was taken (results don't auto-expire; they stay until re-tested).
    """

    ms: int | None
    at: str


class DnsState(BaseModel):
    """DNS configuration for the two user-editable upstreams (sing-box also runs
    internal fake-IP and router-local resolvers — see singbox/dns.py). Both
    default to Cloudflare.

    `doh_url` — the DoH endpoint for PROXY-routed (foreign) domains (resolved
    over the proxy detour so the ISP never sees them) AND for the proxy/VPN
    server-domain bootstrap (`dns-bootstrap`, dialed over `direct`). Use an
    IP-literal DoH (`https://1.1.1.1/dns-query`): the bootstrap resolves server
    *domains*, so a hostname host would itself need resolving (a loop).

    `direct_dns` — a plain-UDP resolver IP for DIRECT-routed (home/regional)
    domains only. sing-box dials it on its own outbound; no mark exclusion is
    involved, because that traffic is router-origin and takes OUTPUT, which the
    capture (mangle/PREROUTING) never sees. It should NOT be the router's own
    resolver — under the tun that deadlocked outright via `hijack-dns`, and
    while that mechanism is gone the recommendation stands (see
    `schemas.py::_direct_shape`, which also records that the TPROXY-era
    behaviour has not been re-tested). Empty falls back to sing-box
    `type: local`. Set this to a regional resolver if you rely on region-specific
    GeoDNS; foreign VPN endpoints no longer resolve here (they use the encrypted
    bootstrap above), so a regional/plain-UDP value here can't stale-out a node.
    """

    doh_url: str = DEFAULT_DOH_URL
    direct_dns: str = DEFAULT_DIRECT_DNS


class Data(BaseModel):
    """On-disk schema. Also what snapshot() returns to callers."""

    version: int = SCHEMA_VERSION
    subscriptions: list[Subscription] = Field(default_factory=list)
    active_server: ActiveServerRef | None = None
    vpn_on: bool = False
    rules_url: str = ""
    rules_fetched_at: str = ""
    rules: list[dict[str, Any]] = Field(default_factory=list)
    # Rule-set definitions referenced by `rules` (typically type: remote, so
    # sing-box downloads the geo/block data itself — kitewrt ships none).
    rule_sets: list[dict[str, Any]] = Field(default_factory=list)
    # IPv4 CIDRs that never enter the capture, so their traffic stays in
    # netfilter's `forward` chain and keeps the router's hardware flow offload.
    # Loaded into an ipset (a single match rule, not one rule per prefix).
    # Declared by the user's rules document — kitewrt ships no geo data and
    # picks no "home" country. Empty = everything is captured.
    rules_bypass_address: list[str] = Field(default_factory=list)
    rules_warnings: list[str] = Field(default_factory=list)
    rules_skipped_count: int = 0
    last_error: str = ""
    last_apply: ApplyResult | None = None
    applying: bool = False
    dns: DnsState = Field(default_factory=DnsState)
    # Keyed by server.id (host:port). Stale entries (servers that no longer
    # exist in any subscription) are harmless — the UI ignores keys it can't
    # match to a current server tile.
    pings: dict[str, PingResult] = Field(default_factory=dict)


# Per-server fields that are bearer secrets (or unused by the UI) and must NOT
# leave the daemon: the UI renders only id/name/country/type/host/port, while
# these stay on disk (state.json) and in the generated sing-box config only.
# Anyone on the LAN can already flip the VPN (documented trust model) — but they
# should not be able to read the subscription's VLESS UUIDs / passwords / keys.
_SECRET_SERVER_FIELDS = ("uuid", "password", "method", "params")


def redact_state_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Strip per-server secrets from a JSON-able state dict, in place. Applied to
    everything that leaves the daemon (the /api responses + the WS broadcast)."""
    for sub in data.get("subscriptions") or []:
        for srv in sub.get("servers") or []:
            for field in _SECRET_SERVER_FIELDS:
                srv.pop(field, None)
    return data


def redacted_state_dict(snap: Data) -> dict[str, Any]:
    """A secret-free JSON dump of `snap`, safe to broadcast to any UI client."""
    return redact_state_dict(snap.model_dump(mode="json"))


class State:
    """Async-safe wrapper around the JSON file.

    Reads return deep copies and take no lock — callers may freely mutate
    the returned object without affecting stored state. Writes go through
    `update()` which serializes via an asyncio.Lock and persists atomically.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._lock = asyncio.Lock()
        self._data = self._load()
        # Sync callbacks fired (outside the lock) with the new snapshot after
        # every successful update — lets the WS hub push state to the UI on
        # every change without polling. Empty by default (tests, headless).
        self._listeners: list[Callable[[Data], None]] = []

    def add_listener(self, cb: Callable[[Data], None]) -> None:
        self._listeners.append(cb)

    def _load(self) -> Data:
        """Load from disk, migrating an older schema forward where safe and
        falling back to defaults only on a missing/corrupt/inconsistent file."""
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return Data()
        try:
            loaded = Data.model_validate_json(raw)
        except ValidationError:
            # Unparseable into the current model → safe defaults rather than
            # crash. Rare now that writes are durable (tmp→fsync→rename).
            logger.warning("state.json failed validation; resetting to defaults")
            return Data()
        if loaded.version != SCHEMA_VERSION:
            loaded = _migrate(loaded)
        # `applying` describes a worker that is running *now*, so it is never
        # valid on load — and it only got reset inside `_migrate`, i.e. on a
        # schema change. A cancelled apply (which shutdown now does, by design)
        # persisted it as True, and the next boot then read it: the watchdog
        # returns immediately every tick (no capture re-assert, no sing-box
        # supervision), the capture-lost banner is suppressed, and the UI shows
        # a permanent spinner — until some apply happens to complete.
        loaded.applying = False
        # Repair a DoH URL saved before the validator required an IP literal.
        # Left alone it wedges every apply forever (sing-box rejects the
        # config), and there is no way to notice from the UI.
        if not _is_ip_literal_doh(loaded.dns.doh_url):
            logger.warning(
                "state: doh_url %r is a hostname, which sing-box cannot use to "
                "resolve server domains; resetting to %s",
                loaded.dns.doh_url,
                DEFAULT_DOH_URL,
            )
            loaded.dns.doh_url = DEFAULT_DOH_URL
        # Re-check the stored rules document against the *current* validator.
        # It is fetched once and persisted, so a rule that was accepted by an
        # older build is otherwise fed to sing-box on every boot forever — a
        # tightened validator would never see it again. Imported here rather
        # than at module scope to keep `state` free of the data-plane import
        # chain (rules pulls in divert and the sing-box config builders).
        if loaded.rules or loaded.rule_sets or loaded.rules_bypass_address:
            from kitewrt.rules import revalidate_persisted

            kept, sets, bypass, dropped = revalidate_persisted(
                loaded.rules, loaded.rule_sets, loaded.rules_bypass_address
            )
            loaded.rules_bypass_address = bypass
            if dropped:
                logger.warning(
                    "state: dropped %d stored rule(s) that the current validator rejects: %s",
                    len(dropped),
                    "; ".join(dropped[:3]),
                )
                loaded.rules, loaded.rule_sets = kept, sets
                loaded.rules_skipped_count += len(dropped)
                # Capped, because this list is persisted, re-appended on every
                # boot, and shipped whole in every `/api/state` response and WS
                # frame — the one field the bulk-to-count trim does not cover.
                # Measured with a 20,000-rule document the tightened validators
                # now reject: state.json 1.9 MB → 2.8 MB and a 2,749,487-byte
                # state body, surviving reboots. The count is the actionable
                # number; the strings are a sample.
                loaded.rules_warnings = [*loaded.rules_warnings, *dropped][-_MAX_WARNINGS:]
        return loaded

    def snapshot(self) -> Data:
        """Return a deep-copied snapshot safe to mutate."""
        return self._data.model_copy(deep=True)

    def active_server(self) -> Server | None:
        """Resolve the active selection to a concrete Server, or None if
        nothing is selected or the selection points at a server that no
        longer exists (deleted subscription, refreshed-away server, etc).
        """
        ref = self._data.active_server
        if ref is None:
            return None
        for sub in self._data.subscriptions:
            if sub.id != ref.subscription_id:
                continue
            for srv in sub.servers:
                if srv.id == ref.server_id:
                    return srv.model_copy(deep=True)
            return None
        return None

    def has_subscription(self, subscription_id: str) -> bool:
        return any(sub.id == subscription_id for sub in self._data.subscriptions)

    def has_server(self, subscription_id: str, server_id: str) -> bool:
        for sub in self._data.subscriptions:
            if sub.id != subscription_id:
                continue
            return any(srv.id == server_id for srv in sub.servers)
        return False

    async def update(self, fn: Callable[[Data], None]) -> Data:
        """Apply `fn` under the lock, persist, and return a snapshot.

        Use this for atomic read-modify-write of multiple fields. `fn`
        mutates the passed-in Data in place.
        """
        async with self._lock:
            # All-or-nothing: mutate a COPY and adopt it only once it is
            # durably on disk.
            #
            # Mutating `self._data` in place and saving afterwards left memory
            # and disk diverged whenever the write failed — and the damage went
            # further than a stale file. A caller that sets `applying=True` and
            # then signals the apply pipeline never reaches its signal, because
            # the OSError propagates out of here first. The flag is then set in
            # memory with no apply queued that could ever clear it, and the
            # watchdog returns immediately on every tick while it is set, so
            # sing-box stops being supervised at all. Measured on a full
            # filesystem: one ordinary "turn the VPN off" left the LAN dark for
            # over five minutes — capture installed, nothing listening behind
            # it — with `last_apply.ok` true, `last_error` empty, and no
            # self-healing. Recovery needed SSH.
            #
            # Costs one extra deep copy per update (~1.5 ms here with 8639
            # bypass networks, so ~10-15 ms on the router's A53); updates happen
            # a few times a minute, and one of them wedging the daemon is not a
            # trade worth making.
            candidate = self._data.model_copy(deep=True)
            fn(candidate)
            self._save_locked(candidate)
            self._data = candidate
            snap = candidate.model_copy(deep=True)
        # Notify outside the lock so a listener can't deadlock or stall writes.
        for cb in self._listeners:
            try:
                cb(snap)
            except Exception:
                logger.exception("state listener failed")
        return snap

    async def add_subscription(self, label: str, source: str, servers: list[Server]) -> Data:
        """Append a new subscription with a freshly-generated ID.

        Labels and sources are not deduplicated — users may want multiple
        cards for the same source under different labels.
        """
        sub = Subscription(
            id=_new_subscription_id(),
            label=label,
            source=source,
            fetched_at=now_iso(),
            servers=list(servers) if servers else [],
        )
        return await self.update(lambda d: d.subscriptions.append(sub))

    async def delete_subscription(self, subscription_id: str) -> Data:
        """Remove a subscription by ID.

        If the active server was inside it, the active selection is cleared
        and vpn_on is forced off (so the apply worker stops sing-box rather
        than running it without a target).
        """

        def mutate(d: Data) -> None:
            d.subscriptions = [s for s in d.subscriptions if s.id != subscription_id]
            if d.active_server and d.active_server.subscription_id == subscription_id:
                d.active_server = None
                d.vpn_on = False

        return await self.update(mutate)

    async def replace_subscription_servers(
        self, subscription_id: str, servers: list[Server]
    ) -> Data:
        """Update a subscription's server list (after a refresh or source edit).

        If the active server was inside this subscription and is no longer in
        the new server list, the active selection is cleared and vpn_on is
        forced off.
        """
        new_servers = list(servers) if servers else []

        def mutate(d: Data) -> None:
            for sub in d.subscriptions:
                if sub.id != subscription_id:
                    continue
                sub.servers = new_servers
                sub.fetched_at = now_iso()
                break
            if d.active_server is None or d.active_server.subscription_id != subscription_id:
                return
            still_present = any(srv.id == d.active_server.server_id for srv in new_servers)
            if not still_present:
                d.active_server = None
                d.vpn_on = False

        return await self.update(mutate)

    async def merge_pings(self, results: dict[str, int | None]) -> Data:
        """Record ping results, overwriting any prior entries for the same IDs.

        Other entries are left untouched — a per-subscription test should not
        wipe results from other subscriptions that were tested earlier.
        """
        at = now_iso()

        def mutate(d: Data) -> None:
            for server_id, ms in results.items():
                d.pings[server_id] = PingResult(ms=ms, at=at)

        return await self.update(mutate)

    async def rename_subscription(self, subscription_id: str, label: str) -> Data:
        def mutate(d: Data) -> None:
            for sub in d.subscriptions:
                if sub.id == subscription_id:
                    sub.label = label
                    return

        return await self.update(mutate)

    def _save_locked(self, data: Data | None = None) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        raw = (data if data is not None else self._data).model_dump_json(indent=2).encode()
        # mode 0o600: state.json holds subscription URLs and VLESS credentials.
        _atomic_write_durable(self._path, raw, mode=0o600)


def _migrate(loaded: Data) -> Data:
    """Adopt a state file whose `version` differs from SCHEMA_VERSION.

    The JSON already validated into the *current* Data model (pydantic ignores
    removed fields and defaults new ones), so a forward-compatible older file —
    notably v2, which already had `subscriptions` — carries its subscriptions,
    credentials, DNS and vpn_on across cleanly; we just adopt the new version and
    drop transient runtime fields. Only a genuinely *incompatible* shape is
    reset: the tell is `vpn_on` with no servers anywhere, which is what an
    ancient v1 file (a singular `subscription_url`, no `subscriptions`) collapses
    to — honoring "vpn on, nothing to proxy with" would just route direct under a
    false pretense. Resetting silently used to be the behavior for *every*
    version bump, which discarded every subscription on upgrade.
    """
    has_servers = any(sub.servers for sub in loaded.subscriptions)
    if loaded.vpn_on and not has_servers:
        logger.warning(
            "state schema v%d is incompatible (vpn on, no servers); resetting to defaults — "
            "re-add your subscription",
            loaded.version,
        )
        return Data()
    logger.info(
        "migrated state schema v%d → v%d (%d subscription(s) preserved)",
        loaded.version,
        SCHEMA_VERSION,
        len(loaded.subscriptions),
    )
    loaded.version = SCHEMA_VERSION
    loaded.applying = False
    loaded.last_apply = None
    return loaded


def _is_ip_literal_doh(url: str) -> bool:
    """Whether `url`'s host is an IP address, as sing-box's domain resolver
    requires. See kitewrt.schemas for why a hostname cannot work."""
    try:
        ipaddress.ip_address(urlparse(url).hostname or "")
    except ValueError:
        return False
    return True


def _atomic_write_durable(path: Path, raw: bytes, *, mode: int = 0o644) -> None:
    """Write `raw` to `path` durably: tmp → fsync(file) → atomic rename →
    fsync(dir).

    Plain write-tmp-then-rename is atomic against a *crash* but NOT against an
    unclean power-off — the #1 home-router "reboot" is unplugging it. Without
    fsync the rename metadata can hit disk while the data block doesn't, leaving
    a zero-length file; for state.json that silently drops every subscription and
    credential on the next boot (the loader falls back to defaults). The fsyncs
    make both the data and the rename durable.

    The directory fsync is load-bearing on the target stack, not decoration, and
    that was measured rather than assumed: on the router's own layout — f2fs
    with `fsync_mode=posix` under overlayfs, kernel 5.4 — it propagates through
    the overlay to the upper filesystem (block-layer counters show +4 write_ios
    / +40 sectors, identical to raw f2fs) and returns success rather than
    EINVAL. With it in place, 8 power cuts lost 0 acknowledged writes and
    corrupted nothing. Removed as a control, with the probe made the last thing
    to touch f2fs before the cut, it lost a generation 3 times out of 3:
    roll-forward recovered `state.tmp` but not the rename that made it
    `state.json`. (The qemu guest survives `sysrq-b`, so this measures whether
    f2fs *issued* the I/O — which is the question — not a device write cache
    below it.)

    Failure is swallowed because a filesystem that rejects it (some do) is still
    better served by the write than by an exception — but note that on such a
    stack the guarantee above is silently gone, and nothing here can tell.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        # os.write is a single syscall and may write fewer bytes than asked
        # (notably a partial write before ENOSPC) — loop or we'd fsync+rename a
        # truncated file, the exact corruption this helper exists to prevent.
        mv = memoryview(raw)
        while mv:
            mv = mv[os.write(fd, mv) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def _new_subscription_id() -> str:
    """Globally-unique ID for a new subscription.

    Format: "sub-<unix>-<6 hex>". Time prefix sorts naturally; hex suffix
    disambiguates within the same second.
    """
    return f"sub-{int(datetime.now(timezone.utc).timestamp())}-{secrets.token_hex(3)}"


def now_iso() -> str:
    """Current UTC time as ISO-8601 with second precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
