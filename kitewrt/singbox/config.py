"""Assemble a complete sing-box config from a kitewrt state snapshot.

Pure: `build_config(snap) -> dict`. No I/O — `service.py` serialises and
writes it. The shape is the one validated by `sing-box check` on the router.

Server switching and on/off do NOT regenerate this config — they're live
Clash API calls against the `selector`. This config is rewritten only when
the *set* of servers, the routing rules, or the DNS upstream change.

Capture is a single `tun` inbound with `auto_route` + `strict_route`: sing-box
itself installs the policy routes that pull all forwarded LAN traffic into the
tunnel device, so there are no hand-rolled iptables capture chains. This is the
setup proven on the Flint 2 (OpenWrt/fw3). On/off stays a pure selector switch
(the tun is always up; "off" just routes the captured traffic to `direct`).
"""

from __future__ import annotations

from typing import Any

from kitewrt.singbox.dns import DNS_DIRECT, build_dns
from kitewrt.singbox.outbound import build_outbound, outbound_tag
from kitewrt.singbox.route import build_route
from kitewrt.state import Data

SELECTOR_TAG = "select"
CLASH_API_ADDR = "127.0.0.1:9090"
# The tun device sing-box creates and owns. auto_route adds the ip rules /
# routes that capture forwarded LAN traffic into it; strict_route makes the
# capture fail-closed (when the tunnel is down, captured traffic is dropped,
# not leaked to the WAN). IPv4-only: the router denied IPv6 addressing on the
# tun during bring-up, and the LAN policy is IPv4 anyway. A /30 is all the tun
# needs — it's a point-to-point device, not a subnet.
TUN_NAME = "singtun"
TUN_ADDRESS = "172.19.0.1/30"
# tun networking stack. `mixed` = kernel (system) stack for TCP — fastest and
# lowest-CPU on the A53, which carries the bulk of traffic — and the gvisor
# userspace stack for UDP. The pure `system` stack does not relay UDP out of the
# tun (verified: a UDP probe through it times out), so QUIC/HTTP3 never works and
# had to be blocked. `mixed` relays UDP correctly, so QUIC can flow through the
# tunnel (Shadowrocket-parity) while TCP keeps the cheap kernel path.
TUN_STACK = "mixed"
# Where sing-box persists downloaded remote rule-sets + the selector choice.
CACHE_FILE = "/etc/sing-box/cache.db"


def _server_outbounds(snap: Data) -> list[tuple[str, dict[str, Any]]]:
    """(tag, outbound) for every server across all subscriptions.

    Tags are composite (subscription/server) and unique, so identical
    host:port in two subscriptions don't collide in the selector.
    """
    out: list[tuple[str, dict[str, Any]]] = []
    for sub in snap.subscriptions:
        for srv in sub.servers:
            tag = outbound_tag(sub.id, srv.id)
            out.append((tag, build_outbound(srv, tag)))
    return out


def active_tag(snap: Data) -> str | None:
    """The outbound tag of the active server, or None if unset / dangling."""
    ref = snap.active_server
    if ref is None:
        return None
    for sub in snap.subscriptions:
        if sub.id != ref.subscription_id:
            continue
        if any(srv.id == ref.server_id for srv in sub.servers):
            return outbound_tag(ref.subscription_id, ref.server_id)
    return None


def selector_default(snap: Data) -> str:
    """What the selector should point at: the active server when VPN is on
    and the selection resolves, else `direct` (VPN off / no valid server)."""
    if snap.vpn_on:
        tag = active_tag(snap)
        if tag is not None:
            return tag
    return "direct"


def build_config(snap: Data) -> dict[str, Any]:
    server_obs = _server_outbounds(snap)
    server_tags = [tag for tag, _ in server_obs]

    selector = {
        "type": "selector",
        "tag": SELECTOR_TAG,
        # `direct` is a member so on/off is a pure selector switch (no
        # process restart): off → select `direct`, on → select a server.
        "outbounds": [*server_tags, "direct"],
        "default": selector_default(snap),
    }

    outbounds: list[dict[str, Any]] = [ob for _, ob in server_obs]
    outbounds.append(selector)
    outbounds.append({"type": "direct", "tag": "direct"})
    # No `block` outbound: the legacy special outbounds (block/dns) are
    # deprecated and slated for removal from sing-box. A user rule that asks to
    # block is rewritten to the modern `{"action": "reject"}` route action by
    # build_route, so nothing needs to reference a block outbound.

    route = build_route(snap.rules or None, snap.rule_sets or None, SELECTOR_TAG)
    # Resolve outbound *server* domains over the direct (local) resolver,
    # breaking the bootstrap loop (DoH detours through the proxy, whose server
    # domain must itself be resolved first — not through the proxy).
    route["default_domain_resolver"] = DNS_DIRECT
    # No manual loop-avoidance mark: with auto_route, sing-box itself excludes
    # its own outbound sockets from the tun capture, so the OUTPUT-chain
    # RETURN-on-mark plumbing the TPROXY setup needed is gone.

    return {
        "log": {"level": "warn", "timestamp": True},
        # Direct resolver: the user-set `direct_dns` (default Cloudflare), else
        # `type: local`. Bootstraps the proxy server's own domain.
        "dns": build_dns(
            snap.dns.doh_url,
            SELECTOR_TAG,
            snap.rules or None,
            snap.dns.direct_dns.strip(),
        ),
        "inbounds": [
            # Single tun inbound. auto_route makes sing-box install the policy
            # routes that pull forwarded LAN traffic into `singtun`; strict_route
            # makes that capture fail-closed. The recovered packet keeps its real
            # destination IP, so geoip / ip_is_private route rules match directly
            # (no SO_ORIGINAL_DST / TPROXY plumbing, no per-socket loop mark).
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": TUN_NAME,
                "address": [TUN_ADDRESS],
                "auto_route": True,
                "strict_route": True,
                "stack": TUN_STACK,
            },
        ],
        "outbounds": outbounds,
        "route": route,
        "experimental": {
            "clash_api": {"external_controller": CLASH_API_ADDR},
            # Persist downloaded remote rule-sets across restarts so we don't
            # re-fetch geo data every reload. `enabled` alone also persists the
            # selector's live pick (sing-box restores the last selected outbound
            # from cache on restart — no separate flag, and `store_selected` is
            # not a valid 1.13 field). That cached pick can be *stale* relative
            # to the intended target, though, so every restart path re-asserts
            # the selector inside the kill-switch bracket: the apply pipeline via
            # _reload's `after` hook, and the watchdog via its own reselect (see
            # dataplane.reassert_selector). store_fakeip keeps the fake-IP ↔
            # domain map too, so live connections survive a reload instead of
            # dangling on a now-unmapped 198.18.x address.
            "cache_file": {"enabled": True, "path": CACHE_FILE, "store_fakeip": True},
        },
    }
