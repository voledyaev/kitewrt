"""Assemble a complete sing-box config from a kitewrt state snapshot.

Pure: `build_config(snap) -> dict`. No I/O — `service.py` serialises and
writes it. The shape is the one validated by `sing-box check` on the router.

Server switching and on/off do NOT regenerate this config — they're live
Clash API calls against the `selector`. This config is rewritten only when
the *set* of servers, the routing rules, or the DNS upstream change.

Capture is a `tproxy` inbound fed by the netfilter rules in kitewrt.divert.
*We* install those — the mangle chain, the fwmark ip rule and its route table —
because a tproxy inbound gets handed an already-established socket rather than
raw packets, so someone has to tell the kernel which packets to hand over. This
is the setup proven on the Flint 2 (OpenWrt/fw3). On/off stays a pure selector
switch: the capture stays installed and "off" routes captured traffic to
`direct`.
"""

from __future__ import annotations

from typing import Any

from kitewrt import divert
from kitewrt.singbox.dns import DNS_BOOTSTRAP, build_dns
from kitewrt.singbox.outbound import build_outbound, outbound_tag
from kitewrt.singbox.route import build_route
from kitewrt.state import Data

SELECTOR_TAG = "select"
CLASH_API_ADDR = "127.0.0.1:9090"
# LAN capture is done with a `tproxy` inbound plus netfilter rules we install
# ourselves (kitewrt.divert) — not a tun with auto_route.
#
# A tun hands the proxy raw IP packets, so sing-box must run a TCP stack in
# userspace (gvisor) to turn them back into streams. TPROXY lets the *kernel*
# own TCP and hands sing-box an already-established socket. Measured in a
# controlled lab on the target kernel (iperf3, client→router→server):
#
#     plain kernel forwarding      5.98 / 6.42 Gb/s    100%
#     tun stack=mixed              185  / 187  Mb/s      3%
#     tun stack=gvisor + mtu9000   1.10 / 1.17 Gb/s     18%
#     tproxy                       3.54 / 3.34 Gb/s     56%
#
# Same binary, same outbound, same traffic — only the inbound differs.
#
# `listen: "::"` covers both families on one socket; the divert rules decide
# what actually arrives. See kitewrt/divert.py for the capture itself and why
# its rule ordering matters.
TPROXY_PORT = divert.TPROXY_PORT
TPROXY_TAG = "tproxy-in"

# A loopback HTTP-proxy inbound for the *daemon's own* outbound requests
# (subscription / rules fetch, exit-IP check). With a tun, auto_route captured
# router-origin traffic implicitly; TPROXY hooks PREROUTING, which forwarded
# LAN traffic passes through but locally-generated traffic does not. Rather
# than also capturing OUTPUT — which invites routing loops with sing-box's own
# egress — the daemon proxies through this explicitly.
#
# `http` rather than `socks` on purpose: httpx speaks HTTP proxies out of the
# box, while SOCKS needs the extra `socksio` package — one more locked
# dependency uv has to install into `/usr/lib/kitewrt/vendor` on a router with
# a small overlay, for nothing this needs.
#
# Loopback-only. It is unauthenticated, so it must never be reachable off-box.
# The bind address is the only thing enforcing that — do not weaken it on the
# theory that the capture cannot reach here: the divert's PREROUTING hook
# carries no `-i` at all (deliberately, so a guest SSID or a VLAN added later is
# captured rather than silently bypassed), and 127.0.0.0/8 merely happens not to
# be routable from the LAN.
LOCAL_PROXY_PORT = 7896
LOCAL_PROXY_TAG = "local-proxy-in"
LOCAL_PROXY_URL = f"http://127.0.0.1:{LOCAL_PROXY_PORT}"
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
    # Resolve outbound *server* domains over `dns-bootstrap` — encrypted DoH on
    # the `direct` outbound. NOT `dns-direct`: its plain-UDP RU resolver serves
    # stale/spoofed answers for foreign hosts, so a domain-addressed node whose A
    # record just moved (e.g. to escape a block) keeps dialing the dead old IP —
    # silently, since the config is valid and the process is up. `disable_cache`
    # so a corrected A record is picked up on the next reconnect instead of being
    # pinned for the upstream TTL; `ipv4_only` matches the v4-only capture.
    route["default_domain_resolver"] = {
        "server": DNS_BOOTSTRAP,
        "strategy": "ipv4_only",
        "disable_cache": True,
    }
    # No loop-avoidance mark is needed, but NOT because sing-box excludes its
    # own sockets — it has no idea the capture exists. It's because the capture
    # hooks PREROUTING only, and locally-generated traffic (sing-box's outbound
    # sockets, and the daemon's own requests) takes OUTPUT, which we never
    # touch. Anyone adding an OUTPUT hook must add the RETURN-on-mark plumbing
    # in the same change, or sing-box's egress will be captured into itself.

    return {
        "log": {"level": "warn", "timestamp": True},
        # `direct_dns` (the user-set plain-UDP resolver) now serves ONLY
        # direct/regional domains; proxy server-domain resolution moved to the
        # encrypted `dns-bootstrap` (default_domain_resolver above).
        "dns": build_dns(
            snap.dns.doh_url,
            SELECTOR_TAG,
            snap.rules or None,
            snap.dns.direct_dns.strip(),
        ),
        "inbounds": [
            # LAN capture. The netfilter divert (kitewrt.divert) hands us the
            # connection with its original destination intact, so geoip /
            # ip_is_private route rules match on the real address exactly as
            # they did under the tun.
            {
                "type": "tproxy",
                "tag": TPROXY_TAG,
                "listen": "::",
                "listen_port": TPROXY_PORT,
            },
            # The daemon's own egress (see the LOCAL_PROXY_PORT comment above).
            {
                "type": "http",
                "tag": LOCAL_PROXY_TAG,
                "listen": "127.0.0.1",
                "listen_port": LOCAL_PROXY_PORT,
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
            # the selector in the restart's `after` hook, before it reports
            # success: the apply pipeline via `_reload`, and the watchdog via its
            # own reselect (see dataplane.reassert_selector). The watchdog also
            # re-checks the live selector every tick, which heals a restart whose
            # hook never ran. store_fakeip keeps the fake-IP ↔
            # domain map too, so live connections survive a reload instead of
            # dangling on a now-unmapped 198.18.x address.
            "cache_file": {"enabled": True, "path": CACHE_FILE, "store_fakeip": True},
        },
    }
