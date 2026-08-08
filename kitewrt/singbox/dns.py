"""sing-box `dns` block builder.

Five resolvers — four mirroring the routing split, plus the bootstrap that
resolves the proxy servers' own hostnames:
  * `dns-direct` — a plain-UDP resolver (the user's `direct_dns`, default
    Cloudflare; empty → `type: local`). Direct-routed (home-region) domains
    resolve here, on the direct path. Set it to a regional resolver if you rely
    on region-specific GeoDNS.
  * `dns-fake` — a fake-IP resolver. Proxy-routed (foreign) A/AAAA queries get a
    synthetic 198.18.x address *instantly* — no real lookup blocks the connect.
    sing-box reverse-maps that address back to the domain when routing, so the
    real resolution happens at the proxy exit (correct CDN, no ISP visibility).
    This is the Shadowrocket-style fake-IP that eliminates the per-domain
    DoH-over-proxy round trip (~140 ms each) that made page/video startup slow.
  * `dns-proxy` — DoH (the user's `doh_url`) over the proxy detour. Catches
    foreign queries fake-IP can't answer (non-A/AAAA: HTTPS/SVCB/TXT/…) so they
    still resolve over the proxy, never via the ISP.
  * `dns-bootstrap` — the same DoH endpoint, dialed off-tunnel (its own WAN
    socket, like dns-direct — no detour). Resolves proxy/VPN *server* domains
    (`route.default_domain_resolver`) over encrypted DNS, so a foreign endpoint
    is never resolved via the poisonable RU plain-UDP `dns-direct` path (which
    serves stale/spoofed answers for foreign hosts — a just-repointed A record
    stays stale, so the node dials a dead IP). The DoH host must be an IP literal
    so it needs no lookup of its own (no bootstrap loop).
  * `dns-local` — the router's own resolver (`type: local` → dnsmasq) for
    `*.lan` / `localhost`, so LAN hosts reachable by name aren't fake-IP'd and
    sent to the proxy (which can't resolve a private name).

IPv4-only data plane (IPv6 is dropped fail-closed at the firewall, not
tunnelled), so `strategy: ipv4_only` — never hand out AAAA answers that have no
route through a v4-only capture.

Uses the sing-box 1.12+ typed-server DNS format (the legacy format is removed
in 1.14).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from kitewrt.singbox.route import PROXY_ALIAS, default_route_rules

DNS_PROXY = "dns-proxy"
DNS_BOOTSTRAP = "dns-bootstrap"
DNS_DIRECT = "dns-direct"
DNS_FAKE = "dns-fake"
DNS_LOCAL = "dns-local"

# Domain suffixes that name LAN hosts and must resolve on the router's own
# resolver (dnsmasq via `type: local`), never get a fake IP. Without this a
# `*.lan` lookup is fake-IP'd → proxied → the proxy can't resolve a private
# name, so reaching a NAS/printer/router by name breaks while routing is active.
# `lan` is the OpenWrt default LAN domain; `localhost` is always local.
_LOCAL_DOMAIN_SUFFIXES = ["lan", "localhost"]

# Standard fake-IP range (RFC 2544 benchmarking block) — the same one
# Shadowrocket/Clash use. IPv4-only: the data plane has no IPv6, so we never
# mint v6 fake addresses (nothing would carry them — `divert` speaks iptables,
# not ip6tables, and the installer drops forwarded LAN→WAN IPv6 outright).
FAKEIP_INET4 = "198.18.0.0/15"

# Matcher keys that resolve a query by *name* — the only ones meaningful at DNS
# time (IP matchers like ip_cidr/ip_is_private need an answer first, so they
# can't steer the lookup that produces it). `rule_set` is included: an IP
# rule-set simply never matches a domain query, so passing the whole set is
# safe and lets a domain rule-set still steer DNS.
_DOMAIN_MATCH_KEYS = ("domain", "domain_suffix", "domain_keyword", "domain_regex", "rule_set")


def _doh_server(doh_url: str, tag: str) -> dict[str, Any]:
    """Parse a DoH URL into a sing-box typed https server (detour set by caller).

    `https://cloudflare-dns.com/dns-query` → host `cloudflare-dns.com`,
    path `/dns-query`. The same URL builds both `dns-proxy` (detour = selector,
    set by the caller) and `dns-bootstrap` (no detour → dialed off-tunnel).

    NOTE: for `dns-bootstrap` the URL host should be an **IP literal**
    (`https://1.1.1.1/dns-query`) — it resolves proxy server *domains*, so a
    hostname here would itself need resolving (a bootstrap loop). An IP DoH host
    needs no lookup and, queried by numeric address, dodges SNI-based blocking.
    """
    parts = urlsplit(doh_url)
    server: dict[str, Any] = {
        "type": "https",
        "tag": tag,
        "server": parts.hostname or "cloudflare-dns.com",
    }
    if parts.port:
        server["server_port"] = parts.port
    if parts.path and parts.path != "/":
        server["path"] = parts.path
    return server


def _dns_rules_from_routes(
    user_rules: list[dict[str, Any]] | None, selector_tag: str
) -> list[dict[str, Any]]:
    """Mirror the routing decision into DNS so a domain resolves on the same
    side it will be sent: direct-routed names via `dns-direct` (correct CDN
    answers on the direct path), proxy-routed names via `dns-fake` (an instant
    fake IP, with the real lookup deferred to the proxy exit).

    Only name matchers carry over (see `_DOMAIN_MATCH_KEYS`); IP-only rules are
    dropped because there's no IP yet at lookup time. Order is preserved, so a
    `proxy` override placed before a broad `direct` rule wins for DNS too — e.g.
    a censored host that a broad regional `direct` rule would otherwise catch,
    routed to fake-IP (→ proxy) instead of being resolved real on the direct
    path. Anything unmatched falls through to the catch-all fake-IP rule
    build_dns appends.
    """
    rules = user_rules if user_rules else default_route_rules()
    out: list[dict[str, Any]] = []
    for rule in rules:
        outbound = rule.get("outbound")
        if outbound == "direct":
            server = DNS_DIRECT
        elif outbound in (PROXY_ALIAS, selector_tag):
            server = DNS_FAKE
        else:
            continue  # block / unknown — nothing useful to resolve
        matcher = {k: rule[k] for k in _DOMAIN_MATCH_KEYS if k in rule}
        if not matcher:
            continue  # IP-only rule — can't steer a lookup
        if server == DNS_FAKE:
            # Fake-IP answers A/AAAA only; scope the rule so a proxy domain's
            # HTTPS/SVCB query falls through to `final` (DoH, real answer)
            # instead of hitting fake-IP → NODATA and losing its ECH record.
            out.append({**matcher, "query_type": ["A", "AAAA"], "server": server})
        else:
            out.append({**matcher, "server": server})
    return out


def _split_host_port(raw: str) -> tuple[str, int | None]:
    """Split `host:port` → (host, port); a bare host → (host, None).

    A typed UDP server wants the host in `server` and the port in `server_port`,
    not a `host:port` string crammed into `server`. IPv6 literals (more than one
    colon) are returned untouched — the data plane is IPv4-only, so they don't
    occur here in practice.
    """
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        if host and port.isdigit():
            return host, int(port)
    return raw, None


def _direct_server(direct_dns: str) -> dict[str, Any]:
    """The `dns-direct` resolver.

    Empty `direct_dns` → `type: local` (read /etc/resolv.conf — the right
    generic default). A non-empty value pins a plain UDP resolver at that IP/host;
    an optional `:port` is split into `server_port` (a typed server rejects a
    `host:port` string in `server`). Use the LAN/gateway resolver IP on routers
    that don't answer DNS on loopback. No `detour` is set: direct DNS to a
    LAN/gateway IP is private, so the baseline `ip_is_private → direct` route
    rule already sends it direct.
    """
    raw = direct_dns.strip()
    if not raw:
        return {"type": "local", "tag": DNS_DIRECT}
    host, port = _split_host_port(raw)
    server: dict[str, Any] = {"type": "udp", "tag": DNS_DIRECT, "server": host}
    if port is not None:
        server["server_port"] = port
    return server


def build_dns(
    doh_url: str,
    selector_tag: str,
    user_rules: list[dict[str, Any]] | None = None,
    direct_dns: str = "",
) -> dict[str, Any]:
    """Build the `dns` block.

    `doh_url` is the foreign-traffic DoH upstream (from state.dns.doh_url).
    `selector_tag` is the proxy detour for that DoH server.
    `user_rules` are the same route rules the `route` block uses; their
    name-based decisions are mirrored into DNS (see `_dns_rules_from_routes`).
    `direct_dns` optionally pins the direct resolver to a UDP IP (see
    `_direct_server`); empty means `type: local`.

    Shape: direct/home domains resolve real via `dns-direct`; everything else
    A/AAAA resolves to a fake IP (`dns-fake`) so the connect never waits on a
    real lookup; remaining foreign queries (non-A/AAAA) fall through to DoH
    (`dns-proxy`, the `final`). Proxy/VPN server hostnames are resolved by the
    route's `default_domain_resolver` (= `dns-bootstrap`, set in config.py) —
    encrypted DoH dialed off-tunnel, never `dns-direct` (whose plain-UDP RU path
    serves stale/poisoned answers for foreign hosts) and never fake-IP,
    so a domain-addressed node always dials its true current IP.
    """
    proxy_server = _doh_server(doh_url, DNS_PROXY)
    proxy_server["detour"] = selector_tag
    # Same DoH endpoint but NO detour: like dns-direct, sing-box dials it over
    # its own WAN socket. Router-originated traffic takes OUTPUT, which the
    # capture (mangle/PREROUTING) never sees, so this is off-tunnel by
    # construction — no exclusion rule is involved. It therefore resolves proxy
    # server *domains* (route.default_domain_resolver, set in
    # config.py) without going through the proxy — no bootstrap loop. A
    # `detour: "direct"` is rejected at service start ("detour to an empty direct
    # outbound makes no sense"), and `sing-box check` does NOT catch that — only
    # a real run does. Encrypted (DoH) so RU DPI can't spoof it; the RU plain-UDP
    # `dns-direct` path serves stale/spoofed answers for foreign hosts. Expects
    # an IP-literal DoH host (no lookup of its own → no loop).
    bootstrap_server = _doh_server(doh_url, DNS_BOOTSTRAP)

    # LAN names first: *.lan / localhost resolve on the router's own resolver
    # (dnsmasq, which knows DHCP hostnames), never fake-IP'd or proxied. Must
    # precede the user-rule mirror and the fake-IP catch-all so reaching a LAN
    # device by name keeps working while routing is active.
    rules: list[dict[str, Any]] = [
        {"domain_suffix": list(_LOCAL_DOMAIN_SUFFIXES), "server": DNS_LOCAL}
    ]
    rules.extend(_dns_rules_from_routes(user_rules, selector_tag))
    # Catch-all: any A/AAAA not already steered to dns-direct above is foreign →
    # fake IP (instant; real resolution deferred to the proxy exit). Non-A/AAAA
    # foreign queries fall past this to `final` (DoH over the proxy).
    rules.append({"query_type": ["A", "AAAA"], "server": DNS_FAKE})

    return {
        "servers": [
            proxy_server,
            bootstrap_server,
            _direct_server(direct_dns),
            {"type": "fakeip", "tag": DNS_FAKE, "inet4_range": FAKEIP_INET4},
            # Router-local resolver for *.lan / localhost (see the LAN-names
            # rule above). `type: local` reads the system resolver (dnsmasq).
            {"type": "local", "tag": DNS_LOCAL},
        ],
        "rules": rules,
        "final": DNS_PROXY,
        # v4-only data plane → never answer AAAA (the capture is IPv4-only, so
        # a v6 answer names an address nothing here can carry).
        "strategy": "ipv4_only",
        # Per-server cache so fake-IP mappings don't bleed into the real caches.
        "independent_cache": True,
    }
