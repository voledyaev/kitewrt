# Architecture

KiteWrt turns a VLESS subscription into a transparent, per-country VPN for a
whole LAN, managed from a web UI, on an OpenWrt router. This document describes
how the pieces fit together and why.

## Overview

```
┌─ Mac / Linux (install-time only) ──────────────────────┐
│  kitewrt — Python installer (asyncssh).                │
│  SSH (root) → opkg python3, pip deps, fetch sing-box,  │
│  deploy kitewrt/, write procd inits, set up the fw3    │
│  tun zone, start the daemon.                           │
└────────────────┬───────────────────────────────────────┘
                 │ SSH :22 (plain shell, real exit codes)
                 ▼
┌─ OpenWrt router (runtime) ─────────────────────────────┐
│                                                         │
│  python3 -m kitewrt  (procd, :8088)                    │
│    FastAPI UI + apply pipeline + watchdog               │
│    │ writes config.json, drives the Clash API          │
│    ▼                                                    │
│  sing-box  (procd)                                      │
│    tun + auto_route — captures forwarded LAN traffic    │
│    selector / DNS / route                               │
│    ▲                                                    │
│    └──── LAN devices (phones / laptops / TVs) ──────────┘
│              reach the WAN through the singtun device   │
└─────────────────────────────────────────────────────────┘
```

One long-lived process does the data-plane work:

- **sing-box** — the proxy/DNS/routing brain. A single `tun` inbound with
  `auto_route` captures all forwarded LAN traffic; a `selector` outbound picks
  the active server — any parsed protocol (VLESS / Shadowsocks / VMess / Trojan
  / hysteria2 / hysteria v1 / TUIC) or `direct`; the route block applies the
  routing split; the DNS block fake-IPs foreign A/AAAA names (instant; the real
  lookup happens at the proxy exit), sends the rarer non-A/AAAA foreign queries
  over DoH-through-the-proxy, and resolves home/LAN names via the configurable
  Direct DNS.

The **kitewrt daemon** (Python/FastAPI) owns no packets. It holds state,
generates `config.json`, drives sing-box's Clash API for live changes, and
supervises the process. The installer runs once from a laptop and never needs
to talk to the router again.

## The two kinds of change

The core of the design is splitting user actions into two paths:

- **Live change** — *pick a country*, *VPN on/off*, *auto-select fastest*. These
  don't regenerate any config: the daemon issues a Clash API call
  (`PUT /proxies/<selector>`) and sing-box repoints its `selector` outbound in
  place. No process restart, no firewall churn, existing connections drain
  gracefully. Sub-second.
- **Structural change** — the *set* of servers, the routing rules, or the DoH
  URL. These regenerate `config.json` and restart sing-box. A restart briefly
  drops the tun, so it's bracketed by a fail-closed kill switch.

Everything else is a thin layer over those two. A subscription refresh that
changes the *active* server's list is structural (the outbound set changed); a
refresh of a background subscription touches nothing live until the user selects
from it. Auto-select is purely live once the servers are materialized — it
delay-tests each outbound and `select`s the winner.

## Capture: sing-box tun + auto_route

A single `tun` inbound owns the capture:

```jsonc
{ "type": "tun", "tag": "tun-in", "interface_name": "singtun",
  "address": ["172.19.0.1/30"], "auto_route": true, "strict_route": true,
  "stack": "mixed" }
```

`auto_route` makes sing-box install the policy routes (ip rules + a routing
table) that pull forwarded LAN→WAN traffic into `singtun`. `strict_route` makes
the capture **fail-closed**: when the tunnel is down, captured traffic is
dropped rather than leaking out the WAN. There are **no hand-rolled iptables
capture chains** — sing-box owns it end to end. The captured packet keeps its
real destination IP, so `geoip` / `ip_is_private` route rules match directly.

The installer wires an fw3 zone for the tun device (named uci sections, so
re-running converges):

```
config zone        # name 'singbox', input/output/forward ACCEPT, masq 1, mtu_fix 1
    list device 'singtun'
config forwarding  # src 'lan' → dest 'singbox'
```

`stack: mixed` runs TCP on the kernel (system) stack — fastest, lowest-CPU on
the A53, and TCP is the bulk of traffic — and UDP on the gvisor userspace stack.
The pure `system` stack does not relay UDP out of the tun, so QUIC/HTTP3 never
worked under it (earlier builds blocked UDP/443 at the route layer as a result);
`mixed` relays UDP correctly, so QUIC flows through the tunnel. Measured CPU
stayed low (~40% of 4 cores) under 3×4K-HDR multi-device load.

## Components

### Daemon — `kitewrt/` package

FastAPI + uvicorn + httpx + pydantic, run as `python3 -m kitewrt`. Single
async process. Holds state in memory (mirrored to `data/state.json`), serves
the UI + JSON API + a WebSocket push channel, and drives sing-box.

### Modules

| Module | Responsibility |
|---|---|
| `api.py` | App factory + production lifespan (builds State / pipeline / service from env, wires routers, WS broadcast, metrics pump, subscription auto-refresh pump). |
| `deps.py`, `schemas.py` | FastAPI dependency accessors (State / pipeline / clash / data-plane) + Pydantic request-body models. |
| `state.py` | Pydantic `Data` schema + `State` (atomic JSON persistence, listeners). |
| `apply.py` | `ApplyPipeline` — serialised worker that coalesces "apply" signals and runs the data plane. |
| `dataplane.py` | `SingBoxDataPlane` — decides live-switch vs reload; `ensure_materialized` for the delay-test prep; `SingBoxWatchdogDeps`. |
| `subscriptions.py` | Fetch/parse + the best-effort background auto-refresh (shared by the route and the pump). |
| `autoselect.py` | Rank a subscription's servers by proxy delay-test, pick the fastest. |
| `singbox/config.py` | Pure builder: state → sing-box config dict (tun, selector, outbounds, route, dns, clash api). |
| `singbox/route.py`, `dns.py`, `outbound.py` | Route-rule, DNS-block, and proxy-outbound builders (vless / ss / vmess / trojan / tuic / hysteria(2)). |
| `singbox/service.py` | sing-box process control (procd) + atomic config write. |
| `singbox/clash.py` | Clash API client (live selector switch, URL delay-test, proxy list, health, connections/metrics). |
| `rules.py` | Validate/normalise user routing-rules JSON (sing-box-native). |
| `vless.py`, `fetch.py`, `probe.py` | Subscription parsing (all node schemes), fetching, TCP-latency probing. |
| `killswitch.py` | Fail-closed FORWARD DROP around restarts. |
| `watchdog.py` | Restart sing-box if it dies / wedges while VPN is on. |
| `hub.py`, `metrics_store.py` | WS broadcaster + server-side metrics history. |
| `routes/` | FastAPI routers (subscriptions, server, vpn, dns, rules, metrics, ws, meta, connectivity, exit_ip). |

### State — `data/state.json`

The `Data` model is the single source of truth: subscriptions (+ parsed
servers), the active-server reference, `vpn_on`, routing rules (+ rule-set
defs), DNS config, and the latest per-server ping results. Writes are atomic
(tmp + rename); listeners fan changes out to the WS hub. The generated sing-box
config is a derived artifact — only `state.json` is authoritative.

### sing-box config generation — `kitewrt/singbox/`

`build_config(snap)` is pure (state in, dict out), so it's fully unit-testable
without a router. Every server across every subscription is materialized as an
outbound (composite `subscription/server` tag), with the selector listing them
all plus `direct`. `service.py` serialises the config (atomic write) and
restarts the process. Server switching / on-off never call this — they go
through the Clash API. The config is rewritten only on a structural change.

### Live switching — `kitewrt/singbox/clash.py`

sing-box exposes a Clash-compatible API on `127.0.0.1:9090`. The selector's
membership is `[<server tags…>, direct]`; on/off and country are a single
`select` call. The client also URL-delay-tests an outbound (the data behind
"⚡ Fastest"), lists registered proxies (used to wait out a post-reload warmup
before delay-testing), reports health (used by the watchdog), and streams live
connections/throughput (used by the metrics pump).

### Auto-select fastest — `kitewrt/autoselect.py`

`POST /api/subscriptions/{id}/auto-select` delay-tests every server in the
subscription *through the proxy* — sing-box opens a real connection through each
outbound and times an HTTP-204 round-trip, so the score reflects the full
ISP→server→internet path, not just reachability to the server edge. The fastest
becomes the active server (a live `select`, like a manual pick).

A server's outbound is only dialable once it's in the *running* config, but
adding a subscription deliberately skips the reload (so it doesn't disrupt the
live connection) and with the VPN off sing-box may not be running at all. So the
route first calls `dataplane.ensure_materialized` — reload only when the running
structure is stale or sing-box is down — then waits for the per-outbound proxy
entries to register before testing. Concurrency is capped (5) so a wide burst of
cold TLS handshakes doesn't saturate a constrained router/ISP NAT and make
healthy nodes read "down".

### Subscriptions + auto-refresh — `kitewrt/subscriptions.py`

`fetch_and_parse` resolves a source (an HTTP(S) subscription URL, or an inline
`vless://…` node) to a server list. The same flow runs whether the user clicks
*Refresh* or a background pump fires: `api._subscription_refresh_pump` re-fetches
every fetchable subscription every ~6 h. The refresh is best-effort — a failed
source keeps its old server list (a stale list beats an empty one) — and only
nudges the data plane when it touched the *active* subscription, so a background
refresh never disrupts the running VPN.

### Frontend — `web/` (source) → `kitewrt/static/` (built)

A React + Vite SPA (TypeScript, Tailwind CSS + daisyUI for the component set, a
lazily-loaded ApexCharts chunk for the traffic graph). The source lives in
`web/`; `npm run build` emits the bundle into `kitewrt/static/`, which is
committed so the router install needs no Node toolchain (CI rebuilds and fails
if the committed output drifts). It consumes the `/ws` push channel for instant
state + ~1/s metrics, with `/api/state` + `/api/metrics` polling as a fallback
when the socket is down. The dashboard renders throughput/memory/connection
history, top flows by host (with tcp/udp type), and a per-device (source-IP)
traffic rollup.

### Apply pipeline — `kitewrt/apply.py`

A single background worker consumes "apply" signals. Mutating routes update
state, set `applying=True`, and `signal()` the pipeline; the worker coalesces
bursts and calls `dataplane.apply(snapshot)`. Serialising here means concurrent
edits can't race the engine.

### Watchdog — `kitewrt/watchdog.py`

Every 30 s, if `vpn_on`: check sing-box is healthy (process up **and** Clash API
responding). A wedged-but-alive sing-box counts as down. After two consecutive
down ticks (debounce) it restarts via the service. procd's `respawn` also
covers hard crashes; the watchdog adds the wedged-control-plane case.

### Kill switch — `kitewrt/killswitch.py`

A reload restarts sing-box, briefly dropping the tun + auto_route rules. During
that window forwarded LAN→WAN traffic could fall through to the direct route, so
`restart()` is bracketed by a fail-closed `FORWARD -o <wan> -j DROP`. When
sing-box is up the rule is inert (captured packets enter the tun before the
FORWARD egress path); a crash is already fail-closed via `strict_route`.

### Installer — `installer/` package

A Mac/Linux-side asyncssh tool. `Router` runs commands over one SSH connection
with real exit codes and uploads files as base64-over-stdin (dropbear ships no
SFTP). Steps: preflight (OpenWrt + opkg, arch via `uname -m`, kmod-tun) → opkg
python3 + pip deps → fetch the static-Go sing-box binary → deploy `kitewrt/` to
`/usr/lib/kitewrt` → install procd inits → fw3 tun zone → start. Idempotent;
re-running redeploys just the changed source.

For a router whose ISP blocks GitHub/PyPI, the installer first checks an
*artifacts dir* (`installer/artifacts/`, overridable with `--artifacts-dir`):
drop the pre-downloaded sing-box release tarball (and optionally pip wheels)
there and it uploads + installs them offline instead of fetching. Nothing is
auto-bundled — it just checks for the files and falls back to downloading when
absent.

### Init scripts — `installer/resources/`

procd scripts (`#!/bin/sh /etc/rc.common`, `USE_PROCD=1`): `singbox.init`
(`sing-box run -c …`, respawn) and `kitewrt.init` (`python3 -m kitewrt`, with
`PYTHONPATH` + the `KITEWRT_*` env). The sing-box init no-ops until kitewrt has
written its config.

## Install / runtime layout

```
/usr/bin/sing-box                    static Go binary
/usr/lib/kitewrt/kitewrt/            daemon package
/usr/lib/kitewrt/vendor/             pip deps (PYTHONPATH)
/etc/kitewrt/data/                   state.json + metrics
/etc/sing-box/config.json            generated
/etc/sing-box/cache.db               remote rule-sets + selector choice
/etc/init.d/{singbox,kitewrt}        procd inits (enabled)
```

## Data flow examples

### Switching country (live, fast path)
UI → `POST /api/server` → state updated, `signal()` → pipeline →
`dataplane.apply`: structure unchanged + running → `clash.select(selector,
<tag>)`. No restart. Done in well under a second.

### Auto-selecting the fastest (live)
UI ⚡ → `POST /api/subscriptions/{id}/auto-select` → `ensure_materialized`
(reload only if stale) → delay-test every outbound through the proxy →
`select` the lowest-latency one + record the latencies as badges. No structural
reload in the common case.

### Toggling VPN off
`POST /api/toggle` (off) → state `vpn_on=False`, `signal()` →
`dataplane.apply`: `clash.select(selector, direct)`. The tun stays up; captured
LAN traffic just egresses unproxied.

### Editing the DoH URL (structural → reload)
`POST /api/dns/config` → state, `signal()` → `dataplane.apply`: structural key
changed → `write_config` + `service.restart()` (kill-switch-bracketed). The new
DoH upstream is live after the restart.

### Refreshing rules
`POST /api/rules/refresh` → fetch the rules URL, validate (`rules.py`), store →
structural reload. The DNS block is regenerated too (name rules mirror into DNS).

## Design decisions

- **sing-box tun + auto_route, not iptables capture.** OpenWrt + a modern
  sing-box do auto_route natively, so capture needs no hand-rolled
  REDIRECT/TPROXY chains — simpler, fewer moving parts, fail-closed via
  `strict_route`.
- **One engine, not two.** sing-box has the tun, the routing brain, DNS, and the
  Clash API for live switching — there is no second process to keep in sync. An
  earlier out-of-home phone-inbound (a separate xray process for its XHTTP
  transport) was removed: it added a process, a firewall route-fix, and WAN
  exposure for a feature mobile users already cover with their own client.
- **Live switch vs structural reload.** Keeps the common actions (country,
  on/off, auto-select) instant and side-effect-free, and confines the disruptive
  restart to rare structural edits.
- **Delay-test through the proxy, not just TCP-connect.** "Fastest" measures the
  end-to-end path a user's traffic takes, so a node that connects fast but
  proxies poorly scores honestly — the TCP probe ("Test") stays as the cheap
  reachability check.
- **Direct DNS is a user setting, not magic.** `direct_dns` is configurable
  (default Cloudflare), never the router's own resolver (that loops through the
  tun's `hijack-dns` and deadlocks). Region-specific GeoDNS is the user's choice
  — they set a regional resolver in the UI; we ship no region default. (An
  earlier auto-detect was removed: it once picked the router's own resolver,
  which 0-byte'd the VPN.)
- **Ships no servers/rules/geo data.** The engine is generic; the routing policy
  is a documented example preset, and geo data is a `type: remote` rule-set
  sing-box downloads itself.
- **No credentials on the router for runtime.** The installer needs the SSH
  password for its session only; the daemon makes no authenticated firmware
  calls. Uninstall scrubs the engine config.

## Out of scope (for now)

- **UI auth.** The web UI is unauthenticated, bound to the LAN — intentional for
  home use. Lock it down before exposing to untrusted networks.
- **nftables / fw4.** Targets OpenWrt 21.02's fw3 + iptables-legacy; the kill
  switch uses `iptables` (an `iptables-nft` shim would be needed on 22.03+). The
  sing-box tun data plane itself is firewall-agnostic.
- **`.ipk` packaging.** Currently deployed by the asyncssh installer; an opkg
  package is a possible future convenience.
