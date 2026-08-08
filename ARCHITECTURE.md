# Architecture

KiteWrt turns a VLESS subscription into a transparent, per-country VPN for a
whole LAN, managed from a web UI, on an OpenWrt router. This document describes
how the pieces fit together and why.

For installing it, see the [README](./README.md); for driving it,
[docs/using-the-ui.md](./docs/using-the-ui.md); for the OpenWrt-specific facts
that keep biting, [docs/openwrt-notes.md](./docs/openwrt-notes.md).

## Overview

```
┌─ Mac / Linux (install-time only) ──────────────────────┐
│  kitewrt — Python installer (asyncssh).                │
│  SSH (root) → opkg python3, uv-installed deps,         │
│  fetch sing-box,                                       │
│  deploy kitewrt/, write procd inits, set the fw3 MSS   │
│  clamp + IPv6 blocks, start the daemon.                │
└────────────────┬───────────────────────────────────────┘
                 │ SSH :22 (plain shell, real exit codes)
                 ▼
┌─ OpenWrt router (runtime) ─────────────────────────────┐
│                                                         │
│  python3 -m kitewrt  (procd, :8088)                    │
│    FastAPI UI + apply pipeline + watchdog               │
│    │ writes config.json, drives the Clash API          │
│    ▼                                                    │
│    ▼ installs the netfilter capture (kitewrt/divert.py) │
│  mangle/PREROUTING → TPROXY :7895                       │
│    ▲                                                    │
│  sing-box  (procd)                                      │
│    tproxy inbound — kernel hands it ready sockets       │
│    selector / DNS / route                               │
│    ▲                                                    │
│    └──── LAN devices (phones / laptops / TVs) ──────────┘
└─────────────────────────────────────────────────────────┘
```

One long-lived process does the data-plane work:

- **sing-box** — the proxy/DNS/routing brain. A `tproxy` inbound receives LAN
  traffic that the daemon's own netfilter capture steers to it; a `selector` outbound picks
  the active server — any parsed protocol (VLESS / Shadowsocks / VMess / Trojan
  / hysteria2 / hysteria v1 / TUIC) or `direct`; the route block applies the
  routing split; the DNS block fake-IPs foreign A/AAAA names (instant; the real
  lookup happens at the proxy exit), sends the rarer non-A/AAAA foreign queries
  over DoH-through-the-proxy, resolves direct-routed home-region names via the
  configurable Direct DNS, and resolves `*.lan` / `localhost` on the router's own
  resolver (so LAN hosts stay reachable by name).

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
  URL. These regenerate `config.json` and restart sing-box. The capture stays
  installed across the restart, and TPROXY with no listener drops rather than
  falling through, so the reload window is fail-closed on its own — there is no
  kill-switch bracket around a restart any more (see [Kill switch](#kill-switch--kitewrtkillswitchpy)).

Everything else is a thin layer over those two. A subscription refresh that
changes the *active* server's list is structural (the outbound set changed); a
refresh of a background subscription touches nothing live until the user selects
from it. Auto-select is purely live once the servers are materialized — it
delay-tests each outbound and `select`s the winner.

## Capture: a hand-managed TPROXY divert

sing-box listens on a `tproxy` inbound, and `kitewrt/divert.py` owns the
netfilter + policy-routing plumbing that steers LAN traffic to it:

```jsonc
{ "type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 7895 }
```

```
mangle/PREROUTING ──jump──▶ kitewrt_tproxy
                              -i lo                  → RETURN   (router's own DNS)
                              -i <each uplink>       → RETURN   (or TPROXY eats the WAN)
                              tcp/udp --dport 53     → TPROXY   (before the escapes!)
                              -d <reserved ranges>   → RETURN   (LAN-to-LAN, router UI)
                              -m set kitewrt_bypass  → RETURN   (optional fast path)
                              tcp/udp                → TPROXY :7895 --tproxy-mark 0x2023
                              (anything left)        → DROP     (TPROXY carries only tcp/udp)
filter/INPUT  position 1      -m mark 0x2023         → ACCEPT   (before syn_flood)
ip rule       fwmark 0x2023   lookup 2023
table 2023                    local default dev lo
```

**Why not tun.** Measured in a controlled lab (OpenWrt 21.02, same kernel as
the target router; iperf3, client→router→server, two runs each):

| inbound | throughput | vs. plain forwarding |
|---|---|---|
| plain kernel forwarding | 5.98 / 6.42 Gb/s | 100% |
| tun, `stack: mixed` | 185 / 187 Mb/s | 3% |
| tun, `stack: gvisor` + mtu 9000 | 1.10 / 1.17 Gb/s | 18% |
| **tproxy** | **3.54 / 3.34 Gb/s** | **56%** |

Same binary, same outbound, same traffic — only the inbound differs. A tun
hands up raw IP packets, so the proxy must run a TCP stack in userspace (one
fd, one reader goroutine, gvisor's state machine). TPROXY lets the kernel own
TCP and hands over an established socket.

**Ordering is load-bearing**, and every line above was paid for:

- The rules go in only after sing-box is confirmed listening, and come out
  before it stops. TPROXY with no listener does not fall through — it
  black-holes TCP while ICMP keeps working, which looks exactly like "the
  internet broke but the router still pings".
- They deliberately *stay* installed across a sing-box restart, which makes
  the reload window fail-closed for free — the property `strict_route` used to
  provide.
- `-i lo` first: router-origin traffic takes OUTPUT and is never captured, but
  loopback packets do traverse PREROUTING. Without the escape, the router's own
  DNS to 127.0.0.1 is answered with a fake IP, and sing-box's `dns-local`
  resolves through `/etc/resolv.conf` — straight back in.
- Uplinks next: mangle/PREROUTING runs before reverse-NAT, so a captured
  uplink's return packets carry the router's *public* address and no
  private-range escape catches them. Capturing the WAN kills the WAN.
- DNS before the reserved ranges: LAN clients are handed the router as their
  resolver over DHCP, so queries go to a private address. Escapes first and
  every query falls through to dnsmasq and out to the ISP — no fake-IP, no
  error anywhere.
- 198.18.0.0/15 is deliberately *not* escaped: that is the fake-IP range, and
  those connections must reach sing-box to be mapped back to a domain.
- The terminating `DROP` is last, so it only sees what the chain already
  declined to capture *and* declined to let go — i.e. everything that is neither
  TCP nor UDP, which TPROXY has no target for. Without it, ICMP, GRE (47), ESP
  (50), 6in4 (41) and SCTP (132) were measured reaching the far side in the clear
  with the VPN reported on. It costs nothing measurable, and its counter stayed
  at 0 under every TCP/UDP load. Consequence: with the VPN on, pinging a proxied
  address fails while pinging a bypassed one still works.

**What this does not recover.** Anything the proxy terminates locally leaves
netfilter's `forward` chain, so hardware flow offload (MediaTek PPE and
friends) can never bind it — true of tun, tproxy and redirect alike. Traffic
you want offloaded has to RETURN before the TPROXY rules, which is what
`bypass_address` and the `kitewrt_bypass` ipset are for: one `-m set` match is
one `hash:net` lookup whose cost does not grow with the number of entries (8,639 -> 50,000 is flat) but does scale with the number of *distinct prefix lengths* in the set: measured on a 5.4 kernel, ~710 ns fixed plus ~66 ns per distinct length, so 14 lengths cost 1,635 ns for a non-member and one length costs 790 ns. Every proxied packet pays the full scan; a bypassed one stops early. On real GSO-aggregated TCP the whole effect is +4.5% router CPU per gigabyte versus a plain CIDR match. The tun-era `route_exclude_address_set`
expressed the same intent by expanding a geo set into one kernel route per
prefix — 21,619 of them on a real router, which took it down.

The daemon owns this chain, not the installer: it is runtime state that a
`/etc/init.d/firewall restart` flushes, so the watchdog re-asserts it every
tick. The installer's fw3 work is only an MSS clamp and two IPv6 blocks.

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
| `singbox/config.py` | Pure builder: state → sing-box config dict (tproxy + loopback-proxy inbounds, selector, outbounds, route, dns, clash api). |
| `singbox/route.py`, `dns.py`, `outbound.py` | Route-rule, DNS-block, and proxy-outbound builders (vless / ss / vmess / trojan / tuic / hysteria(2)). |
| `singbox/service.py` | sing-box process control (procd) + atomic config write. |
| `singbox/clash.py` | Clash API client (live selector switch, URL delay-test, proxy list, health, connections/metrics). |
| `rules.py` | Validate/normalise user routing-rules JSON (sing-box-native). |
| `vless.py`, `fetch.py` | Subscription parsing (all node schemes) + fetching with the SSRF guard. |
| `killswitch.py` | Fail-closed FORWARD DROP for the boot window, before the capture exists. |
| `watchdog.py` | Supervise sing-box, re-assert the capture and the selector, probe the exit path. |
| `hub.py`, `metrics_store.py` | WS broadcaster + server-side metrics history. |
| `routes/` | FastAPI routers (subscriptions, server, vpn, dns, rules, metrics, ws, meta, connectivity, exit_ip). |

### State — `data/state.json`

The `Data` model is the single source of truth: subscriptions (+ parsed
servers), the active-server reference, `vpn_on`, routing rules (+ rule-set
defs), DNS config, and the latest per-server ping results. Writes are durable
(tmp → fsync → atomic rename → dir fsync), so an unclean power-off can't zero out
state; listeners fan changes out to the WS hub. The generated sing-box
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

### Delay-testing and auto-select — `kitewrt/autoselect.py`

Both `POST /api/subscriptions/{id}/test` ("Test") and
`POST /api/subscriptions/{id}/auto-select` ("⚡ Fastest") run the *same*
measurement: sing-box opens a real connection through each outbound and times an
HTTP-204 round-trip, so the score reflects the full ISP→server→internet path,
not just reachability to the server edge. There is no separate router-side TCP
probe — the two routes differ only in what they do with the result. `/test`
records the latency badges and nothing else; `/auto-select` also makes the
fastest node the active server (a live `select`, like a manual pick).

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

A React + Vite SPA (TypeScript, Tailwind CSS + daisyUI for the component set; no
charting library — the charts were removed along with the ApexCharts dependency,
and `web/package.json` now carries only react, react-dom and daisyui). The
source lives in `web/`; `npm run build` emits the bundle into `kitewrt/static/`,
which is committed so the router install needs no Node toolchain (CI rebuilds and
fails if the committed output drifts). `npm run test` runs the vitest suite
(`health.test.ts`, `format.test.ts`). It consumes the `/ws` push channel for
instant state + ~1/s metrics, with `/api/state` + `/api/metrics` polling as a
fallback when the socket is down. The dashboard renders current-and-30s-peak
tiles for WAN throughput, router CPU and memory (the server-side history is what
the peak is computed from, not a plotted series), top flows by host (with tcp/udp
type and whether each took the tunnel), and a per-device (source-IP) traffic
rollup.

### Apply pipeline — `kitewrt/apply.py`

A single background worker consumes "apply" signals. Mutating routes update
state, set `applying=True`, and `signal()` the pipeline; the worker coalesces
bursts and calls `dataplane.apply(snapshot)`. Serialising here means concurrent
edits can't race the engine.

### Watchdog — `kitewrt/watchdog.py`

Every 30 s it reads the capture state first and publishes it, so the UI can tell
"the VPN is on" from "traffic is actually being captured". Then, if sing-box is
healthy (process up **and** Clash API responding — a wedged-but-alive sing-box
counts as down) and `vpn_on`, it re-asserts the capture, re-asserts the selector
if sing-box drifted off the intended outbound, and delay-probes the active node's
real exit path. After two consecutive down ticks (debounce) it restarts via the
service. procd's `respawn` also covers hard crashes; the watchdog adds the
wedged-control-plane case, the flushed-capture case and the
selector-on-the-wrong-outbound case.

Two branches exist for states the VPN switch alone cannot describe. With the VPN
*off* but the capture gone and sing-box still running, it recycles the process
once — re-asserting the capture was measured not to clear sing-box's stale
transparent UDP sockets, which black-hole LAN DNS. And when sing-box has failed
to restart `_GIVE_UP_AFTER` times *with the VPN off*, it removes the capture, so
a dead listener does not hold the LAN hostage.

`process_alive()` is checked against the pidfile procd maintains for our own init
script, with `kill -0` on the pid; `pidof sing-box` is only a fallback for an
install that predates the pidfile. Matching by name alone made a second sing-box
on the router (a lab exit node) read as ours.

### Kill switch — `kitewrt/killswitch.py`

Mostly retired by the move to TPROXY. The divert stays installed across a
sing-box restart, and TPROXY with no listener drops rather than falls through,
so the reload window is fail-closed on its own. The `FORWARD -o <wan> -j DROP`
bracket now covers only the boot window, before the capture exists at all —
the one span where LAN traffic really could take the direct route.

### Installer — `installer/` package

A Mac/Linux-side asyncssh tool. `Router` runs commands over one SSH connection
with real exit codes and uploads files as raw bytes over stdin (dropbear ships
no SFTP; base64 would need a decoder the router may not have). Steps: preflight
(OpenWrt + opkg, arch via `uname -m`, a real TPROXY-target probe, an `-m set`
probe, an `ip rule … lookup 2023` probe, BBR) → opkg python3, then a pinned uv
downloaded to the router installs the deps from the hashed
`installer/resources/requirements.txt` into `/usr/lib/kitewrt/vendor` → fetch
the sing-box binary (SHA-256 pinned; dynamically glibc-linked on x86-64 and
aarch64, so a musl box gets a loader shim — the armv7 build has no `PT_INTERP`
at all and needs none) → deploy `kitewrt/` to `/usr/lib/kitewrt` → install procd inits + the
`keep.d` entry → fw3 MSS clamp + IPv6 blocks → start. Idempotent, but only
sing-box is genuinely *skipped* on a re-run — the dependency install repeats
every time (`--no-cache`), so a re-run is ~a minute, not seconds.

For a router whose ISP blocks GitHub/PyPI, the installer first checks an
*artifacts dir* (`installer/artifacts/`, overridable with `--artifacts-dir`):
drop the pre-downloaded sing-box **and uv** release tarballs (and optionally
wheels) there and it uploads + installs them offline instead of fetching.
Nothing is auto-bundled — it just checks for the files and falls back to
downloading when absent.

### Init scripts — `installer/resources/`

procd scripts (`#!/bin/sh /etc/rc.common`, `USE_PROCD=1`): `singbox.init`
(`sing-box run -c …`, respawn) and `kitewrt.init` (`python3 -m kitewrt`, with
`PYTHONPATH` + the `KITEWRT_*` env). The sing-box init no-ops until kitewrt has
written its config.

## Install / runtime layout

```
/usr/bin/sing-box                    the sing-box Go binary (glibc-linked on x86-64/aarch64)
/usr/lib/kitewrt/kitewrt/            daemon package
/usr/lib/kitewrt/vendor/             locked deps, uv-installed (PYTHONPATH)
/etc/kitewrt/data/                   state.json + metrics (the only copy of the subs)
/etc/kitewrt/mss-clamp.sh            fw3 firewall include
/etc/sing-box/config.json            generated
/etc/sing-box/cache.db               remote rule-sets + selector choice
/etc/init.d/{singbox,kitewrt}        procd inits (enabled)
/lib/upgrade/keep.d/kitewrt          carries /etc/kitewrt across a sysupgrade
```

Uninstall removes `/usr/lib/kitewrt` (vendor included) **and `/etc/kitewrt`** —
i.e. the subscriptions and their credentials. That is intentional: uninstall's
contract is that no credentials are left on disk.

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
`dataplane.apply`: `clash.select(selector, direct)`, then `ensure_capture()`.
The capture stays installed and sing-box keeps terminating the connections — it
just dials them out through its `direct` outbound instead of the proxy server.
Tearing the capture down instead would strand the fake IPs sing-box has already
handed out for up to their 600 s TTL.

The one exception is the *hybrid* state — sing-box running with no capture, which
our own shutdown produces. There `apply` restarts sing-box rather than merely
re-selecting: its transparent UDP sockets stay bound to the LAN resolver address
and swallow client DNS that dnsmasq would have answered, and re-asserting the
capture over them was measured not to clear it. Only recycling the process does.

### Editing the DoH URL (structural → reload)
`POST /api/dns/config` → state, `signal()` → `dataplane.apply`: structural key
changed → stage + `sing-box check` + promote + `service.restart()`, with the
selector re-asserted in the restart's `after` hook before it reports success.
The capture stays up throughout, so the window drops rather than leaks. The new
DoH upstream is live after the restart.

### Refreshing rules
`POST /api/rules/refresh` → fetch the rules URL, validate (`rules.py`), store →
structural reload. The DNS block is regenerated too (name rules mirror into DNS).

## Design decisions

- **TPROXY, not a tun.** The tun was simpler — sing-box installed the capture
  itself via `auto_route`, no hand-rolled chains — and it cost throughput at
  every tuning it was ever run at: 19x against the original `stack: mixed`
  (185 Mb/s), and still 3x against the `stack: gvisor` + mtu-9000 build that was
  actually in place when the migration happened (1.10 Gb/s vs 3.54). A tun hands
  up raw IP packets, so the proxy runs a TCP stack in userspace; TPROXY lets the
  kernel own TCP. Owning the chain ourselves is the price, and it bought back the
  fail-closed property for free: TPROXY with no listener drops.
- **One engine, not two.** sing-box has the transparent-proxy inbound, the
  routing brain, DNS, and the
  Clash API for live switching — there is no second process to keep in sync. An
  earlier out-of-home phone-inbound (a separate xray process for its XHTTP
  transport) was removed: it added a process, a firewall route-fix, and WAN
  exposure for a feature mobile users already cover with their own client.
- **Live switch vs structural reload.** Keeps the common actions (country,
  on/off, auto-select) instant and side-effect-free, and confines the disruptive
  restart to rare structural edits.
- **Delay-test through the proxy, and nothing else.** Both "Test" and "Fastest"
  measure the end-to-end path a user's traffic takes, so a node that connects
  fast but proxies poorly scores honestly. The cheap router-side TCP-connect
  probe was dropped rather than kept alongside: it could not reach the UDP/QUIC
  protocols (hysteria2 / hysteria v1 / tuic) at all, so those nodes always read
  as down.
- **Direct DNS is a user setting, not magic.** `direct_dns` is configurable
  (default Cloudflare) and should not be the router's own resolver. Under the
  tun that was a hard deadlock — dnsmasq's upstream queries were re-hijacked by
  `hijack-dns` back into sing-box — and that mechanism is gone: the capture hooks
  PREROUTING only, and dnsmasq's upstream traffic is router-origin, so it takes
  OUTPUT and is never captured. **Whether the loop still reproduces under TPROXY
  has not been re-tested**; the advice stands on the remaining reason, which is
  that routing regional lookups back through the router's own forwarder just
  hands them to the ISP resolver and defeats the point of setting a regional one.
  Region-specific GeoDNS is the user's choice — they set a regional resolver in
  the UI; we ship no region default. (An earlier auto-detect was removed: it once
  picked the router's own resolver, which 0-byte'd the VPN.)
- **Ships no servers/rules/geo data.** The engine is generic; the routing policy
  is a documented example preset, and geo data is a `type: remote` rule-set
  sing-box downloads itself.
- **No credentials on the router for runtime.** The installer needs the SSH
  password for its session only; the daemon makes no authenticated firmware
  calls. Uninstall scrubs the engine config.

## Out of scope (for now)

- **UI auth.** The web UI is unauthenticated, bound to the LAN — intentional for
  home use. Lock it down before exposing to untrusted networks.
- **A capture flushed between watchdog ticks.** On fw3, `/etc/init.d/firewall
  restart` wipes the mangle table and the LAN is unproxied until the next tick —
  measured at up to 34.4 s and 15,839 plaintext packets, with the dashboard
  reading CAPTURED throughout because the reading was *fresh evidence of a state
  that had already changed*. There is no netfilter change notification to
  subscribe to, and a 5 s poll measured ~18% of an A53 core, so this is a
  recorded bound rather than a solved problem. See
  docs/measured-facts.md. (Rarer on fw4, where a `firewall restart` does not
  flush `table ip mangle`.)
- **`.ipk` packaging.** Currently deployed by the asyncssh installer; an opkg
  package is a possible future convenience.
