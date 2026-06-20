# KiteWrt

A self-hosted web UI on an **OpenWrt** router that turns a VLESS subscription into a transparent VPN for every device on the LAN. Pick a country, flip a switch, all your phones / laptops / TVs go through the chosen exit point — no per-device clients.

> **Tested on:** GL.iNet Flint 2 (GL-MT6000), OpenWrt 21.02 base / GL.iNet 4.x firmware, aarch64 (MediaTek Filogic 830), fw3 + iptables-legacy. Should work on any OpenWrt 21.02+ router with a roomy overlay (~140 MB free for python3, the deps, and the sing-box binary) and `kmod-tun`. See [Compatibility](#compatibility).

## ⚠️ Disclaimer

KiteWrt is a **generic management UI for sing-box** — it sets up the transparent-proxy plumbing and lets you point sing-box at a subscription (VLESS, Shadowsocks, VMess, Trojan, hysteria2/hysteria, TUIC) and your own routing rules. **It ships no servers, no routing/geo rules, and no block-lists** of any kind. You supply the VLESS subscription and the routing rules yourself (the rules can reference `type: remote` rule-sets that sing-box downloads at runtime — that data is never stored in or distributed by this project).

This is provided **as-is, with no warranty, for lawful purposes only**. You are solely responsible for how you use it and for complying with the laws and regulations that apply to you. Use at your own risk.

---

## Quick start

### Step 1 — Prepare the router (one-time, manual)

1. **Enable SSH/root access.** On GL.iNet: enable SSH in the admin UI (or LuCI → System → Administration) and set a root password. Verify with `nc -zv 192.168.8.1 22` (`succeeded`).
2. That's it — no USB drive, no firmware components, no reboot. The installer pre-flight confirms it's OpenWrt with `opkg`, and installs `kmod-tun` if the tun device is missing.

### Step 2 — Run the installer

From any machine with Python 3.9+ on the same LAN as the router:

```sh
git clone https://github.com/voledyaev/kitewrt.git
cd kitewrt
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[installer]"
kitewrt root@192.168.8.1
```

The installer asks for the SSH password once and uses it **only for the SSH session** that deploys everything. Nothing is stored on the router for runtime use — the daemon makes no authenticated calls back to the router firmware.

First run takes a few minutes (opkg `python3`, pip-installing the daemon's deps, fetching the sing-box binary). Subsequent runs (e.g. after pulling a new version) take ~30 seconds — they only redeploy the `kitewrt/` Python source.

What happens, in order:

| | Step | Notes |
|---|---|---|
| 1 | Pre-flight | Confirms OpenWrt + `opkg`, detects CPU arch (`uname -m`), ensures `kmod-tun` (`/dev/net/tun`). |
| 2 | python3 + pip | `opkg install python3 python3-pip`. |
| 3 | pip deps | `pip install --target=/usr/lib/kitewrt/vendor fastapi uvicorn websockets httpx pydantic`. |
| 4 | Install sing-box | Downloads the pinned **static Go** sing-box binary for the router's arch → `/usr/bin/sing-box` (or uses a pre-placed tarball from `installer/artifacts/` when GitHub is blocked — see below). Idempotent: skips if the right version is already there. |
| 5 | Deploy + init scripts | Pushes the `kitewrt/` package to `/usr/lib/kitewrt/`; installs procd `/etc/init.d/singbox` + `/etc/init.d/kitewrt` and enables them. |
| 6 | Firewall + start | Creates the fw3 tun zone (`singbox`, masq) + `lan→singbox` forwarding, then starts the daemon (polls `:8088` up to 15 s). |

KiteWrt installs **no geo data or block-lists** — see the disclaimer. Any country/geo split is opt-in: you supply routing rules referencing your own `type: remote` rule-sets, which sing-box downloads and caches at runtime.

**Behind a blocked GitHub / PyPI?** Steps 3–4 fetch from PyPI and GitHub *on the router*. If your ISP blocks them there, pre-download the sing-box release tarball (and optionally the pip wheels) on a machine that can reach them, drop them into `installer/artifacts/`, and re-run — the installer detects and uses them instead of fetching, no auto-bundling. See [`installer/artifacts/README.md`](./installer/artifacts/README.md) for the exact filenames.

### Step 3 — Connect

Open **`http://192.168.8.1:8088/`** in any browser on the LAN.

1. Paste your **VLESS subscription URL** (the standard base64-encoded list of `vless://` lines most providers serve at a per-user URL). You can also add an inline `vless://...` link directly.
2. Optionally paste a **routing-rules URL** — JSON in [sing-box's native route-rule format](./docs/rules-format.md). Without one, all traffic goes through the VPN — only private/LAN networks stay direct (required so the router and local devices stay reachable). Fine to start without it. An annotated example showing the format (a few domains + your home country direct, the rest via VPN) ships at [`examples/rules-example.json`](./examples/rules-example.json) — adapt it, host it somewhere reachable, and point the rules URL at it.
3. Pick a country.
4. Flip the **VPN** switch on. Every device on the LAN now exits through the chosen server, with foreign-domain DNS resolved over encrypted DoH through the tunnel (Cloudflare by default — editable) and home/local domains resolved directly.

---

## Using the UI

| Action | What it does |
|---|---|
| **Pick a different country tile** | Switches the active server **live** via sing-box's Clash API — no process restart. Connections to the old server drain. Usually sub-second. |
| **VPN toggle on** | Points sing-box's selector at the chosen server. A live Clash API switch when the config structure is unchanged; the first time (or after a structural change) it's a config reload + restart, bracketed by a fail-closed kill switch. |
| **VPN toggle off** | Points the selector at `direct` — a live switch. The tun stays up; LAN traffic just egresses unproxied. |
| **Edit DoH URL** | The DoH endpoint sing-box uses to resolve **foreign** domains (home/local resolve direct). Saving regenerates the config and reloads. |
| **Refresh / add subscription** | Re-fetch a subscription, or add another (URL or inline `vless://`). Multiple subscriptions coexist. Every subscription is also auto-refreshed in the background (~6 h), so a provider rotating its servers shows up without a click. |
| **Test a subscription** | TCP-latency probe per server (handshake to the server edge) — a quick "which exits are reachable" check. |
| **⚡ Fastest** | Delay-tests every server in a subscription *through the proxy* (the full ISP→server→internet round-trip), then switches to the lowest-latency one. More honest than Test: it measures the path your traffic actually takes, so a node that connects fast but proxies poorly scores low. |
| **Set / refresh / reset rules** | Validate + apply a sing-box route-rules URL; reset clears it back to all-traffic-through-VPN (private/LAN direct). |
| **Dashboard** (VPN on) | Live throughput + totals, connection count (VPN vs direct), sing-box memory, 30 s traffic/memory/connection sparklines, top flows by host (with tcp/udp type), and a **per-device** breakdown — which LAN client is using how much. |

The UI polls every 10 s (1.5 s while an apply is in flight) and takes a live `/ws` push feed, so changes made from another device show up automatically.

---

## What's running on the router

```
/usr/bin/sing-box              the sing-box Go binary (single data-plane process)
/usr/lib/kitewrt/
├── kitewrt/                   the Python package (the daemon)
└── vendor/                    pip deps (FastAPI, uvicorn, httpx, pydantic, websockets)
/etc/kitewrt/
└── data/                      state.json (atomic) + metrics
/etc/sing-box/
├── config.json                the full config kitewrt generates
└── cache.db                   downloaded remote rule-sets + selector choice
/etc/init.d/{singbox,kitewrt}  procd init scripts (both enabled)
```

Two persistent processes: `sing-box` (proxy + DNS + routing) and `python3 -m kitewrt` (UI + apply pipeline + watchdog). Capture is a single sing-box `tun` inbound with `auto_route` + `strict_route` — sing-box installs the policy routes that pull forwarded LAN traffic into the `singtun` device. An fw3 zone gives the tun masquerading + `lan→singbox` forwarding. No iptables capture chains, no transparent-proxy port.

The split between the two kinds of change is the core of the design:

- **Server switch / VPN on-off** is a *live* Clash API call (`PUT /proxies/<selector>`) — sing-box just repoints its `selector` outbound. No restart, no firewall churn, existing connections drain gracefully.
- **Structural change** (the *set* of servers, the routing rules, or the DoH URL) regenerates `config.json` and restarts sing-box. The restart briefly drops the tun, so it's bracketed by a fail-closed `FORWARD -o <wan> -j DROP` kill switch.

A **watchdog** coroutine checks sing-box health every 30 s (process up **and** Clash API responding). procd also supervises sing-box with `respawn`. A crash is fail-closed: `strict_route` leaves captured traffic with no working tunnel, so it's dropped rather than leaked.

For the deeper architecture, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Notes & gotchas

**No credentials stored on the router.** The installer needs your SSH password for the session it runs from your laptop, but does **not** write it to the router. The daemon makes no authenticated firmware calls at runtime.

**DNS is split, with fake-IP for foreign domains.** *Foreign* (proxy-routed) A/AAAA lookups get an instant **fake IP** (`198.18.x`) — the real resolution happens at the proxy exit (correct CDN, no ISP visibility), so page/video startup never waits on DNS. The rarer non-A/AAAA foreign queries (HTTPS/SVCB, TXT) go over **DoH** through the tunnel. *Direct* (home/LAN/RU) domains resolve via a plain **Direct DNS** resolver on the direct path. The Direct DNS must not be the router's own resolver (it loops through the tunnel) — set it to a regional resolver if you rely on region-specific GeoDNS.

**QUIC flows through the tunnel.** The `mixed` tun stack relays UDP via gvisor, so QUIC/HTTP3 (UDP/443) works end-to-end. (The `system` stack didn't relay UDP, which is why older builds blocked UDP/443 and fell apps back to HTTP/2 over TCP — that reject rule is no longer needed.)

**Devices with their own VPN client bypass us.** An on-device Shadowrocket/WireGuard wraps traffic before it reaches the router; only that tunnel's exit IP shows up. Disable the on-device client to test the router VPN there.

**Rules use sing-box's native route-rule JSON.** No proprietary DSL. The validator accepts `{"route": {"rules": [...]}}`, the `{"rules": [...]}` shorthand, or a bare `[...]` array, with `outbound` of `proxy`/`direct`/`block`. Pasted-in xray rules are rejected with a pointer to the new shape. See [docs/rules-format.md](./docs/rules-format.md).

**Local trust model.** The web UI is unauthenticated and bound to the LAN. Anyone on the LAN can flip the VPN. Intentional for home use — lock it down before exposing to untrusted networks.

**fw4/nftables (22.03+).** KiteWrt was built on 21.02's fw3 + iptables-legacy but also runs on 22.03+ fw4/nftables (verified): the uci zone applies via nftables, the installer uses the backend-agnostic `/etc/init.d/firewall reload`, and the kill switch goes through the `iptables-nft` compat shim 22.03 ships. The one caveat: the router-origin MSS clamp is a shell-script firewall include that fw3 runs but fw4 doesn't, so on a pure-fw4 router it silently doesn't apply (the VPN still works; only router-origin PMTU on a constrained upstream is affected). See [docs/openwrt-notes.md](./docs/openwrt-notes.md).

---

## Uninstall

```sh
kitewrt --uninstall root@192.168.8.1
```

End state:

**Removed / reverted:**
- Daemon stopped + disabled; `/usr/lib/kitewrt/` removed; init scripts removed.
- sing-box stopped (tun + auto_route rules disappear, in-memory credentials dropped).
- `config.json` overwritten with a credential-free config (selector points only at `direct`) — **no VLESS UUID, server hostname, Reality SNI, or custom rules left on disk.**
- fw3 sections (tun zone, forwarding) removed and `fw3 reload`ed.

**Intentionally left in place:** `python3`, the pip deps, and the `/usr/bin/sing-box` binary (they survive a re-install; other tooling may depend on python3). Also the BBR congestion-control setting (`/etc/sysctl.d/99-kitewrt-bbr.conf` + `/etc/modules.d/99-kitewrt-tcp-bbr`) — it's a fine system-wide default and removing it could change unrelated TCP behavior; delete those two files by hand if you want cubic back.

---

## Development

```sh
git clone https://github.com/voledyaev/kitewrt.git
cd kitewrt
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,installer]"
pytest tests/                       # ~365 tests, ~5s
kitewrt --probe root@192.168.8.1     # connectivity + state check, no changes
```

The web UI is a React + Vite SPA under `web/`. Its build output is committed to
`kitewrt/static/` so the router install needs no Node — but if you change the
UI, rebuild and commit the result (CI fails if it's stale):

```sh
cd web
npm install
npm run build          # → ../kitewrt/static/
npm run dev            # HMR dev server, proxies /api + /ws to a running daemon
```

To preview locally without a router, run the daemon against a scratch dir:

```sh
KITEWRT_BASE_DIR=/tmp/kitewrt-dev KITEWRT_LISTEN=127.0.0.1:8088 python -m kitewrt
```

Project layout:

```
kitewrt/         # the daemon package (FastAPI, asyncio, Pydantic)
  singbox/      #   sing-box config builder, Clash API client, service control
  static/       #   built web UI (generated from web/ — do not hand-edit)
web/            # web UI source (React + Vite + Tailwind + daisyUI)
installer/     # the Mac/Linux-side installer (asyncssh)
tests/          # unit tests
docs/           # supplementary docs (OpenWrt notes, VLESS / rules formats)
```

---

## Compatibility

**Tested on.** GL.iNet Flint 2 (GL-MT6000, aarch64, OpenWrt 21.02 base, 1 GB RAM, ~6 GB overlay).

**Requirements:**

- OpenWrt **21.02+** (incl. GL.iNet firmware), with `opkg`, `fw3`, `uci`.
- `kmod-tun` (`/dev/net/tun`) — built in on most images; the installer installs it if missing.
- Enough free overlay for python3 + the pip deps + the sing-box binary (~140 MB; the installer pre-flights this). Small-flash (8/16 MB) devices won't fit python3.
- ≥ 256 MB RAM (sing-box + python3 + uvicorn run ~80 MB resident).
- CPU arch: `aarch64`, `x86_64`, or `armv7` (auto-detected via `uname -m`; sing-box ships a static Go build per arch).

**Caveats:**

- **fw4/nftables (OpenWrt 22.03+):** supported via the `iptables-nft` compat shim 22.03 ships + the backend-agnostic firewall reload; the only gap is the router-origin MSS clamp (an fw3 shell-include that fw4 doesn't run).
- **pydantic-core (Rust wheel):** pip resolves the `musllinux` aarch64 build on the router. An arch without a musllinux wheel would try to build from source and fail.

---

## Project docs

- [ARCHITECTURE.md](./ARCHITECTURE.md) — components, data flow, design decisions
- [docs/openwrt-notes.md](./docs/openwrt-notes.md) — OpenWrt / fw3 / procd platform notes
- [docs/vless-format.md](./docs/vless-format.md) — subscription / VLESS link parsing reference
- [docs/rules-format.md](./docs/rules-format.md) — accepted sing-box routing-rules JSON format
- [examples/rules-example.json](./examples/rules-example.json) — annotated routing-rules example

---

## License

[MIT](./LICENSE) © voledyaev
