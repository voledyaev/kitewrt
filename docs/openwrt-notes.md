# OpenWrt platform notes

Reference notes for running kitewrt on OpenWrt. Validated on a GL.iNet Flint 2
(GL-MT6000, MediaTek Filogic 830 / MT7986 quad-core Cortex-A53, OpenWrt 21.02
base / GL.iNet 4.x firmware, fw3 + iptables-legacy, ~6 GB overlay, 1 GB RAM),
and on the stock-OpenWrt targets in the table below. Updated 2026-08.

## Hardware / firmware compatibility

kitewrt is firmware-driven, not model-driven. It should work on any OpenWrt
router that satisfies:

- **CPU**: aarch64 / x86_64 / armv7. The installer detects via `uname -m` and
  fetches the matching sing-box release (one Go binary per arch). That binary is
  glibc-linked, so on a musl-only OpenWrt the installer adds a loader shim
  (symlink the musl loader to the glibc loader path the binary requests) — a
  no-op on GL.iNet firmware, which ships a glibc-compat layer.
- **OpenWrt 21.02+** (incl. GL.iNet firmware), with `opkg`, `fw3`, `uci`.
- **The iptables TPROXY target** (`iptables-mod-tproxy`, or built into the
  kernel). The installer probes it by adding a real rule, not by asking opkg —
  a module can be built in with no package, and a package can be installed
  whose module won't load. A missing target is a hard stop.
- **Full iproute2 (`ip-full`).** busybox's built-in `ip` applet caps route-table
  IDs at 255 and the capture needs table 2023, so this is a hard requirement,
  not a nicety. Probed the same way — by adding a real `ip rule … lookup 2023` —
  and a hard stop if it cannot be installed, because the install otherwise
  succeeds end to end and nothing is ever proxied. GL.iNet firmware already
  ships it, which is why this went unnoticed for months.
- **Optional: `ipset` + the `xt_set` match**, for `bypass_address`. Probed the
  same way. Absent, the capture works and the bypass just does nothing.
- **≥ 256 MB RAM** and **enough free overlay for python3 + the python deps +
  the sing-box binary** (~140 MB; the installer pre-flights this). sing-box +
  uvicorn run ~80 MB resident. Small-flash devices
  (8/16 MB) won't fit python3 — kitewrt targets routers with a roomy overlay
  (the Flint 2 has ~6 GB).

> **fw4/nftables (OpenWrt 22.03+):** kitewrt was built on 21.02's fw3 +
> iptables-legacy and **also runs on 22.03+ fw4/nftables**. Measured on a stock
> 22.03.6 x86-64 box with no iptables at all: install 140 s, exit 0; the
> pre-flight's `opkg install iptables` pulls `xtables-nft-multi`; the capture
> installs; and a LAN client got HTTP 200 through the tunnel via a fake IP, with
> the TPROXY counter moving and the exit node logging the connection. The three
> uci rules land in the nft ruleset.
>
> Three caveats this file used to state as verified were **measured false** on
> that box, and are corrected here rather than deleted, because they read as
> facts and were not:
>
> - The router-origin MSS clamp *does* apply. It is a `config include` script,
>   and firewall4 runs those — flushed and reloaded, the rule came straight back
>   into `mangle/POSTROUTING`.
> - `iptables-mod-tproxy` *does* exist in the 22.03 feed and is what the
>   pre-flight installs (`iptables-mod-tproxy - 1.8.7-7`).
> - A `firewall restart` does *not* take the capture with it. fw4 rebuilds only
>   `table inet fw4`; the capture lives in `table ip mangle`, and the chain, the
>   PREROUTING jump and the `ip rule` all survived.
>
> There is also no uci *zone* — `setup_firewall` deletes the tun-era
> `kitewrt_singbox` / `kitewrt_lan2singbox` sections on every install.
>
> **The real fw4 friction is timing.** On 22.03 the first apply failed twice
> over roughly three minutes (`sing-box is not listening on tproxy port 7895`)
> before settling, against ~15 s on 21.02. The watchdog carries it and the
> dashboard correctly reads "not captured" throughout — but expect a red
> dashboard for a few minutes after the first install on 22.03.

## What has actually been run, and on what

Every row was installed from scratch with the real installer and then checked
**end to end** — a LAN client reaching the internet through the tunnel, with the
TPROXY counters moving and the exit node logging the connection. That distinction
matters here more than usual: this project once passed pre-flight 6/6 green and
reported a healthy daemon on a router where nothing was ever proxied, because
busybox's `ip` caps route-table IDs at 255 and only GL.iNet firmware ships full
iproute2. "The daemon is healthy" is not evidence.

| target | kernel | firewall | python | install |
|---|---|---|---|---|
| GL.iNet Flint 2, 21.02 base, aarch64 | 5.4 | fw3 | 3.9 | daily driver |
| stock 21.02.7, x86-64 | 5.4 | fw3 | 3.9 | 137 s |
| stock 22.03.6, x86-64 | 5.10 | fw4 | 3.10 | 140 s |
| stock 23.05.5, aarch64 | 5.15 | fw4 | 3.11 | 64 s |
| stock 24.10.0, aarch64 | 6.6 | fw4 | 3.11 | 55 s |
| stock 24.10.0, x86-64 | 6.6 | fw4 | 3.11 | 143 s |
| stock 24.10.0, **armv7** | 6.6 | fw4 | 3.11 | 2 m 57 s (emulated) |

Untested: mips/mipsel (those routers have 8–16 MB of flash and are excluded by
the ~140 MB requirement anyway), and any firmware other than stock OpenWrt or
GL.iNet's. **No armv7 run has happened on real hardware** — that row is
emulated, which is also why its install time is three times the others.

### Facts that differ per architecture

- **The sing-box release is dynamically linked on x86-64 and static on armv7.**
  x86-64 asks for `/lib64/ld-linux-x86-64.so.2` and will not start on musl
  without `ensure_loader_shim`; the armv7 build has no `PT_INTERP` at all and
  runs with the shim symlink moved aside. Do not conclude either way from
  whichever arch you happen to have — the comment in `parsers.py` claimed both,
  at different times, and both were wrong as a general statement.
- **`uname -m` does not name the musl loader.** armv7 reports `armv7l` while the
  loader is `/lib/ld-musl-armhf.so.1`, so an exact-form check reports glibc on a
  musl box.
- **The musllinux wheel tag is `musllinux_1_1`, not `_1_2`.** `pydantic-core` is
  the only compiled dependency, and it publishes `_1_1` for x86_64, aarch64 and
  armv7l and nothing newer.

### Facts about the tools, which are not the tools you think

- **`tar` is busybox, and busybox tar rewrites hostile member names itself.**
  It strips a leading `/` and resolves `..`, landing the file inside the
  extraction directory — and `tar tzf` prints the *already-rewritten* name, so a
  name-based guard on its output can never fire. bsdtar does neither: it lists
  and extracts those names verbatim. A guard written against one is inert on the
  other, and `tar` is whatever the router ships.
- **What busybox tar does honour is a link member.** A symlink named as the
  file you are about to extract survives, and a following `chmod +x`
  dereferences it — as root, across filesystems, onto a path the archive chose.
  Verified on 21.02.7. Check member *type*, not member name.
- **busybox `ip` caps route-table IDs at 255**, and the capture needs 2023.
  `ip-full` (iproute2) is a hard requirement, not a nicety; on GL.iNet firmware
  it is already there, which is why this went unnoticed for months.
- **busybox `command -v` takes exactly one argument.** `command -v a b c`
  reports only `a`, silently, with rc=0.
- **`/bin/sh` is ash.** Bash-isms fail, and macOS `/bin/sh` is bash, so a
  script tested on the admin machine proves nothing about the router. Test
  shell changes under `dash` at minimum.

### Facts that differ per OpenWrt version

- **21.02 ships Python 3.9; 22.03 ships 3.10; 23.05 and 24.10 ship 3.11.** The
  locked requirements carry `python_full_version` markers, so 3.9 takes one
  branch and everything newer takes another — an offline wheel bundle built for
  the wrong one is rejected as `unsatisfiable` (the installer then falls back to
  PyPI, which defeats the point of the bundle).
- **On 22.03+ `/sbin/fw3` is a symlink to fw4.** kitewrt takes its "fw3" path
  and it works, because fw4 accepts the fw3 UCI syntax — but any `command -v
  fw3` detection is a false positive there. (`--probe` resolves symlinks for
  exactly this reason, and prints `fw3: /sbin/fw3 -> fw4`.)
- **fw4 does run `config include` shell scripts** (the MSS clamp applies), and a
  `firewall restart` does **not** take the capture with it, because the capture
  lives in `table ip mangle` while fw4 rebuilds only `table inet fw4`. On fw3 a
  restart *does* flush it. Both measured.
- **`iptables-mod-tproxy` exists in the 22.03+ feeds** and is what the pre-flight
  installs, through the `iptables-nft` compat shim.
- **fw4 renders a UCI rule's `dest='wan'` as a jump into `drop_to_wan`**, a
  chain containing only the devices in the fw4 `wan` zone. When nothing is in
  that zone the chain is *empty* and the rule silently drops nothing — a stock
  armsr install ships exactly that. `dest='*'` renders as a flat rule in
  `forward`, ahead of the zone dispatch, and is the only form that does not
  depend on how the user assigned their interfaces. Config order is preserved,
  so an ACCEPT written before a DROP really does precede it.
- **The first apply after an install can take minutes on 22.03/24.10** (measured
  at ~80 s and ~3 min against ~15 s on 21.02) before the capture settles. The
  watchdog carries it and the dashboard correctly reads "not captured"
  throughout, but expect a red dashboard on first install.

## SSH access

OpenWrt SSH (dropbear) lands `root` in a normal POSIX shell with real exit
codes — no structured CLI, no `exec sh` wrapper. The installer (`installer/`,
run from your Mac) uses one persistent connection: `Router.run()` for commands,
and **raw bytes** over the command's stdin for file uploads (dropbear ships no
SFTP server by default). Not base64, which is what it used to be: that needs a
*decoder on the router*, and a stock OpenWrt x86 build has neither the busybox
`base64` applet nor `openssl`, so the install died at the first upload.

Enable SSH/root in the GL.iNet UI (Applications → … or LuCI) before installing.
At runtime the daemon needs **no** SSH or router API — it runs locally on the
router, generates `config.json`, and drives sing-box via the local Clash API
and the procd init script. SSH is install-time only.

## What the installer lays down

```
/usr/bin/sing-box              official sing-box binary, pinned version + pinned SHA-256
                               (dynamically glibc-linked on x86-64/aarch64 — the installer
                                shims the musl loader; the armv7 build is static)
/usr/lib/kitewrt/kitewrt/      the daemon package source
/usr/lib/kitewrt/vendor/       python deps (fastapi/uvicorn/httpx/pydantic/websockets)
/etc/kitewrt/data/             daemon state (state.json, metrics)
/etc/kitewrt/mss-clamp.sh      the fw3/fw4 `config include` script
/etc/sing-box/config.json      generated by kitewrt
/etc/sing-box/cache.db         downloaded remote rule-sets + selector choice
/etc/init.d/singbox            procd init (data plane)
/etc/init.d/kitewrt            procd init (the daemon, :8088)
/lib/upgrade/keep.d/kitewrt    carries /etc/kitewrt across a sysupgrade
```

python3 comes from opkg. The deps are installed by a **pinned uv**, downloaded to
`/tmp` (SHA-256 verified) and deleted afterwards — it is a build tool, not
runtime. There is no pip: uv installs into `/usr/lib/kitewrt/vendor` (`--target`,
no venv), put on `PYTHONPATH` by the init script.

> **Blocked GitHub / PyPI from the router?** *Three* downloads happen on the
> router: sing-box and **uv** (both GitHub) and the wheels (PyPI). Pre-download
> them on a machine that can reach them and drop them into
> `installer/artifacts/` — the sing-box release tarball **and** the uv tarball,
> each named exactly as GitHub publishes it, plus optionally `wheels/*.whl`. The
> installer uses them instead of fetching. Pre-placing only sing-box is the
> common mistake: the install then fails at step `[2/6]` instead. See
> `installer/artifacts/README.md` for the exact filenames.

> The deps are **exact pins with hashes**, in the checked-in
> `installer/resources/requirements.txt` — the versions CI tested, not a range
> resolved on the router. The lock carries `python_full_version` markers so 3.9
> (OpenWrt 21.02) takes one branch and 3.10+ takes another; an offline wheel
> bundle built for the wrong one is rejected as `unsatisfiable`, and the
> installer then falls back to PyPI, which defeats the point of the bundle.

> pydantic v2 pulls `pydantic-core` (a Rust wheel), the only compiled
> dependency. uv resolves the `musllinux_1_1_*` build for the router's arch — it
> publishes `_1_1` for x86_64, aarch64 and armv7l and nothing newer. An arch with
> no musllinux wheel would have to build from source (no toolchain on the
> router); the install-time import smoke-test catches that there rather than at
> first boot.

## Capture: a hand-managed TPROXY divert

The data plane is one sing-box process with a `tproxy` inbound, plus a
loopback HTTP-proxy inbound for the daemon's own egress:

```jsonc
{ "type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 7895 }
{ "type": "http",   "tag": "local-proxy-in", "listen": "127.0.0.1", "listen_port": 7896 }
```

`kitewrt/divert.py` owns the netfilter side: a `mangle/PREROUTING` chain that
escapes loopback, the uplinks, the reserved ranges and (optionally) an ipset of
bypassed destinations, then TPROXYs everything else to `:7895` under fwmark
`0x2023` — with an `ip rule` and a `local default` route in table 2023 to make
that mark deliverable, and an `INPUT` accept at position 1 so fw3's `syn_flood`
and zone dispatch don't eat it first. See ARCHITECTURE.md for the ordering and
why each line is there.

**This replaced a tun inbound, for throughput.** Measured on this same VM
kernel (iperf3, client→router→server): plain forwarding 5.98 Gb/s, tun
`stack: mixed` 185 Mb/s, tun `stack: gvisor` + mtu 9000 1.10 Gb/s, tproxy
3.54 Gb/s. A tun hands up raw IP packets so the proxy runs TCP in userspace;
TPROXY hands over an established socket. (The tun actually in place at the time
of the migration was the gvisor one, so the honest like-for-like is ~3x, not the
~19x against the original mixed stack.)

**On fw3 the capture does NOT survive a firewall *restart*.** This is the
opposite of the tun era and worth being explicit about. `auto_route`/`strict_route`
were policy routing — `ip rule`s in iproute2, a different subsystem from
netfilter — so `firewall reload` and even `firewall restart` left them alone. Our
chain lives in the mangle table, which fw3's `/etc/init.d/firewall restart`
rebuilds from scratch. A plain **reload** (WAN flap, PPPoE reconnect, DHCP renew,
`uci commit firewall`, LuCI "Save & Apply" — all reloads) leaves us alone; a
**restart** takes the chain with it.

**On fw4 (22.03+) neither does.** Measured: fw4 rebuilds only `table inet fw4`,
and the capture lives in `table ip mangle`, so the chain, the PREROUTING jump and
the `ip rule` all survived a restart. The failure below is therefore an fw3
problem in practice.

That failure is fail-**open**: traffic quietly goes direct, nothing is
black-holed, so nobody notices. The watchdog re-asserts the capture on every
healthy tick specifically to heal it, and now surfaces a failure to do so in
the UI rather than only the log.

**A dead listener is fail-closed**, which is the other half. TPROXY with no
socket behind it does not fall through — it black-holes TCP while ICMP keeps
working. That is why the rules go in only after sing-box is confirmed
listening, come out before it stops, and deliberately *stay* installed across
a reload (making the reload window fail-closed for free). It is also why
`sweep()` runs at daemon startup: a SIGKILL'd daemon otherwise leaves the LAN
dark behind a chain pointing at nothing.

**IPv4-only.** `divert.py` speaks `iptables`, not `ip6tables`, so the installer
drops forwarded LAN→WAN IPv6 at the firewall and REJECTs LAN IPv6 DNS (see
Security notes) rather than let either leak around the tunnel.

On/off and country selection are **live Clash API switches** of the selector
outbound (`direct` ↔ a server) — no process restart, no netfilter churn.
sing-box only restarts on a *structural* change (servers/rules/DNS). The
kill-switch `FORWARD -o <wan> -j DROP` now covers only the boot window, before
the capture exists at all.

procd supervises sing-box with `respawn` (crash recovery); kitewrt's watchdog
additionally catches a *wedged* sing-box (process up but Clash API dead) and
restarts it.

## DNS

DNS lives entirely inside the sing-box config (`kitewrt/singbox/dns.py`) — five
resolvers: four mirroring the routing split, plus a bootstrap for the proxy
servers' own hostnames.

* `dns-fake` — a **fake-IP** resolver. Foreign (proxy-routed) A/AAAA queries get
  a synthetic `198.18.x` address *instantly*; sing-box reverse-maps it back to
  the domain when routing, so the real lookup happens at the proxy exit (correct
  CDN, no ISP visibility). This is the Shadowrocket-style fake-IP — it removes a
  per-domain DoH-over-proxy round trip (~140 ms each) that made page/video
  startup slow. `strategy: ipv4_only` (the data plane is v4-only).
* `dns-proxy` — DoH over the proxy. Now only the rarer non-A/AAAA foreign
  queries (HTTPS/SVCB type 65/64, TXT, …); the bulk (A/AAAA) is fake-IP'd.
* `dns-direct` — a plain-UDP resolver for direct-routed home-region/RU domains
  (resolved real, so RU GeoDNS/CDN is correct on the direct path).
* `dns-bootstrap` — the **same DoH endpoint as `dns-proxy`, with no detour**, so
  sing-box dials it over its own WAN socket. It is wired as
  `route.default_domain_resolver`, i.e. it is what resolves the proxy/VPN
  *servers'* own hostnames. Deliberately not `dns-direct`: the RU plain-UDP path
  serves stale or spoofed answers for foreign hosts, so a node whose A record
  just moved keeps dialing the dead IP, silently, with a valid config and a
  healthy process. This is why **the DoH URL must be an IP literal** — a
  hostname here would itself need resolving, which is the loop this exists to
  avoid. (A `detour: "direct"` is rejected at service start and `sing-box check`
  does not catch it; only a real run does.)
* `dns-local` — the router's own resolver (`type: local` → dnsmasq) for `*.lan`
  and `localhost`, so LAN hosts reachable by name aren't fake-IP'd and proxied
  (the proxy can't resolve a private name).

**`dns-direct` should not be the router's own resolver.** Under the tun this was
a hard deadlock: sing-box's `hijack-dns` rule pulled dnsmasq's upstream queries
back into sing-box, and it 0-byte'd the VPN on first deploy. That mechanism is
gone with the tun — the capture hooks PREROUTING only, and dnsmasq's upstream
traffic is router-origin, so it takes OUTPUT and is never captured. **Whether the
loop still reproduces under TPROXY has not been re-tested.** The advice stands on
what is still true: pointing it back at the router just forwards regional lookups
to the ISP's resolver, which defeats the point of setting a regional one. For
region-specific GeoDNS use a public resolver hosted in that region
(Settings → DNS).

## QUIC

QUIC/HTTP3 (UDP/443) flows through the tunnel. The capture TPROXYs UDP as well
as TCP (`_chain_rules` emits a tcp *and* a udp rule at each of its two TPROXY
points) and sing-box relays the datagrams natively, so no tun stack is involved
at all. Earlier builds — on the old `system` tun stack, which did not relay UDP —
blocked UDP/443 with a `{network: udp, port: 443, action: reject}` route rule and
fell apps back to HTTP/2 over TCP. **That reject rule is no longer needed; remove
it from any rules preset that still carries it.**

What the capture cannot carry is everything that is neither TCP nor UDP: TPROXY
has no target for ICMP, GRE, ESP, 6in4 or SCTP, so the chain ends in a `DROP`
rather than let them egress in the clear. Fragmented UDP is fine —
`nf_defrag_ipv4` reassembles before the chain, and a 3000-byte datagram matched
the UDP TPROXY rule as one packet.

## Congestion control (BBR)

The proxy uplink is a long-RTT, sometimes-lossy path. The kernel default `cubic`
treats loss as congestion and collapses the window on it; **BBR** models the
path's bandwidth/RTT and ignores non-congestion loss, holding throughput where
cubic dips. The installer enables it (`ensure_bbr`: `kmod-tcp-bbr` +
`net.ipv4.tcp_congestion_control=bbr`, persisted in `/etc/sysctl.d/` +
`/etc/modules.d/`). Best-effort — a kernel without a matching kmod keeps cubic.
It applies to TCP-carrier nodes (vless/trojan) and direct TCP; hysteria2 carries
its own (Brutal) congestion control over QUIC and doesn't depend on this.

## Security notes

1. **kitewrt web UI is unauthenticated**, bound on the LAN. Anyone on the LAN
   can flip the VPN. Intentional for home use; lock down before exposing. The
   installer adds a fw3 rule dropping WAN→:8088 as defense-in-depth (on top of
   OpenWrt's default WAN-input REJECT).
2. **sing-box binary fetched over HTTPS** from GitHub releases, version-pinned
   **and SHA256-verified** — the install fails closed on a mismatch, on an arch
   with no pinned hash, *and* when `sha256sum` cannot produce one. None of those
   degrade to a warning any more: it runs as root and is the whole data plane.
   The same applies to the uv tarball. Both tarballs are also refused if any
   member is a link or a non-plain file, or if any member name traverses — a
   name check alone cannot see a link member, and busybox `tar` rewrites hostile
   *names* itself while honouring a symlink that a following `chmod +x`
   dereferences as root.
3. The OpenWrt `lan` zone has `input ACCEPT`, so the UI on :8088 is reachable
   from the LAN without an extra firewall rule.
4. **IPv6 is blocked, not tunnelled.** The data plane is IPv4-only, so the
   installer adds a fail-closed fw3 rule dropping forwarded LAN→WAN IPv6 — LAN
   clients fall back to (tunnelled) IPv4 rather than leaking their real IPv6
   address around the tunnel.
5. **SSRF guard on fetched URLs.** Subscription / rules / rule-set URLs are
   refused if they point at a non-public address — both IP-literals and
   hostnames that resolve to loopback / link-local (cloud metadata) / reserved.
   Private LAN addresses are allowed so you can self-host. Subscription/rules
   URLs also need an `http(s)://` scheme.
6. **NTP boot gate.** After a power-loss reboot a router with no RTC starts with
   an unset clock; the daemon waits (bounded) for the clock to look sane before
   bringing a TLS-validating proxy up, so a "cert not yet valid" rejection
   doesn't keep the LAN dark until NTP lands.
7. **Subscription size cap.** At most a few hundred servers are taken from one
   subscription, bounding the config size a malicious/oversized provider can
   produce on a low-RAM router.

## References

- [sing-box documentation](https://sing-box.sagernet.org/)
- [OpenWrt firewall (fw3) — includes](https://openwrt.org/docs/guide-user/firewall/firewall_configuration)
- [OpenWrt procd init scripts](https://openwrt.org/docs/guide-developer/procd-init-scripts)
