# The installer, in detail

The [README](../README.md#install) has the three commands you actually type.
This file is what they do — the pre-flight probes, why the dependency step is
built the way it is, the one system-wide setting the installer changes, and
exactly what `--uninstall` takes with it.

The installer runs on **your** machine (macOS or Linux) and talks to the router
over one SSH session. Nothing of it stays on the router: at runtime the daemon
makes no authenticated calls back to the router firmware, and the SSH password
is used only for the session that deploys everything.

## What happens, in order

These are the `[n/6]` markers the installer prints.

| | Step | What it does |
|---|---|---|
| `[1/6]` | Connect + pre-flight | Confirms OpenWrt + `opkg`; checks ~140 MB free; ensures `curl` + `sha256sum`; detects CPU arch (`uname -m`). Then three kernel probes, run by *actually adding a rule* rather than trusting `opkg list-installed`: **TPROXY** (installs `iptables-mod-tproxy`; a hard stop if it still fails — nothing would be proxied), **`ip rule … lookup 2023`** (installs `ip-full`; busybox's built-in `ip` caps route-table IDs at 255, also a hard stop), and the **`-m set` match** (installs `ipset`; optional — its absence only disables `bypass_address`). Finally it switches the router to **BBR** congestion control (see below). |
| `[2/6]` | python3 + deps | `opkg install python3`. **No pip.** A pinned **uv** (SHA-256 verified) is downloaded to `/tmp`, installs the deps into `/usr/lib/kitewrt/vendor` from the checked-in [`installer/resources/requirements.txt`](../installer/resources/requirements.txt) — every version pinned to what CI tested, every wheel hash-checked — and is then deleted; it's a build tool, not runtime. Ends with an import smoke-test under the *router's* interpreter, so a bad wheel fails here instead of crash-looping the daemon later. |
| `[3/6]` | Install sing-box | Downloads the pinned sing-box release for the router's arch → `/usr/bin/sing-box`, verifying the tarball against a pinned SHA-256 before it is trusted (it runs as root and *is* the data plane). On x86-64 the official build is dynamically glibc-linked, so on a musl-only OpenWrt the installer symlinks the musl loader into the glibc loader path; the armv7 build is static and needs no shim. Idempotent: skips if the right version is already there. |
| `[4/6]` | Deploy + init scripts | Pushes the `kitewrt/` package to `/usr/lib/kitewrt/`; installs procd `/etc/init.d/singbox` + `/etc/init.d/kitewrt` and enables them; registers `/lib/upgrade/keep.d/kitewrt` so `/etc/kitewrt` survives a firmware upgrade (the binaries don't — re-run the installer after a sysupgrade). |
| `[5/6]` | Configure firewall | Adds the fw3 router-origin MSS clamp, the WAN-side DROP on the UI port, and the IPv6 egress DROP + IPv6 DNS REJECT (the capture is IPv4-only, so without these a client's real IPv6 address leaks straight out the WAN). |
| `[6/6]` | Start the daemon | Starts it and polls `/api/health` on `:8088` for up to ~20 s; if it never answers, the installer dumps the log tail and fails rather than printing "Done". The LAN capture itself is *not* installed here — the daemon owns it at runtime. |

## Re-running it

Re-running is safe — every step is idempotent — but it is **not much faster**.
Only sing-box is version-checked and skipped; the dependency install runs every
time (uv is re-fetched to `/tmp`, and the deps are reinstalled with
`--no-cache`). Budget about a minute, not seconds. A fresh install after an
uninstall measured 56 s in the [audit notes](./measured-facts.md).

## Why uv and not pip

pip was given version *ranges* and resolved them **on the router** with the pip
22.0.4 that OpenWrt 21.02 ships, so a router provisioned six months after a
release quietly ran a dependency tree CI had never seen. uv installs the exact
locked versions with hash verification, and drops the `python3-pip` package
(5.4 MB) and one more feed from the requirements.

The lock carries `python_full_version` markers, so 3.9 (OpenWrt 21.02) takes one
branch and 3.10+ takes another — see [the per-version
notes](./openwrt-notes.md#facts-that-differ-per-openwrt-version).

## BBR: the one system-wide setting the installer changes

**The installer switches the router's TCP congestion control to BBR.** It
installs `kmod-tcp-bbr` if needed, applies it immediately, and persists it in
`/etc/sysctl.d/99-kitewrt-bbr.conf` + `/etc/modules.d/99-kitewrt-tcp-bbr` — so
it affects *all* the router's TCP, not just proxied traffic.

BBR holds throughput on the lossy, long-RTT paths a proxy uplink actually takes,
where the default `cubic` treats loss as congestion and collapses the window on
it. It applies to TCP-carrier nodes (vless/trojan) and to direct TCP; hysteria2
carries its own (Brutal) congestion control over QUIC and doesn't depend on it.

It is best-effort — a kernel with no matching kmod keeps `cubic`, with a warning
— and **it is not reverted by uninstall**. To go back to cubic:

```sh
ssh root@192.168.8.1 'rm -f /etc/sysctl.d/99-kitewrt-bbr.conf /etc/modules.d/99-kitewrt-tcp-bbr'
ssh root@192.168.8.1 'sysctl -w net.ipv4.tcp_congestion_control=cubic'
```

## Behind a blocked GitHub / PyPI

Three downloads happen *on the router*: **sing-box** and **uv** (both GitHub)
and the **wheels** (PyPI). If your ISP blocks them there, pre-download them on a
machine that can reach them, drop them into `installer/artifacts/`, and re-run —
the installer detects and uses them instead of fetching, no auto-bundling.
Pre-placing only sing-box is the common mistake: the install then fails at
`[2/6]` instead. See [`installer/artifacts/README.md`](../installer/artifacts/README.md)
for the exact filenames. (`python3` itself comes from the opkg feed and has no
escape hatch.)

An offline wheel bundle must match the router's Python: a bundle built for the
wrong minor version is rejected as `unsatisfiable`, and the installer then falls
back to PyPI — which defeats the point of the bundle.

## Checking an install without changing it

```sh
uv run kitewrt --probe root@192.168.8.1
```

Connects, reports what is installed and what state it is in, and changes
nothing.

## Uninstall

```sh
cd kitewrt                                   # the repo you cloned
uv run kitewrt --uninstall root@192.168.8.1
```

> ### ⚠️ Uninstall deletes your configuration
>
> It removes **`/etc/kitewrt`**, and `/etc/kitewrt/data/state.json` is the only
> copy of your **subscriptions and their credentials**, your DNS settings and
> your rules URL. There is no backup and no prompt.
>
> That is deliberate — "no credentials left on disk" is the point of
> uninstalling — but it means **you must save your subscription URLs somewhere
> else first** if you ever intend to reinstall.
>
> Don't let the firmware-upgrade behaviour mislead you: `/etc/kitewrt` is
> registered in `/lib/upgrade/keep.d/` *specifically* so it survives a
> sysupgrade, and the installer says so as it runs. Surviving a firmware flash
> and surviving an uninstall are different things.

**Removed:**

- Daemon stopped + disabled; init scripts removed; the `keep.d` entry removed.
- `/usr/lib/kitewrt/` removed — **including `vendor/`**, so the next install
  redoes the whole dependency step.
- **`/etc/kitewrt/` removed** — state.json, metrics, the MSS-clamp include. See
  the warning above.
- sing-box stopped and the netfilter capture removed (chain, INPUT accept, ip
  rule, route table, the bypass ipset, and any stranded kill-switch rule —
  matched by comment, so a renamed WAN doesn't strand it).
- `config.json` overwritten with a credential-free config (selector points only
  at `direct`) — **no VLESS UUID, server hostname, Reality SNI, or custom rules
  left on disk** — and `/etc/sing-box/cache.db` deleted.
- fw3 sections (MSS clamp, WAN-UI block, IPv6 egress/DNS blocks) removed, the
  firewall reloaded, and the clamp rule dropped from `mangle/POSTROUTING`.

**Intentionally left in place:**

- `/usr/bin/sing-box` and `python3`, plus the packages the pre-flight installed
  (`ip-full`, `ipset`, `iptables-mod-tproxy`, `curl`, `coreutils-sha256sum`,
  `kmod-tcp-bbr`) — a re-install reuses them, and other tooling may depend on
  python3.
- **BBR stays the router's congestion control**, for the reasons and with the
  revert recipe [above](#bbr-the-one-system-wide-setting-the-installer-changes).
