# Troubleshooting

Symptoms in the order you are likely to meet them: install first, then the UI,
then traffic. Every example uses `192.168.8.1` — substitute your router's LAN
address.

## During the install

**`sh: kitewrt: command not found`.** The CLI is installed into this repo's uv
environment, not onto your `PATH`. Run it from the clone: `cd kitewrt && uv run
kitewrt --uninstall root@192.168.8.1`. Same for `--probe`.

**`ip rule … lookup 2023` is rejected on this router.** busybox's built-in `ip`
caps route-table IDs at 255, so the policy-routing rule the capture needs can't
be added — every non-GL.iNet router hits this. The installer tries `opkg install
ip-full` itself, so seeing this means the feed was unreachable: fix `opkg
update` and re-run. It's a hard stop because the install would otherwise look
perfectly healthy right up until the VPN switch failed.

**`this kernel can't do TPROXY`.** Same shape: `opkg install
iptables-mod-tproxy` needs a working feed. If the package installs and the probe
still fails, the kernel has no TPROXY target and this router can't run KiteWrt.

**`only ~N MB free`.** The pre-flight wants ~140 MB of writable overlay for
python3 + deps + sing-box. 8/16 MB flash devices won't fit python3 at all.

**sing-box download hangs or `install verification failed`.** GitHub is blocked
from the router's WAN. Pre-place the tarballs — see
[`installer/artifacts/README.md`](../installer/artifacts/README.md), and note
that **uv comes from GitHub too**, so you need both files, not just sing-box.

**`the daemon's deps don't import under the router's python`.** A wheel is
missing or built for the wrong python/arch — almost always a hand-built
`installer/artifacts/wheels/` bundle (pydantic-core is a compiled extension,
tagged for exactly one arch and one Python). Delete the `wheels/` folder to fall
back to PyPI, or rebuild it for the router's actual interpreter.

**`daemon did not become healthy on :8088 within 20s`.** The installer prints
the log tail; there's more of it on the router:

```sh
ssh root@192.168.8.1 'logread | grep -i kitewrt | tail -40'
ssh root@192.168.8.1 '/etc/init.d/kitewrt restart'
```

## Once it's installed

**The UI doesn't load.** It's `http://<router-lan-ip>:8088/`, from the LAN — the
WAN side is DROPped by a firewall rule on purpose, and 8080 belongs to GL.iNet's
own uhttpd.

**The dashboard is red for the first few minutes on OpenWrt 22.03+.** Expected
on fw4: the first apply after an install has been measured taking ~80 s to
~3 minutes and a couple of retries (`sing-box is not listening on tproxy port
7895`) before the capture settles, against ~15 s on 21.02. The watchdog carries
it, and the dashboard is telling the truth while it waits. See
[the fw4 notes](./openwrt-notes.md#facts-that-differ-per-openwrt-version).

**The LAN went dark — no DNS, no browsing — after a crash or a failed install.**
That's the fail-closed design showing: TPROXY with nothing listening drops
traffic rather than leaking it to the ISP. The router still answers SSH. Bring
the daemon back (`/etc/init.d/kitewrt restart`), or unhook the capture by hand:

```sh
ssh root@192.168.8.1 'iptables -w 5 -t mangle -D PREROUTING -j kitewrt_tproxy'
```

**One device ignores the VPN.** An on-device VPN client (Shadowrocket,
WireGuard) wraps its traffic before the router sees it. Turn it off to test.

**Pinging a site fails with the VPN on.** Expected. TPROXY has no target for
ICMP, so the capture chain drops everything that is neither TCP nor UDP rather
than let it out in the clear. A bypassed address still pings.

**After a firmware upgrade the UI is gone.** Expected: a sysupgrade wipes the
overlay, so `/usr/lib/kitewrt` and the binaries go with it. `/etc/kitewrt` is
preserved by `/lib/upgrade/keep.d/kitewrt`, so re-running the installer gets you
back with your subscriptions intact.

## Looking at it from outside

```sh
uv run kitewrt --probe root@192.168.8.1     # connectivity + state check, changes nothing
ssh root@192.168.8.1 'logread | grep -i kitewrt | tail -40'
ssh root@192.168.8.1 'iptables -w 5 -t mangle -L kitewrt_tproxy -nv'
```
