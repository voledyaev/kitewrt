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

**LAN internet is blocked during startup, but the UI opens.** With VPN on,
KiteWrt installs `kitewrt-boot-killswitch` before clearing stale capture or
waiting for clock synchronization. It stays until a fresh successful apply,
the intended selector and capture are confirmed; a listening sing-box port or
cached selector alone does not prove readiness. Check the daemon log for clock,
selector, capture and `boot protection` errors. There is no fixed timeout that
silently releases traffic. Failed first applies retry with bounded backoff,
including when WAN or writable storage becomes available later. Switch VPN off
in the UI to regain ordinary internet.
If the daemon cannot recover, the independent guard presents the emergency page
and its VPN-off action releases both current and legacy owned boot guards.


**The UI doesn't load.** It's `http://<router-lan-ip>:8088/`, from the LAN — the
WAN side is DROPped by a firewall rule on purpose, and 8080 belongs to GL.iNet's
own uhttpd.

**The dashboard is red for the first few minutes on OpenWrt 22.03+.** Expected
on fw4: the first apply after an install has been measured taking ~80 s to
~3 minutes and a couple of retries (`sing-box is not listening on tproxy port
7895`) before the capture settles, against ~15 s on 21.02. The watchdog carries
it, and the dashboard is telling the truth while it waits. See
[the fw4 notes](./openwrt-notes.md#facts-that-differ-per-openwrt-version).

**The LAN went dark — no DNS, no browsing.** That's the fail-closed design
showing: with the VPN on, TPROXY with nothing listening drops traffic rather
than leaking it to the ISP. **Turn the VPN off in the UI** — that always gives
plain internet, even with sing-box down. Before (or instead of) anything else,
keep the evidence: the newest file in `/etc/kitewrt/data/diag/` was written
when it happened, and `/etc/kitewrt/data/logs/kitewrt.log` survives reboots.

If the UI itself is gone, the daemon is dead. After about three minutes the
guard restarts it; if that does not work, with the VPN off it releases the LAN,
and with the VPN on it shows a "kitewrt is down" page on the same address
(`http://<router>:8088/`) with a button to turn the VPN off. To act now, bring
the daemon back (`/etc/init.d/kitewrt restart`), or unhook the capture by hand:

```sh
ssh root@192.168.8.1 'iptables -w 5 -t mangle -D PREROUTING -j kitewrt_tproxy'
```

**One device ignores the VPN.** An on-device VPN client (Shadowrocket,
WireGuard) wraps its traffic before the router sees it. Turn it off to test.

**Pinging a site fails with the VPN on.** Expected. TPROXY has no target for
ICMP, so the capture chain drops everything that is neither TCP nor UDP rather
than let it out in the clear. A bypassed address still pings.

**After a firmware upgrade the UI is gone for a minute or two.** Expected: a
sysupgrade wipes the overlay, so `/usr/lib/kitewrt`, python3 and sing-box go
with it, while `/etc/kitewrt` is kept by `/lib/upgrade/keep.d/kitewrt`. The
router then **reinstalls kitewrt by itself**: a kept boot hook
(`/etc/uci-defaults/99-kitewrt-restore`) waits for the internet, installs
python3 from the firmware's feed and runs the same installer from
`/etc/kitewrt/restore/kit.tgz` in `--local` mode — measured at ~70 s on the
Flint 2. Progress is in `/etc/kitewrt/data/logs/restore.log`. If it cannot
(GitHub/PyPI unreachable), it retries for about two hours; re-running the
installer from a computer always works too. Your subscriptions are intact either
way — and Settings → backup gives you a copy for the cases a firmware upgrade is
not: a reset or a new router.

## Looking at it from outside

```sh
uv run kitewrt --probe root@192.168.8.1     # connectivity + state check, changes nothing
ssh root@192.168.8.1 'logread | grep -i kitewrt | tail -40'
ssh root@192.168.8.1 'tail -60 /etc/kitewrt/data/logs/kitewrt.log'   # survives reboots
ssh root@192.168.8.1 'ls -t /etc/kitewrt/data/diag/ | head'          # failure snapshots
ssh root@192.168.8.1 'iptables -w 5 -t mangle -L kitewrt_tproxy -nv'
```


Failure snapshots include a bounded connection-context section: the selected
outbound's configured address/protocol/port, whether the live selector agrees
with the requested state, and separate transport and proxy-test results.
Only a `node_unreachable` incident triggers short probes to the selected public
IP and the existing proxy URL-test target; there is no new periodic probe.
Generic TLS success is not proof of Reality authentication, and TCP probing is
skipped for UDP protocols. A controller error is recorded as unknown rather
than evidence that the upstream node failed. Snapshots are private from creation
(mode 600), retain only the latest five files, and omit config credentials.

The exit-IP card is unavailable while settings are being applied. Its cache is
invalidated when the selected node or applied routing state changes. With VPN
on, an unavailable local proxy produces an unavailable result rather than a
request sent directly through the ISP.


## UDP DNS fails while TCP DNS works

A vendor DNS proxy, parental-control plugin or captive portal can redirect DNS
in `nat/PREROUTING` after KiteWrt accepted the packet in `mangle/PREROUTING`.
TPROXY does not skip later netfilter hooks. This can leave ordinary UDP DNS
unanswered even though the same query over TCP, or directly to the TPROXY
listener, succeeds.

KiteWrt places its own first rule in `nat/PREROUTING`: packets bearing its exact
TPROXY mark are accepted by that table before other destination translations.
Within this iptables NAT chain, this is independent of the vendor, protocol
port and redirect destination.
Independent native nftables NAT base chains need separate integration and
validation: ACCEPT in an iptables-compatible chain does not stop other base
chains. This guard does not claim protection from every native nftables
redirect on every firmware.
Unmarked traffic still follows the existing NAT rules. The rule is installed
before capture, checked and repaired with it, and removed only after capture
has safely stopped. It does not stop or reconfigure third-party services.
For captured DNS, KiteWrt owns resolution; DNS-based policies in a separate
parental-control proxy will not also process that traffic.

An existing UDP conntrack entry may retain an older DNAT decision until it
expires. Test with a new source port after repair; avoid flushing the router's
whole connection table, which would interrupt unrelated sessions.

## Structural reload and rollback safety

A structural reload requires a complete, private `config.json.last-good` copy
before promotion. An I/O failure aborts promotion. A newly added proxy can be
tried even if the old configuration has no safe VPN-on rollback target: if the
candidate fails, the old bytes are restored and sing-box is stopped behind
retained protection instead of being started on direct. A safe old proxy is
reselected when one is available; an explicit new VPN-off intent permits direct.

The procd launcher and Python restart controller install two owned INPUT guards:
`kitewrt-reload-killswitch` for the full TPROXY mark and
`kitewrt-reload-local-proxy` for loopback TCP port 7896. These cover a listener
that restores cached direct, including automatic respawn. The API/control port
remains available. Release requires fresh selector intent and verified capture,
serialized with the launcher through `/var/run/kitewrt-reload.lock`. Guard
cleanup failure is an explicit error. The emergency VPN-off action stops the
service and removes the exact owned guards after saving the off intent.

Policy-routing repair failures retain existing capture. An earlier overlapping
policy rule or a non-local route shadowing table 2023 prevents a readiness claim;
KiteWrt does not rewrite unrelated PBR rules. The first nat/PREROUTING mark guard
still applies only to the common iptables chain, as described above.

## DNS rules with additional connection conditions

A direct domain rule qualified by source address, port, network or another
condition cannot safely become an unconditional direct DNS rule. Ambiguous
projections stay on proxy DNS instead; unknown or mixed address/domain rule-sets
also prevent later direct projections from overriding that protection. Connection
routing rules retain their conditions. A proxy domain's non-A/AAAA queries use
proxy DoH rather than falling into a later broad direct DNS rule.
