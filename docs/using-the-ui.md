# Using the UI

What each control does, what the dashboard is actually claiming, and the
behaviours that surprise people once traffic is flowing. For how the pieces work
underneath, see [ARCHITECTURE.md](../ARCHITECTURE.md).

The UI lives on `http://<router-lan-ip>:8088/` and is reachable from the LAN
only — the WAN side is DROPped by a firewall rule on purpose.

## What each control does

| Action | What it does |
|---|---|
| **Pick a different country tile** | Switches the active server **live** via sing-box's Clash API — no process restart. Connections to the old server drain. Usually sub-second. |
| **VPN toggle on** | Points sing-box's selector at the chosen server. A live Clash API switch when the config structure is unchanged; the first time (or after a structural change) it's a config reload + restart. The capture stays installed across that restart, which makes the window fail-closed on its own — TPROXY with no listener drops. |
| **VPN toggle off** | Points the selector at `direct` — a live switch. The capture stays installed and sing-box keeps handling the connections; it just dials them out itself instead of through the proxy server. |
| **Edit DoH URL** | The DoH endpoint sing-box uses to resolve **foreign** domains (home/local resolve direct). Saving regenerates the config and reloads. It has to be an IP literal — see [DNS](./openwrt-notes.md#dns). |
| **Refresh / add subscription** | Re-fetch a subscription, or add another (URL or inline `vless://`). Multiple subscriptions coexist. Every subscription is also auto-refreshed in the background (~6 h), so a provider rotating its servers shows up without a click. |
| **Test a subscription** | Delay-tests every server *through the proxy* (the full ISP→server→internet round-trip) and records the result as a latency badge, re-sorting the tiles. Observation only — it never changes the active server. |
| **⚡ Fastest** | The same measurement as Test, and then it switches to the lowest-latency server. The two buttons run identical probes; only what happens afterwards differs. |
| **Set / refresh / reset rules** | Validate + apply a sing-box route-rules URL; reset clears it back to all-traffic-through-VPN (private/LAN direct). Format: [docs/rules-format.md](./rules-format.md). |
| **Dashboard** | WAN throughput with its 30 s peak, router CPU, memory and temperature, the reachability probes, top flows by host (with tcp/udp type and whether each took the tunnel), and a **per-device** breakdown — which LAN client is using how much. Shown whether or not the VPN is on: the CPU and the WAN link are just as real either way. |

The UI takes a live `/ws` push feed, so changes made from another device show up
automatically. If the socket is down it falls back to polling every 10 s (0.5 s
while an apply is in flight, so the "applying…" state clears promptly).

## The headline is a claim about your traffic, not about the switch

"VPN on" and "your LAN is actually being captured" are different facts, and
every silent failure this project has hunted lives in the gap between them — a
`firewall restart` flushing the mangle table, a rebuilt chain missing the
uplink. So the dashboard never derives its headline from the toggle. It reads
what the watchdog last *observed* about the capture, says how old that reading
is, and treats "could not tell" as its own state rather than as "probably fine".

When the capture is gone, the picture breaks rather than the wording softening —
and the numbers that corroborate it stop being reassuring:

![KiteWrt dashboard in the leaking state: a hatched red panel reading LEAKING — “Your LAN is on the open internet right now” — with the signal path cut at the capture and re-routed straight to the WAN, 213 hardware-offloaded flows, 0% through the tunnel, and the reachability panel labelled “reachable ≠ protected”](./images/dashboard-leaking-dark.png)

Note what every *other* panel says at that moment: three reachability ticks, a
working internet connection, and a VPN switch still in the "on" position. All
true — the internet is working perfectly, through your ISP. So the reachability
panel relabels itself "reachable ≠ protected", the flow and device tables say
why they are empty instead of showing a neutral "no active flows", and the
corroborating numbers (0% through the tunnel, 213 flows back on the hardware
fast path, an idle proxy under a busy uplink) are all on the same screen as the
claim.

Colour is reserved for this. No metric on the page is tinted, so a hue anywhere
means something is being said about the state of your traffic; and each state
also carries its own glyph, edge treatment and share of the screen, so the page
still parses in greyscale and without hue.

## Settings

**Settings** holds the two things that change how traffic is resolved and routed
— the split DNS resolvers and the routing-rules URL, with what that document
actually became (rules, rule-sets, and the bypassed-network count that decides
whether traffic stays on the router's hardware fast path):

![The Settings tab: the DNS panel with the foreign DoH URL and the direct resolver, and the routing-rules panel showing the masked rules URL, when it was last fetched, its rule and rule-set counts, and a plain-language note that 8640 networks bypass the tunnel and leave through the ISP in the clear](./images/settings-dark.png)

## Behaviour worth knowing

**No router credentials stored.** The installer needs your SSH password for the
session it runs from your laptop, but does **not** write it to the router, and
the daemon makes no authenticated firmware calls at runtime. Your *subscription*
credentials are a different matter — they necessarily live in
`/etc/kitewrt/data/state.json` and in the generated `config.json`, because
sing-box has to dial with them.

**DNS is split, with fake-IP for foreign domains.** *Foreign* (proxy-routed)
A/AAAA lookups get an instant **fake IP** (`198.18.x`) — the real resolution
happens at the proxy exit (correct CDN, no ISP visibility), so page/video
startup never waits on DNS. The rarer non-A/AAAA foreign queries (HTTPS/SVCB,
TXT) go over **DoH** through the tunnel. *Direct* (home-region) domains resolve
via a plain **Direct DNS** resolver on the direct path, while `*.lan` /
`localhost` resolve on the router's own resolver (so LAN devices stay reachable
by name). Proxy *server* hostnames are resolved separately, over the same DoH
endpoint dialed off-tunnel (`dns-bootstrap`), so a poisoned plain-UDP answer
can't point a node at a dead IP — which is why the DoH URL has to be an IP
literal. Don't set Direct DNS to the router's own resolver: under the old tun
inbound that deadlocked outright, and while that mechanism is gone (router-origin
traffic takes `OUTPUT` and is never captured, so the loop has **not** been
re-tested under TPROXY), pointing it back at the router just forwards regional
lookups to your ISP's resolver and defeats the point. Set it to a regional
resolver if you rely on region-specific GeoDNS. Full detail:
[DNS](./openwrt-notes.md#dns).

**QUIC flows through the tunnel.** The capture TPROXYs UDP as well as TCP, and
sing-box relays the datagrams natively, so QUIC/HTTP3 (UDP/443) works end-to-end
— no reject rule pushing apps back to HTTP/2. What the capture *can't* carry is
everything that is neither TCP nor UDP: TPROXY has no target for ICMP, GRE, ESP,
6in4 or SCTP, so the chain ends in a `DROP` rather than let them leak in the
clear. Consequence: with the VPN on, pinging a proxied address fails, while
pinging a bypassed one still works.

**The router itself is not captured.** The capture hooks `PREROUTING`, so only
traffic *arriving* from the LAN is diverted; the router's own traffic (opkg,
ntpd, LuCI) takes `OUTPUT` and goes out the WAN untouched. The daemon is the
exception, on purpose: its HTTP client points at a loopback HTTP inbound
sing-box exposes (`127.0.0.1:7896`), so subscription and rules fetches can take
the tunnel when it's up.

**Devices with their own VPN client bypass us.** An on-device
Shadowrocket/WireGuard wraps traffic before it reaches the router; only that
tunnel's exit IP shows up. Disable the on-device client to test the router VPN
there.

**IPv6 is blocked, not tunnelled.** The data plane is IPv4-only, so the
installer adds fail-closed firewall rules dropping forwarded LAN→WAN IPv6 and
rejecting IPv6 DNS. LAN clients fall back to (tunnelled) IPv4 rather than
leaking their real IPv6 address around the tunnel.

**Rules use sing-box's native route-rule JSON.** No proprietary DSL. The
validator accepts `{"route": {"rules": [...]}}`, the `{"rules": [...]}`
shorthand, or a bare `[...]` array, with `outbound` of `proxy`/`direct`/`block`.
Pasted-in xray rules are rejected with a pointer to the new shape. See
[docs/rules-format.md](./rules-format.md).

**Local trust model.** The web UI is unauthenticated and bound to the LAN.
Anyone on the LAN can flip the VPN. Intentional for home use — lock it down
before exposing to untrusted networks.
