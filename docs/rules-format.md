# Custom routing rules format

kitewrt accepts routing rules in **sing-box's native route-rule JSON** — the same
shape sing-box uses for entries under `route.rules` in its `config.json`. No
custom DSL, no proprietary format.

> **This changed in v2.** Earlier versions took Xray's `{"routing": {"rules":
> [...]}}` format with `outboundTag` / `type: "field"`. The data plane is now
> sing-box, so rules are sing-box-native. A pasted-in xray rule (one that
> carries `type` or `outboundTag`) is **rejected** with a pointer to the new
> shape — see [Migrating from xray](#migrating-from-xray-rules) below.

This means you can:

- Reuse the rule *shape* from any sing-box setup — remapping each rule's
  `outbound` to KiteWrt's vocabulary (`proxy` = through the VPN, `direct`, or
  `block`; see [What each rule needs](#what-each-rule-needs))
- Use community-maintained rule sets that target sing-box
- Reference sing-box's own [route rule documentation](https://sing-box.sagernet.org/configuration/route/rule/) for any matcher field

> **This is a rules *slice*, not a full sing-box config — and it won't behave
> like one.** KiteWrt reads **only** the route rules (plus their rule-set
> definitions) and owns everything else: the tproxy inbound, the outbounds (your
> subscription's servers + the live selector), and DNS. Consequences:
> - a rule may only target `proxy` / `direct` / `block` — **never a named
>   outbound or selector tag** (those are rejected; KiteWrt's outbounds come from
>   the subscription, not your file);
> - a pasted full `config.json` has its `inbounds` / `outbounds` / `dns` /
>   `log` / `experimental` **ignored** — only `route.rules` / `route.rule_set`
>   are read.
>
> So you can't drop in an arbitrary sing-box config and expect identical
> behaviour — you supply *routing policy*, KiteWrt supplies the plumbing.

The app fetches the URL once when you set it (and on each manual refresh) and
validates the structure before applying.

## How your rules fit in

kitewrt's generated config already prepends the baseline so your file only needs
to carry the *selective* logic:

```
{ "action": "sniff"  }                ← recover the destination domain from packets
{ "protocol": "dns", "action": "hijack-dns" }     ← LAN DNS into the internal resolver
{ "ip_is_private": true, "outbound": "direct" }   ← LAN / loopback stays direct
…your rules here, in order…
final → the proxy selector                        ← anything unmatched is proxied
```

So you don't need to add the sniff/DNS-hijack/private-direct rules yourself —
just the destinations you want to force `direct`, `block`, or back to `proxy`.
When you set **no** rules at all, the default is a plain full tunnel: private/LAN
→ `direct`, everything else → proxy. kitewrt ships **no** geo data — any geo
split is something you add (see [Rule-sets](#rule-sets)).

> **`direct` rules that match on IP (`ip_cidr`, `geoip` rule-sets) don't fire for
> domain-accessed sites.** kitewrt resolves foreign domains to a *fake IP* (so a
> connection never blocks on a real DNS lookup) and deliberately does **not** add
> a `resolve` action — re-resolving would overwrite the real destination and
> break nested-proxy SNI camouflage. The upshot: an unproxied destination you
> reach **by domain** is matched on its name, not its real IP, so a
> `{"ip_cidr": [...], "outbound": "direct"}` or `{"rule_set": ["geoip-XX"],
> "outbound": "direct"}` rule **won't take effect** for it — it falls through to
> the proxy. To force a domain-accessed site direct, match it by **domain**
> (`domain_suffix` / a `geosite` rule-set). IP-match rules still work for traffic
> addressed by raw IP, and `ip_is_private` still keeps LAN traffic direct.

## Accepted shapes

The validator accepts three top-level shapes for convenience — pick whichever
feels most natural:

### 1. Full config slice — a `route` block

```json
{
  "route": {
    "rules": [
      { "rule_set": ["geosite-example"], "outbound": "direct" },
      { "domain_suffix": ["example.com"], "outbound": "proxy" }
    ]
  }
}
```

### 2. Just the `rules` key

```json
{
  "rules": [
    { "domain_suffix": ["openai.com"], "outbound": "proxy" }
  ]
}
```

### 3. Bare array

```json
[
  { "domain_suffix": ["openai.com"], "outbound": "proxy" }
]
```

`_comment` keys are stripped recursively before the rules are handed to
sing-box (sing-box rejects unknown fields, so you can annotate freely):

```json
[
  { "_comment": "send this domain through the VPN",
    "domain_suffix": ["example.com"], "outbound": "proxy" }
]
```

## What each rule needs

Every route rule must have:

- **`outbound`** — one of:
  - `direct` — bypass the VPN, send straight to the internet
  - `proxy` — send through the active VLESS server (an alias kitewrt rewrites to
    its internal selector tag at build time, so your file stays portable)
  - `block` — drop the connection
- **At least one match field** — typically `domain_suffix`, `ip_cidr`, or
  `rule_set`, but sing-box supports more (see the table below).

Standalone **action** rules are also accepted, but you rarely need them —
kitewrt already prepends `sniff` + the LAN DNS hijack. (`block` is accepted as
sugar and emitted as the modern `reject` action.) The five actions differ in
what they may leave out:

- `sniff` / `resolve` only annotate a connection and matching continues past
  them, so they may stand alone with no matcher at all;
- `reject` / `hijack-dns` decide the connection's fate, so they need at least
  one match field — see [Nothing that quietly turns the VPN
  off](#nothing-that-quietly-turns-the-vpn-off);
- `route` is the long spelling of an ordinary route rule and needs an
  `outbound`.

No other action may carry an `outbound`.

### Nothing else is accepted

A rule may carry **match fields plus `outbound` / `action`, and nothing else**.
Any other key is rejected naming the key and the rule it was in
(`rule[3] has unsupported key 'override_address'`), and so is a rule containing
a nested JSON object — no match field takes one.

sing-box's own route rule has more fields than that, and this is not an
oversight: your rules file may come from someone else, and sing-box's
`override_address` / `override_port` rewrite the *dial destination* for
whichever domains a rule matches. A document that did so passed validation and
`sing-box check` alike, because every other check here asks whether something
required is present, not what else came along. The accepted set is therefore
what this page documents, not sing-box's full surface.

### Nothing that quietly turns the VPN off

For the same reason — the file may not be yours — a few documents are refused
even though sing-box would happily run them. Each of these passed validation,
`sing-box check` **and** `sing-box run` before the checks below existed:

- **A catch-all `direct` rule.** `{"ip_cidr": ["0.0.0.0/0"], "outbound":
  "direct"}`, or the same thing split across several rules, takes every raw-IP
  destination out of the tunnel while the dashboard still reports the VPN on.
  The limit is a *total*, not a prefix length: the `direct` rules in one
  document may not cover more than a quarter of the IPv4 address space —
  the same line `bypass_address` draws, so a country list (well under 2%) is
  untouched. To send everything direct, use the VPN switch; a fetched document
  does not get to operate it. `proxy` and `block` catch-alls are still
  accepted: the first is what `final` already does, and the second stops your
  internet in a way you notice within seconds.
- **An empty matcher value.** `{"domain_keyword": [""], "outbound": "direct"}`
  matches every connection there is, and because name rules are mirrored into
  the DNS block it would also send every lookup on your LAN in clear text to
  the direct resolver. Other spellings (`network: ""`, `process_name: [""]`)
  match *nothing*, so the rule silently never fires. Both are rejected.
- **`ip_is_private: false`** (and `source_ip_is_private: false`). sing-box
  builds no matcher at all for a false boolean, which leaves the rule matching
  everything rather than "everything public" — including traffic reached by
  domain, which an `ip_cidr` rule never sees. Rejected as a rule with no
  matcher.
- **A bare `reject` or `hijack-dns`.** With no matcher it applies to every
  connection: `{"action": "reject"}` is a total blackout that `sing-box check`
  accepts and a healthy-looking process serves.
- **An `action` beside an `outbound`.** sing-box obeys the action and ignores
  the outbound, so `{"action": "reject", "outbound": "direct"}` reads as direct
  and blocks. Only `action: "route"` may carry one — and `route` *without* an
  outbound passes `sing-box check`, then fails every connection it matches with
  "outbound not found".

What none of this catches, said plainly: a rule that matches every *name* takes
one character (`{"domain_keyword": ["."], "outbound": "direct"}`), and nothing
syntactic can tell that from a legitimately broad rule. Read a rules file
before you point kitewrt at it.

## Match field reference (most common)

| Field | What matches | Example values |
|---|---|---|
| `"domain": [...]` | Exact domain names. | `["example.com"]` |
| `"domain_suffix": [...]` | Domain suffix (the usual one). | `["openai.com", ".google.com"]` |
| `"domain_keyword": [...]` | Substring of the domain. | `["googlevideo"]` |
| `"domain_regex": [...]` | Regex over the domain. | `["^api\\.[a-z]+$"]` |
| `"ip_cidr": [...]` | IPv4/IPv6 address or CIDR. | `["10.0.0.0/8", "2001:db8::/32"]` |
| `"ip_is_private": true` | Any RFC1918 / loopback / link-local address. | `true` |
| `"port": [...]` | Destination port(s). | `[443, 80]` |
| `"port_range": [...]` | Destination port range(s). | `["1000:2000"]` |
| `"network": "..."` | Transport. | `"tcp"`, `"udp"` |
| `"protocol": [...]` | Sniffed L7 protocol. | `["tls", "http", "quic"]` |
| `"rule_set": [...]` | A named rule-set you declare yourself (see [Rule-sets](#rule-sets)). | `["my-geoip"]` |

Also accepted, and rarely useful on a router: `source_ip_cidr`,
`source_ip_is_private`, `source_port`, `process_name`, `package_name`,
`clash_mode`. Together with the table above that is the complete list — see
[Nothing else is accepted](#nothing-else-is-accepted).

A rule with two matchers (say `domain_suffix` AND `port`) matches when **all**
of them match — sing-box rule fields are AND'd within a rule, and the multiple
values inside one field are OR'd.

## Rule-sets

kitewrt bundles **no** geo data or block-lists. If your rules reference a
`rule_set`, you must also **declare** it — alongside `rules`, add a `rule_set`
array of sing-box rule-set definitions. Use `type: remote` so sing-box downloads
the `.srs` itself at runtime and caches it (across restarts, via `cache.db`).
`download_detour: "proxy"` fetches it through the VPN (the source is often
blocked on the direct path):

```json
{
  "rule_set": [
    {
      "type": "remote",
      "tag": "my-geoip",
      "format": "binary",
      "url": "https://example.com/path/to/geoip-XX.srs",
      "download_detour": "proxy"
    }
  ],
  "rules": [
    { "rule_set": ["my-geoip"], "outbound": "direct" }
  ]
}
```

Public `.srs` rule-sets exist for many countries/categories (e.g. SagerNet's
`sing-geoip` / `sing-geosite` rule-set branches) — kitewrt neither ships nor
endorses any particular set; the URL and choice are entirely yours.

A rule-set definition may carry `tag`, `type`, `format`, `url` (remote),
`path` (local — see below), `download_detour` and `update_interval` — and
nothing else, for the same reason a rule may not. `download_detour` is
`"proxy"` (through the VPN) or `"direct"`; it used to accept any outbound tag,
which let a document you did not write pull the `.srs` outside the tunnel and
tell your ISP which rule-set this router downloads. An unknown tag is also not
survivable — sing-box refuses to start on one, so it takes the whole data plane
down rather than degrading a single rule-set.

`update_interval` (e.g. `"7d"`) is how often sing-box re-downloads it.

**The URL must name a public host.** *sing-box* fetches it, from the router, so
a rules document that pointed it at `http://localhost:9090/…` would be aiming
the router at its own control API. Refused: loopback / link-local / reserved
addresses, names that are local by definition (`localhost`, `*.localhost`,
anything under the reserved `.internal` TLD), and IPv4 literals written in the
alternative spellings a C resolver accepts (`127.1`, `2130706433`,
`0177.0.0.1`). A private LAN address or name is still allowed, so you can
self-host a `.srs` on your own network.

The check reads the name; it does not resolve it. sing-box resolves a rule-set
host through its own DNS — encrypted DoH, or at the exit node under
`download_detour: "proxy"` — so an answer looked up here would describe a
different lookup than the one it makes, while leaking your rule-set hostnames
to your ISP's resolver to say so.

**A `type: local` `path` must sit inside `/etc/sing-box/`** — copy the `.srs`
there (over SSH) and reference it as `/etc/sing-box/my-list.srs`. Absolute
paths only, no `..`. sing-box reports what it found at the path it was given,
and kitewrt shows that error on the dashboard, so an unrestricted `path` let a
document you did not write ask whether any file on your router exists — the
replies distinguish "no such file", "permission denied", "invalid rule-set
file" and "is a directory". A relative path is refused for a second reason: it
resolves against whichever working directory the reader happens to have, so the
file that passed validation need not be the file that gets loaded.

## Keeping traffic off the proxy entirely (`bypass_address`)

`outbound: direct` does **not** mean "skips the proxy". It means "not via the
proxy server" — the packet is still handed to sing-box and relayed through
userspace. On a router that costs real throughput, because traffic the proxy
terminates locally leaves the kernel's `forward` chain and can no longer be
accelerated by the hardware flow offload (MediaTek PPE and friends only bind
*forwarded* flows).

`bypass_address` is the one knob that keeps traffic on that fast path. Listed
networks are returned to normal forwarding before the capture ever sees them:

```jsonc
{
  "route": {
    "rules": [
      // A DOMAIN matcher, not ip_cidr — see "the DNS half" below.
      { "domain_suffix": ["example.ru", "yandex.ru"], "outbound": "direct" }
    ]
  },
  // The addresses those names resolve to now skip sing-box altogether.
  "bypass_address": ["203.0.113.0/24", "198.51.100.0/24"]
}
```

Accepted at the top level or inside `route`. IPv4 CIDRs only — the capture is
IPv4-only, so a v6 entry is rejected rather than silently ignored. Host bits
are normalised (`10.0.0.1/8` → `10.0.0.0/8`), duplicates dropped, and
`0.0.0.0/0` rejected (the kernel refuses it, and "bypass everything" is just
turning the VPN off).

**Plain CIDRs, not rule-set tags.** They are loaded into an ipset, which is a
single `hash:net` match whose cost is flat in the number of entries (measured: 8,639 and 50,000 are indistinguishable) though it does scale with the number of distinct prefix lengths in the list — a 15,000-network country list costs
about 340 KB and one rule. (An earlier design named sing-box rule-sets instead
and expanded them into one kernel route per prefix; at 21,619 routes it took a
real router down.) Generate the list from whatever source you like and paste it
in; the fetch limit is 1 MiB, which is roughly 40,000 entries.

**The hard ceiling is 65,536 networks**, and going past it is a parse error on
the document you just pasted, not a silent degrade — the validator refuses it
before the capture ever sees it, so you find out where you can still do
something about it. (That number is well under `hash:net`'s own 262,144 default,
deliberately: the set is loaded synchronously inside the capture's lock, and a
250k list measures ~7 s on this class of hardware. A country list is ~15,000, so
65,536 is 4x headroom at ~1 s.)

### The DNS half, which is easy to get wrong

`bypass_address` matches **addresses**, and by default your clients never see
real ones: sing-box answers every A/AAAA query with a synthetic `198.18.x`
fake IP, which is not in your set, so the traffic gets captured anyway and the
bypass achieves nothing.

Only a **name** matcher changes that. A route rule with `domain`,
`domain_suffix`, `domain_keyword` or `domain_regex` is mirrored into the DNS
block as a `dns-direct` rule, so those names resolve to real addresses that
your set can then recognise. An `ip_cidr` rule is *not* mirrored — sing-box
can't know a name's address before resolving it — so pairing `bypass_address`
with an `ip_cidr` rule alone leaves the fake-IP path fully intact.

So the two halves are:

- a **domain** route rule with `outbound: direct` → clients get real addresses;
- `bypass_address` covering those addresses → the traffic stays on the kernel
  fast path and never reaches sing-box.

Consequence worth knowing before you build a list: a pure geo-IP dump with no
domains attached cannot steer DNS, so it only speeds up connections made to
raw IPs. To get the offload win for ordinary browsing you need the matching
domain rules too.

**Caveats:**

- Bypassed traffic is matched by **IP only**, so domain-level rules no longer
  apply to it. If you override specific domains back through the proxy, make
  sure their addresses aren't inside a bypassed range.
- Needs `ipset` **and** the `xt_set` iptables match on the router — separate
  packages, and a router can have one without the other. The installer probes
  the match itself and installs what's missing. Without it the capture still
  works and this option simply does nothing (you'll see a warning in the log).

kitewrt ships no geo data and takes no view on which country is "home" — the
list is entirely yours.

## Order matters

sing-box evaluates rules top-to-bottom; the first match wins. kitewrt runs your
rules *after* its baseline sniff + DNS-hijack + private-direct, so a private-IP
destination is already `direct` before your rules see it. Put your most specific
overrides first.

Anything that matches no rule falls through to `final`, which kitewrt sets to the
proxy selector — that's why "everything through the VPN" is the default behaviour
even with a tiny rule set, and why a split-tunnel file usually only lists the
`direct` exceptions.

## Hosting

Anywhere that returns the JSON over HTTPS as plain text:

- A GitHub gist with a `.json` file (use the **Raw** URL)
- A self-hosted file
- A static-site CDN

The fetch must complete in under 30 seconds and the body must be under 1 MiB —
that's plenty for thousands of rules in practice.

## Migrating from xray rules

If you have an old xray/XKeen `05_routing.json`, it will **not** load — kitewrt
detects `type` / `outboundTag` and fails with a message telling you to convert.
The mapping is mechanical:

| xray | sing-box |
|---|---|
| `"outboundTag": "direct"` | `"outbound": "direct"` |
| `"outboundTag": "proxy"` | `"outbound": "proxy"` |
| `"outboundTag": "block"` | `"outbound": "block"` |
| `"type": "field"` | (drop it — not needed) |
| `"domain": ["domain:foo.com"]` | `"domain_suffix": ["foo.com"]` |
| `"domain": ["full:foo.com"]` | `"domain": ["foo.com"]` |
| `"domain": ["regexp:^…$"]` | `"domain_regex": ["^…$"]` |
| `"domain": ["geosite:XX"]` | `"rule_set": ["geosite-XX"]` * |
| `"ip": ["10.0.0.0/8"]` | `"ip_cidr": ["10.0.0.0/8"]` |
| `"ip": ["geoip:XX"]` | `"rule_set": ["geoip-XX"]` * |
| `"ip": ["geoip:private"]` | `"ip_is_private": true` |
| `"port": "443"` | `"port": [443]` |
| `"network": "tcp"` | `"network": "tcp"` |

\* `geoip:XX` / `geosite:XX` become `rule_set` references — and you must
**declare** that rule-set (see [Rule-sets](#rule-sets)); kitewrt ships none.

## Migrating from Shadowrocket / Surge / Clash

This app does not parse provider-specific formats. Convert by hand:

- **Shadowrocket / Surge `.conf`** — `DOMAIN-SUFFIX,foo,DIRECT` becomes
  `{"domain_suffix": ["foo"], "outbound": "direct"}`; `IP-CIDR,1.2.3.0/24,PROXY`
  becomes `{"ip_cidr": ["1.2.3.0/24"], "outbound": "proxy"}`. Coalesce adjacent
  rules with the same `(field, outbound)` into one rule with multiple values.
- **Clash YAML** — Clash's `rules:` list maps cleanly; remap the proxy-group
  names to `direct` / `proxy` / `block`.
