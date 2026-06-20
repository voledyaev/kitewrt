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
> definitions) and owns everything else: the tun inbound, the outbounds (your
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
{ "action": "resolve" }               ← resolve sniffed domains before IP rules
{ "ip_is_private": true, "outbound": "direct" }   ← LAN / loopback stays direct
…your rules here, in order…
final → the proxy selector                        ← anything unmatched is proxied
```

So you don't need to add the sniff/private-direct rules yourself — just the
destinations you want to force `direct`, `block`, or back to `proxy`. When you
set **no** rules at all, the default is a plain full tunnel: private/LAN →
`direct`, everything else → proxy. kitewrt ships **no** geo data — any geo split
is something you add (see [Rule-sets](#rule-sets)).

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

Standalone **action** rules (`sniff`, `resolve`, `reject`, `hijack-dns`,
`route`) are also accepted without an `outbound`, but you rarely need them —
kitewrt already prepends `sniff` + `resolve`.

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
endorses any particular set; the URL and choice are entirely yours. `download_detour`
accepts the `proxy` alias (→ the selector) or any literal outbound tag.

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

The fetch must complete in under 30 seconds and the body must be under 1 MB —
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
