# Subscription & node-URI formats

> VLESS is the primary/most-common protocol and gives this doc (and the
> `kitewrt/vless.py` module) its name, but the parser handles seven schemes —
> see [Other protocols](#other-protocols-shadowsocks--vmess--trojan--tuic--hysteria-v1).

## Subscription URL

A subscription URL returns a single text body which is **base64-encoded** when fetched. After base64-decoding, the body is a list of `vless://` URIs, one per line (LF-separated).

Verified format from `https://provider.example/sub/<token>` (May 2026):

```
$ curl -sS https://provider.example/sub/<token> | base64 -d | head -3
vless://aaaaaaaa-...@pl.example:8443?security=reality&type=tcp&...&pbk=...&sid=...#🇵🇱⚡Poland
vless://bbbbbbbb-...@es.example:8443?security=reality&type=tcp&...&pbk=...&sid=...#🇪🇸⚡Spain
vless://cccccccc-...@de.example:8443?security=reality&type=tcp&...&pbk=...&sid=...#🇩🇪⚡Germany
```

This matches the **standard V2RayN / V2RayNG / Shadowrocket** subscription convention. Most VLESS providers follow it, so the parser is generic.

**Fallbacks the parser should handle:**

- The body is *not* base64 (some providers return raw `vless://` lines). Detect by trying base64 decode and falling back to the raw text if the result has no `vless://` lines.
- Trailing whitespace or `\r\n` line endings.
- Padding-less base64 (need to add `=` padding before decoding).

## VLESS URI structure

```
vless://<UUID>@<HOST>:<PORT>?<query>#<fragment>
```

| Component | Example | Notes |
|---|---|---|
| `UUID` | `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` | Auth identifier |
| `HOST` | `pl.example` | DNS or IP |
| `PORT` | `8443` | Usually 443 / 8443 |
| `query` | `security=reality&type=tcp&...` | Transport + crypto params |
| `fragment` | `🇵🇱⚡Poland` (URL-encoded) | Human-readable label |

### Query parameters (Reality protocol — most common today)

| Param | Example | Required | Notes |
|---|---|---|---|
| `security` | `reality` | yes | Other values: `tls`, `none` |
| `type` | `tcp` | yes | Other: `ws`, `grpc`, `xhttp` |
| `flow` | `xtls-rprx-vision` | for reality | Empty for non-reality |
| `sni` | `www.example.com` | for reality/tls | Server Name Indication / handshake host |
| `pbk` | `9Y-_jCI3Z1x6...` | for reality | Reality public key |
| `sid` | `d2c6d9f6e6e12bfe` | for reality | Reality short ID |
| `fp` | `chrome` | for reality | Browser fingerprint |
| `headerType` | (empty) | optional | tcp obfuscation header type |
| `host` | (empty) | for ws/grpc | HTTP Host header / SNI for h2 |
| `path` | `/` | for ws/grpc | URL path |

### Fragment (server label)

URL-encoded UTF-8 string. Convention: starts with country flag emoji, then optional separator (`⚡`, `-`, ` `), then country name (often in the provider's locale rather than English).

**Country detection:**

1. Look for a flag emoji at the start (`U+1F1E6..U+1F1FF` regional indicator pairs)
2. Map flag to ISO-3166 alpha-2 (e.g. 🇵🇱 → `PL`)
3. If no flag: try matching the rest of the fragment against a known English country-name list (the flag emoji — step 1 — is the language-agnostic path that covers locale-specific labels)
4. Fallback: `??` (still display the raw fragment as `name`)

This gives us a stable `country` code for grouping/sorting in the UI plus the original `name` for display.

## hysteria2 nodes

Providers commonly mix a second protocol into the same subscription —
**hysteria2** (QUIC-based, often labelled "GAMING"). The parser recognises both
`hysteria2://` and the shorthand `hy2://`. These have no UUID; auth is a
password carried in the URI userinfo, and the transport is always QUIC/TLS.

```
hysteria2://<PASSWORD>@<HOST>:<PORT>?<query>#<fragment>
hy2://<PASSWORD>@<HOST>:<PORT>?<query>#<fragment>
```

| Param | Example | Notes |
|---|---|---|
| `sni` | `fi-gaming.example` | TLS SNI; defaults to the host |
| `insecure` | `1` | Skip cert verification (truthy: `1`/`true`/`yes`) |
| `obfs` | `salamander` | Optional QUIC obfuscation |
| `obfs-password` | `…` | Required when `obfs` is set |

The parsed `Server` carries `type: "hysteria2"` and `password` (instead of
`uuid`). `kitewrt/singbox/outbound.py: build_hysteria2_outbound` maps it to a
sing-box `hysteria2` outbound:

```json
{
  "type": "hysteria2",
  "tag": "<subscription-id>/<server-id>",
  "server": "<host>",
  "server_port": <port>,
  "password": "<password>",
  "tls": { "enabled": true, "server_name": "<sni>", "insecure": false },
  "obfs": { "type": "salamander", "password": "<obfs-password>" }
}
```

> hysteria2 runs over UDP, so the TCP "Test"/ping probe skips these nodes (a
> TCP handshake to a QUIC port would always read as "down"). They appear in the
> list untested rather than falsely dead.

## Other protocols (shadowsocks / vmess / trojan / tuic / hysteria v1)

Beyond `vless` and `hysteria2`, `parse_node` and `build_outbound` handle five
more schemes that show up in mixed subscriptions. Each maps to the same-named
sing-box outbound; `Server.type` discriminates, and the protocol-specific auth
lives in `uuid` / `password` / `method`.

| Scheme | `type` | Auth | Carrier | Notes |
|---|---|---|---|---|
| `ss://` | `shadowsocks` | `method` + `password` | TCP/UDP | SIP002 (`base64(method:password)@host:port`) **and** legacy whole-base64; optional SIP003 `plugin` |
| `vmess://` | `vmess` | `uuid` (+ `aid`) | tcp/ws/grpc | Payload is `base64(JSON)` — `add`/`port`/`id`/`net`/`tls`/`scy`/… |
| `trojan://` | `trojan` | `password` | TLS (+ ws/grpc) | `sni`/`alpn`/`allowInsecure` query params |
| `tuic://` | `tuic` | `uuid` **+** `password` | QUIC | `congestion_control` (default `bbr`), `alpn` (default `h3`) |
| `hysteria://` | `hysteria` | `auth` query → `password` | QUIC | v1, distinct from hysteria2; `upmbps`/`downmbps` → `up_mbps`/`down_mbps` |

- **shadowsocks** userinfo is detected as base64 vs plaintext by the presence of
  a literal `:` (the base64 alphabet has none). The cipher goes in
  `Server.method`; `ss://…?plugin=obfs-local;obfs=tls` splits into sing-box
  `plugin` + `plugin_opts`.
- **vmess** isn't URI-shaped — the whole payload is base64'd JSON. Transport/TLS
  hints are stashed into `Server.params` (string-valued, like the URI query
  dict) so `build_vmess_outbound` reads them uniformly.
- **tuic** carries both a uuid and a password in the userinfo as `uuid:password`.
- **hysteria v1** keeps its auth in the `auth` (or `auth_str`) query param rather
  than the userinfo — that's the giveaway vs hysteria2.

> The QUIC protocols (hysteria2, tuic, hysteria v1) run over UDP, so the TCP
> "Test"/ping probe skips them — they show untested rather than falsely dead.

## Internal representation

After parsing, each server is stored as a flat dict:

```jsonc
{
    "id": "pl.example:8443",        // host:port — stable, used as key
    "country": "PL",                // ISO-3166 alpha-2
    "name": "🇵🇱⚡Poland",           // raw fragment (kept verbatim, any language)
    "host": "pl.example",
    "port": 8443,
    "uuid": "aaaaaaaa-...",
    "security": "reality",
    "type": "tcp",
    "flow": "xtls-rprx-vision",
    "sni": "www.example.com",
    "pbk": "9Y-_jCI3Z1x6...",
    "sid": "d2c6d9f6e6e12bfe",
    "fp": "chrome",
    # transport-specific extras only when relevant
    "host_header": null,
    "path": null,
}
```

## Mapping to a sing-box outbound

`kitewrt/singbox/outbound.py: build_vless_outbound` maps a parsed server to a
sing-box `vless` outbound. sing-box uses a flatter shape than xray did — no
`vnext` nesting; `tls` carries the Reality + uTLS sub-blocks:

```json
{
  "type": "vless",
  "tag": "<subscription-id>/<server-id>",
  "server": "<host>",
  "server_port": <port>,
  "uuid": "<uuid>",
  "flow": "<flow>",
  "tls": {
    "enabled": true,
    "server_name": "<sni>",
    "utls": { "enabled": true, "fingerprint": "<fp, default chrome>" },
    "reality": {
      "enabled": true,
      "public_key": "<pbk>",
      "short_id": "<sid>"
    }
  }
}
```

For non-reality (plain TLS): the `tls` block drops `reality` and adds
`alpn: ["h2", "http/1.1"]`, with `server_name` defaulting to the host. For
ws / grpc the outbound gains a `transport` block (`{"type": "ws", "path": …,
"headers": {"Host": …}}` or `{"type": "grpc", "service_name": …}`).

The `tag` is composite (`subscription-id/server-id`) so two subscriptions can
hold the same `host:port` without colliding — it's also the value kitewrt PUTs to
the Clash API selector to switch servers live. See [ARCHITECTURE.md](../ARCHITECTURE.md)
for the selector / live-switch mechanism.
