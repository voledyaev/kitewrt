"""Validates and normalises user-supplied sing-box routing rules.

kitewrt ships no geo data — a user's rules file carries the selective logic
(which destinations go `direct`/`block`/`proxy`) AND, optionally, the rule-set
*definitions* those rules reference. Rule-sets are typically `type: remote` so
sing-box downloads the geo/block data itself (`download_detour: "proxy"` fetches
it through the VPN). `proxy` is an alias the config generator rewrites to the
selector tag (see kitewrt.singbox.route).

Accepts the three top-level shapes seen in the wild, strips `_comment` keys
(sing-box rejects unknown fields), validates each rule is sing-box-native with
a usable outbound + at least one matcher, and validates any rule-set defs.
Returns {"rules": [...], "rule_set": [...]}.

The bar is deliberately not "would sing-box run this" — sing-box runs a
one-rule document that sends everything direct, and a bare `{"action":
"reject"}` that drops everything, quite happily. The question each check here
answers is "can a document the user did not write turn the VPN off, or redirect
it, without saying so".
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

from kitewrt import divert
from kitewrt.fetch import blocks_ssrf, blocks_ssrf_name
from kitewrt.singbox.dns import FAKEIP_INET4
from kitewrt.singbox.service import SINGBOX_CONFIG

_FAKEIP_NET = ipaddress.ip_network(FAKEIP_INET4)

# Most of IPv4 that a bypass list may cover in total, across all its entries.
# A quarter of the space: far above any legitimate list (a country is well
# under 2%), far below the "everything, expressed as many CIDRs" evasion.
_BYPASS_MAX_COVERAGE = (1 << 32) // 4

# The same line for route rules that send traffic `direct`. Deliberately the
# same number rather than a second one nobody can compare: both fields answer
# the one question this module cares about — how much of the internet does a
# document the user did not write take out of the tunnel — and reusing it means
# a country list that `validate_bypass_list` refuses cannot be smuggled in as
# route rules instead. See `_check_direct_ip_coverage` for why a coverage total
# and not a prefix-length cap.
_DIRECT_MAX_COVERAGE = _BYPASS_MAX_COVERAGE

# A single domain_regex over ~1 KB is almost certainly a mistake or abuse; cap it
# (sing-box's RE2 is linear so ReDoS is low, but bounding attacker-influenced
# engine input is cheap defence).
MAX_REGEX_LEN = 1024

# Outbound targets a user rule may name. `proxy` is the through-VPN alias
# (rewritten to the selector at build time); the other two are real outbounds.
_VALID_OUTBOUNDS = {"proxy", "direct", "block"}

# sing-box rule matchers we accept; a route rule must carry at least one.
_MATCH_FIELDS = (
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "ip_is_private",
    "source_ip_cidr",
    "source_ip_is_private",
    "port",
    "port_range",
    "source_port",
    "network",
    "protocol",
    "rule_set",
    "process_name",
    "package_name",
    "clash_mode",
)

# Actions a user rule may name.
_VALID_ACTIONS = {"sniff", "resolve", "reject", "hijack-dns", "route"}

# The subset that decides a connection's fate on its own, and therefore may not
# stand without a matcher. Measured with `sing-box run` 1.13.16: `{"action":
# "reject"}` and `{"action": "hijack-dns"}` with no matcher at all match EVERY
# connection — the trace prints a bare `router: match[1] => reject` for a domain
# and a raw-IP destination alike, and the hijack variant feeds every connection
# to the DNS server, where it hangs. `sniff` and `resolve` only annotate the
# connection and matching continues past them, which is why kitewrt's own
# baseline opens with a matcher-free `{"action": "sniff"}` — requiring a matcher
# for those would reject the shape this project generates.
_TERMINAL_ACTIONS = frozenset({"reject", "hijack-dns"})

# Everything a route rule may carry. Every other check here asks "is something
# required present?" and none of them look at what ELSE the object holds, so
# this document passed both this validator and `sing-box check`:
#
#   {"domain_suffix": ["victim-bank.example"], "outbound": "proxy",
#    "override_address": "203.0.113.66", "override_port": 8443}
#
# — a rules document, fetched from a URL, rewriting the dial destination for
# whichever domains it names. sing-box's route rule has many more fields than
# these; the whitelist is deliberately what kitewrt *documents and ships* (the
# matchers above, plus outbound/action — see docs/rules-format.md and
# examples/) rather than sing-box's full surface, so a field nobody here has
# reasoned about cannot arrive inside someone else's document. `_comment` is
# absent on purpose: `_strip_comments` has already removed it by this point.
_ALLOWED_RULE_KEYS = frozenset(_MATCH_FIELDS) | {"outbound", "action"}

# Dead giveaways of an xray rule pasted by mistake — fail with a pointer.
_XRAY_MARKERS = ("type", "outboundTag")


class RulesParseError(ValueError):
    """Raised when a rules document fails validation."""


def parse_singbox_rules(raw: bytes | str) -> dict[str, Any]:
    """Parse, strip `_comment`s from, and validate a sing-box rules document.

    Accepted top-level shapes: {"route": {"rules": [...], "rule_set": [...]}},
    {"rules": [...], "rule_set": [...]}, or a bare [...] (rules only). Returns
    {"rules": [...], "rule_set": [...], "bypass_address": [...]} — the first two
    ready for the `route` block, the third for the netfilter capture.

    sing-box rejects unknown fields, so `_comment` keys (which xray tolerated)
    are stripped recursively here.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        top = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RulesParseError(f"not valid JSON: {exc.msg}") from exc

    rules_raw = _extract_rules_array(top)
    if not rules_raw:
        raise RulesParseError("`rules` is empty")

    rules: list[dict[str, Any]] = []
    for i, ri in enumerate(rules_raw):
        if not isinstance(ri, dict):
            raise RulesParseError(f"rule[{i}] is not an object")
        rule = _strip_comments(ri)
        _validate_rule(i, rule)
        rules.append(rule)

    rule_sets: list[dict[str, Any]] = []
    for i, rsi in enumerate(_extract_rule_sets(top)):
        if not isinstance(rsi, dict):
            raise RulesParseError(f"rule_set[{i}] is not an object")
        rs = _strip_comments(rsi)
        _validate_rule_set(i, rs)
        rule_sets.append(rs)

    # How much of the internet the document sends `direct` is a property of the
    # whole document, so no per-rule check can see it: four rules at 24% each
    # are one rule at 96%.
    _check_direct_ip_coverage(rules)

    # Cross-reference, and reject here rather than later. A rule naming a tag no
    # `rule_set` defines — a typo is enough — passes every per-object check AND
    # `sing-box check`, then FATALs at `run`: "initialize DNS rule[1]: rule-set
    # not found". Measured end to end, that is a LAN blackout: procd reports the
    # start as successful, so the config rollback (gated on that signal) never
    # restores the last-good config and the capture stays installed over a dead
    # listener. `revalidate_persisted` has had this check since it was written,
    # precisely so dropping a rule_set could not strand its references — the
    # path that *installs* the document had no equivalent.
    missing = _missing_rule_set_refs(rules, rule_sets)
    if missing:
        i, tag = missing[0]
        known = sorted(str(rs.get("tag")) for rs in rule_sets)
        raise RulesParseError(
            f"rule[{i}] references rule_set {tag!r}, which this document does not "
            f"define (defined: {known or 'none'}); sing-box would accept the file "
            "and then refuse to start"
        )

    bypass = _extract_bypass_address(top)

    return {"rules": rules, "rule_set": rule_sets, "bypass_address": bypass}


def _rule_set_refs(rule: dict[str, Any]) -> list[str]:
    """The rule-set tags a route rule names, as a list however it was spelled."""
    refs = rule.get("rule_set")
    if isinstance(refs, list):
        return [r for r in refs if isinstance(r, str)]
    return [refs] if isinstance(refs, str) and refs else []


def _missing_rule_set_refs(
    rules: list[dict[str, Any]], rule_sets: list[dict[str, Any]]
) -> list[tuple[int, str]]:
    """(rule index, tag) for every reference no definition satisfies."""
    tags = {rs.get("tag") for rs in rule_sets}
    return [(i, t) for i, rule in enumerate(rules) for t in _rule_set_refs(rule) if t not in tags]


def revalidate_persisted(
    rules: list[dict[str, Any]],
    rule_sets: list[dict[str, Any]],
    bypass: list[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    """Re-check a rules document that was validated by an *earlier* build.

    The document is fetched once and then persisted in `state.json`, so every
    boot feeds the stored copy straight to sing-box; a validator tightened
    afterwards never sees it again. `override_address` — which rewrites the dial
    destination for matched domains — was accepted until the key whitelist
    landed, and a router that had already fetched such a document would have
    gone on honouring it indefinitely, through any number of upgrades. Same for
    a `rule_set` URL naming `localhost`.

    Drops what no longer validates rather than refusing to start. The rules
    document is a routing preference, not a prerequisite: `build_route` falls
    back to the bundled defaults on an empty list, so dropping is a working
    router with less routing, while raising here is a router that will not boot
    because of a file the user cannot see.

    Returns (rules, rule_sets, bypass, reasons).
    """
    kept_rules, kept_sets, dropped = [], [], []
    for i, rule in enumerate(rules):
        try:
            _validate_rule(i, rule)
        except RulesParseError as exc:
            dropped.append(str(exc))
            continue
        kept_rules.append(rule)
    for i, rs in enumerate(rule_sets):
        try:
            _validate_rule_set(i, rs)
        except RulesParseError as exc:
            dropped.append(str(exc))
            continue
        kept_sets.append(rs)
    # A rule_set that was dropped leaves any rule referencing its tag pointing
    # at nothing, and sing-box refuses to start on an unknown rule-set tag —
    # which would turn "less routing" into the boot failure this function exists
    # to avoid.
    stranded = {i for i, _ in _missing_rule_set_refs(kept_rules, kept_sets)}
    surviving = []
    for i, rule in enumerate(kept_rules):
        if i in stranded:
            tag = _missing_rule_set_refs([rule], kept_sets)[0][1]
            dropped.append(f"rule[{i}] references rule_set {tag!r}, which is not defined")
            continue
        surviving.append(rule)

    # Coverage is a property of the document, so the per-rule loop above cannot
    # notice it and a stored document accepted before this guard existed would
    # go on emptying the tunnel on every boot — precisely the gap
    # `bypass_address` had. Only the rules that carry the coverage are dropped:
    # what is left falls through to `final`, i.e. *into* the tunnel, which is
    # the safe direction to fail in.
    try:
        _check_direct_ip_coverage(surviving)
    except RulesParseError as exc:
        dropped.append(str(exc))
        surviving = [r for r in surviving if not _sends_ip_range_direct(r)]

    # The bypass list comes from the same document and was the field this
    # function forgot. It is fed to the ipset on every boot, so a list accepted
    # before the coverage cap existed went on bypassing 99.9969% of IPv4
    # indefinitely — the VPN effectively off with the dashboard reporting it on,
    # which is the outcome the cap was written to prevent. Cleared rather than
    # trimmed: a list this wrong has no safe subset, and an empty bypass only
    # costs the hardware fast path, while a wrong one costs the tunnel.
    kept_bypass = list(bypass or [])
    if kept_bypass:
        try:
            kept_bypass = validate_bypass_list(kept_bypass)
        except RulesParseError as exc:
            dropped.append(f"bypass_address: {exc}")
            kept_bypass = []

    return surviving, kept_sets, kept_bypass, dropped


def _extract_bypass_address(top: Any) -> list[str]:
    """Optional `bypass_address`: IPv4 CIDRs that never enter the proxy at all.

    This is the only knob that keeps traffic on the router's *hardware* fast
    path, and it is worth being precise about why. A route rule with
    `outbound: direct` does NOT do this — "direct" means "not via the proxy
    server", and the packet still travels through sing-box. Anything the proxy
    terminates locally leaves netfilter's `forward` chain, where flow offload
    (MediaTek PPE and friends) lives, so it can never be accelerated.
    Addresses named here RETURN out of the capture before that happens.

    Plain CIDRs rather than rule-set tags. The tun-era spelling took sing-box
    rule-set names and expanded them into one kernel route per prefix — 21,619
    of them for a country list, which took a real router down. The divert loads
    these into an ipset instead: a single match rule, ~340 KB for 15,000 nets.
    Not O(1) — a `hash:net` lookup costs ~66 ns per *distinct prefix length* in
    the set on top of ~710 ns fixed, measured — but flat in the entry count,
    which is the property that matters here.
    Tags would mean resolving a binary .srs here just to get back to the same
    list, so the document carries the list.

    Declared in the user's own rules document. kitewrt ships no geo data and
    takes no view on which country is "home"; this keeps it that way while
    still letting a deployment reclaim the fast path.
    """
    raw: Any = None
    if isinstance(top, dict):
        route = top.get("route")
        if isinstance(route, dict) and "bypass_address" in route:
            raw = route["bypass_address"]
        elif "bypass_address" in top:
            raw = top["bypass_address"]
    if raw is None:
        return []
    return validate_bypass_list(raw)


def validate_bypass_list(raw: Any) -> list[str]:
    """The `bypass_address` checks, split out so the *persisted* list can be
    re-checked on load and not only the freshly-parsed one.

    That gap was real: the list is stored in `state.json` and fed to the ipset
    on every boot, so a document accepted before the coverage cap existed kept
    bypassing 99.9969% of IPv4 forever, through any number of upgrades — the
    exact evasion the cap was written to stop, surviving the fix that stopped
    it. Re-validation covered `rules` and `rule_set` but not this field.
    """
    if not isinstance(raw, list):
        raise RulesParseError("`bypass_address` must be an array of IPv4 CIDRs")

    nets: list[str] = []
    seen: set[str] = set()
    covered = 0
    # Integer bounds once, so the fake-IP overlap test and the coverage total
    # below need no further `ipaddress` objects.
    fake_lo = int(_FAKEIP_NET.network_address)
    fake_hi = int(_FAKEIP_NET.broadcast_address)
    for i, entry in enumerate(raw):
        if not isinstance(entry, str) or not entry.strip():
            raise RulesParseError(f"bypass_address[{i}] must be a non-empty CIDR string")
        net = entry.strip()
        try:
            # strict=False so 10.0.0.1/8 is accepted and normalised rather than
            # rejected — hand-written lists routinely carry host bits.
            parsed = ipaddress.ip_network(net, strict=False)
        except ValueError as exc:
            raise RulesParseError(f"bypass_address[{i}]: {net!r} is not a valid CIDR") from exc
        if parsed.version != 4:
            # The capture is IPv4-only (divert speaks iptables, not ip6tables),
            # so a v6 entry would silently do nothing.
            raise RulesParseError(f"bypass_address[{i}]: {net!r} is IPv6; the capture is IPv4-only")
        if parsed.prefixlen == 0:
            # `ipset add ... 0.0.0.0/0` is rejected by hash:net, which would
            # fail the whole capture install at a point where nothing can
            # repair it. Catch it here, where the user sees a parse error on
            # the document they just pasted. It is also never what they meant:
            # bypassing everything is just turning the VPN off.
            raise RulesParseError(
                f"bypass_address[{i}]: {net!r} matches every address; "
                "to send all traffic direct, turn the VPN off instead"
            )
        lo = int(parsed.network_address)
        hi = int(parsed.broadcast_address)
        if lo <= fake_hi and fake_lo <= hi:
            # The whole point of the fake-IP range is that those connections
            # reach sing-box, which is the only thing that can map a synthetic
            # address back to a domain. Bypassing it sends them straight out
            # the WAN to an address that exists nowhere — every proxied *name*
            # breaks while raw-IP traffic keeps working, so it reads as "some
            # sites are down". `divert._RESERVED` deliberately omits this range
            # and `body_matches` rejects a chain that escapes it; without this
            # check the ipset was an unguarded way to do the same thing.
            raise RulesParseError(
                f"bypass_address[{i}]: {net!r} overlaps the fake-IP range "
                f"{FAKEIP_INET4}; those connections must reach the proxy to be "
                "mapped back to a domain, so bypassing them breaks every "
                "proxied hostname"
            )
        text = str(parsed)
        # Set membership, and the coverage accumulated here. `if text not in
        # nets` was a linear scan of a growing list, once per entry — quadratic,
        # and it dominated: measured **on the router**, validating an 8,640-net
        # document took 29.2 s, of which ~21 s was this line and the rest a
        # second `ip_network()` construction per entry in the total below. The
        # fit was 0.970·n + 2.79e-4·n² ms, i.e. ~21 minutes at the 65,536-net
        # ceiling this module advertises. It runs on the event loop from
        # `POST /api/rules-url`, and `state.py` now runs it again on every boot.
        if text in seen:
            continue
        seen.add(text)
        nets.append(text)
        covered += hi - lo + 1

    # Each guard above looks at ONE entry. Together they miss the obvious
    # composition: the complement of the fake-IP range is 15 CIDRs, every one of
    # them with a non-zero prefix length, none overlapping 198.18.0.0/15, and
    # fifteen is nowhere near the count cap — so `0.0.0.0/0` minus the one range
    # we check for walks straight through and covers 99.9969% of IPv4. That is
    # not a bypass list, it is the VPN switched off while the dashboard still
    # says it is on, which for this tool is the worst outcome there is.
    #
    # So check the total instead of the parts. The threshold is deliberately
    # blunt: a real bypass list is a country or a few providers, and even a
    # generous one (the RU list this was built for is 8639 networks) covers well
    # under 2% of the address space. Anything past a quarter is someone either
    # making a serious mistake or being led into one.
    if covered > _BYPASS_MAX_COVERAGE:
        pct = covered / (1 << 32) * 100
        raise RulesParseError(
            f"bypass_address covers {pct:.2f}% of the IPv4 address space "
            f"({len(nets)} networks); that sends effectively all traffic "
            "direct while the VPN reports itself on — to route everything "
            "direct, turn the VPN off instead"
        )

    if len(nets) > divert.BYPASS_MAX_NETWORKS:
        # The kernel refuses the set past this, and the install then quietly
        # drops the bypass. Saying so here — against the document the user just
        # pasted — beats a warning buried in syslog days later.
        raise RulesParseError(
            f"bypass_address has {len(nets)} networks; the kernel set holds at "
            f"most {divert.BYPASS_MAX_NETWORKS}"
        )
    return nets


def _sends_ip_range_direct(rule: dict[str, Any]) -> bool:
    """Whether this rule contributes to the direct-coverage total."""
    return rule.get("outbound") == "direct" and "ip_cidr" in rule


def _check_direct_ip_coverage(rules: list[dict[str, Any]]) -> None:
    """Refuse a document whose `direct` rules cover the IPv4 address space.

    `{"ip_cidr": ["0.0.0.0/0"], "outbound": "direct"}` passed every per-rule
    check here, `sing-box check` and `sing-box run`: one rule, fetched from a
    URL, and every raw-IP destination leaves the tunnel while the dashboard
    still reports the VPN on. `_extract_bypass_address` spends three guards
    preventing exactly that outcome; this path had none.

    **A coverage total, not a prefix-length cap.** A legitimate document does
    route large ranges direct — a country list is precisely that, and the
    shipped example does it — so "refuse anything shorter than /8" would break
    the normal case, while `0.0.0.0/1 + 128.0.0.0/1` (or the 15-CIDR complement
    of the fake-IP range) walked straight through it. Summed across the whole
    document for the same reason `validate_bypass_list` sums across the whole
    list: each part can be innocent while the union is "everything".

    **Only `outbound: direct`.** A `proxy` catch-all is what `final` already
    does, and a `block` catch-all takes the internet down in seconds where
    nobody can miss it — that is a default-deny document, not a VPN quietly
    switched off, and the message this module wants to send ("turn the VPN off
    instead") would be wrong for it.

    **IPv4 only.** The capture is IPv4-only (divert speaks iptables, not
    ip6tables) and v6 is blocked at the firewall rather than proxied, so v6
    traffic never enters sing-box and a v6 `direct` rule cannot take anything
    out of a tunnel it was never in.

    What this does NOT close, stated plainly rather than implied: measured on
    1.13.16, an `ip_cidr` rule never matches a domain-addressed connection under
    fake-IP — sing-box logs `found fakeip domain: example.com` and has replaced
    the synthetic address with the name before route rules run — so the guard is
    about raw-IP traffic and names a *name* rule already resolved real. A name
    catch-all is still expressible in one character (`domain_keyword: ["."]`),
    and nothing syntactic can tell that from a legitimately broad rule; see
    docs/rules-format.md, which now says so out loud.
    """
    seen: set[str] = set()
    covered = 0
    first = None
    for i, rule in enumerate(rules):
        if not _sends_ip_range_direct(rule):
            continue
        raw = rule["ip_cidr"]
        for entry in raw if isinstance(raw, list) else [raw]:
            if not isinstance(entry, str):
                continue
            try:
                # strict=False for the same reason the bypass list uses it:
                # real lists carry host bits.
                net = ipaddress.ip_network(entry.strip(), strict=False)
            except ValueError:
                # Not this function's call: sing-box refuses a malformed
                # ip_cidr at `check`, which the apply path gates on, so it fails
                # loudly with its own message rather than silently here.
                continue
            if net.version != 4:
                continue
            text = str(net)
            if text in seen:
                continue
            seen.add(text)
            covered += int(net.broadcast_address) - int(net.network_address) + 1
            if first is None:
                first = i
    if covered > _DIRECT_MAX_COVERAGE:
        pct = covered / (1 << 32) * 100
        raise RulesParseError(
            f"this document routes {pct:.2f}% of the IPv4 address space `direct` "
            f"(from rule[{first}] on); that leaves effectively nothing in the tunnel "
            "while the VPN reports itself on — to send all traffic direct, turn the "
            "VPN off instead"
        )


def _extract_rules_array(top: Any) -> list[Any]:
    if isinstance(top, list):
        return top
    if isinstance(top, dict):
        route = top.get("route")
        if isinstance(route, dict) and isinstance(route.get("rules"), list):
            return route["rules"]
        if isinstance(top.get("rules"), list):
            return top["rules"]
        raise RulesParseError(
            'expected {"route": {"rules": [...]}} or {"rules": [...]} or a bare [...] array'
        )
    raise RulesParseError("expected JSON object or array at the top level")


def _extract_rule_sets(top: Any) -> list[Any]:
    """Optional rule-set definitions, from route.rule_set or top-level rule_set.
    A bare-array document has none."""
    if isinstance(top, dict):
        route = top.get("route")
        if isinstance(route, dict) and isinstance(route.get("rule_set"), list):
            return route["rule_set"]
        if isinstance(top.get("rule_set"), list):
            return top["rule_set"]
    return []


# What a rule-set definition may carry. Same argument as `_ALLOWED_RULE_KEYS`,
# and left out of the first pass only because the exploit there was louder.
# `download_detour` is the one that matters: it takes any outbound tag, so a
# hostile document sets it to `direct` and the `.srs` fetch leaves the router
# outside the tunnel — telling the ISP which rule-set this router downloads,
# from a document the user pasted to *route* with. The rest of sing-box's
# rule-set schema is simply un-reasoned-about surface.
_ALLOWED_RULE_SET_KEYS = frozenset(
    {"tag", "type", "format", "url", "path", "download_detour", "update_interval"}
)

# Where a `type: local` rule-set may live: sing-box's own config directory, the
# one place on the router this project already owns (config.json and cache.db
# are there). Derived from the service constant so the two cannot drift.
_LOCAL_RULE_SET_DIR = PurePosixPath(SINGBOX_CONFIG).parent


def _inside_singbox_dir(path: Any) -> bool:
    """Whether `path` is an absolute path under sing-box's config directory.

    `..` is refused outright rather than resolved: `PurePosixPath` collapses
    nothing, and resolving would be a lie anyway — the file may not exist yet
    and a symlink placed later could still point out, which only the kernel can
    settle at open time.
    """
    if not isinstance(path, str) or not path:
        return False
    p = PurePosixPath(path)
    return p.is_absolute() and ".." not in p.parts and _LOCAL_RULE_SET_DIR in p.parents


def _validate_rule_set(i: int, rs: dict[str, Any]) -> None:
    for key in rs:
        if key not in _ALLOWED_RULE_SET_KEYS:
            raise RulesParseError(
                f"rule_set[{i}] has unsupported key {key!r}; allowed: "
                f"{sorted(_ALLOWED_RULE_SET_KEYS)} (see docs/rules-format.md)"
            )
    detour = rs.get("download_detour")
    if detour is not None and detour not in ("proxy", "direct"):
        # An arbitrary tag here is not merely unknown — sing-box refuses to
        # start on one, so a typo takes the whole data plane down rather than
        # degrading the one rule-set.
        raise RulesParseError(
            f"rule_set[{i}].download_detour must be 'proxy' or 'direct'; got {detour!r}"
        )
    tag = rs.get("tag")
    if not isinstance(tag, str) or not tag:
        raise RulesParseError(f"rule_set[{i}] needs a non-empty string `tag`")
    rs_type = rs.get("type")
    if rs_type not in ("remote", "local"):
        raise RulesParseError(f"rule_set[{i}].type must be 'remote' or 'local'; got {rs_type!r}")
    if rs_type == "remote":
        url = rs.get("url")
        if not url:
            raise RulesParseError(f"rule_set[{i}] (remote) needs a `url`")
        # sing-box fetches this URL; validate it's a real http(s) URL pointing at
        # a public host so a rules document can't aim it at the local controller
        # or cloud metadata.
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise RulesParseError(f"rule_set[{i}].url must be an http(s) URL; got {url!r}")
        host = urlparse(url).hostname
        # `blocks_ssrf` alone is IP-literals only, and measured, that let the two
        # obvious targets straight through:
        #
        #   blocks_ssrf('127.0.0.1')                = True   rejected
        #   blocks_ssrf('localhost')                = False  ACCEPTED
        #   blocks_ssrf('metadata.google.internal') = False  ACCEPTED
        #
        # `localhost` is not theoretical here: singbox.dns sends `*.localhost`
        # and `*.lan` to `dns-local` (dnsmasq), so sing-box resolves it to the
        # router and the GET lands on the local Clash controller on :9090.
        #
        # Deliberately NOT the resolving guard. `resolve_blocks_ssrf` is async
        # and this runs synchronously on the event loop (the rules route awaits
        # the fetch, then calls the parser inline), so there is no seam for it —
        # but the real reason is that its answer would be about the wrong
        # lookup. We would ask the router's `getaddrinfo`; sing-box resolves
        # this host through its own DNS block — `dns-bootstrap` over DoH
        # (route.default_domain_resolver), or at the exit node when
        # `download_detour: "proxy"` — minutes to hours later. Different
        # resolver, different moment, so a hostile name answers public to us and
        # 127.0.0.1 to sing-box for free, and we would have handed every
        # rule-set hostname to the ISP's resolver in plaintext to learn nothing
        # (see `fetch_url`'s `resolving_fetcher` for why that matters).
        #
        # `blocks_ssrf_name` instead refuses what is non-public *by definition*
        # — the answer no resolver can change. That leaves one hole, stated
        # plainly: a public name its owner points at 127.0.0.1. Nothing
        # checkable at parse time closes that; only sing-box, as it dials, could.
        if host and (blocks_ssrf(host) or blocks_ssrf_name(host)):
            raise RulesParseError(f"rule_set[{i}].url points at a non-public address: {host}")
    if rs_type == "local":
        path = rs.get("path")
        if not path:
            raise RulesParseError(f"rule_set[{i}] (local) needs a `path`")
        # `path` used to be checked for truthiness and nothing else, and
        # `sing-box check`'s stderr is captured into `last_error` and served on
        # `/api/state` and the WebSocket — so a document fetched from a URL
        # could ask about any path on the router and read the answer off the
        # dashboard. Measured, the replies tell the cases apart:
        #   /etc/kitewrt-nope   → "open ...: no such file or directory"
        #   /etc/master.passwd  → "open ...: permission denied"
        #   /etc/hosts (binary) → "invalid sing-box rule-set file"
        #   /etc/hosts (source) → "json: cannot unmarshal number into ..."
        #   /etc                → "read /etc: is a directory"
        # Confining it to sing-box's own directory leaves only "did the owner
        # put a file of this name where they keep their own rule-sets", and
        # blocks `/etc/sing-box/../..` on the way. Relative paths go too: they
        # resolve against the *process* working directory, which is procd's for
        # the running sing-box and the daemon's for the check — so the file that
        # passed validation need not be the file that gets loaded.
        if not _inside_singbox_dir(path):
            raise RulesParseError(
                f"rule_set[{i}].path must name a file inside {_LOCAL_RULE_SET_DIR}/; "
                f"got {path!r} (copy the .srs there and reference it by that path)"
            )


def _validate_rule(i: int, rule: dict[str, Any]) -> None:
    for marker in _XRAY_MARKERS:
        if marker in rule:
            raise RulesParseError(
                f"rule[{i}] looks like an xray rule (has {marker!r}); this is "
                "sing-box now — use domain_suffix/ip_cidr/rule_set + "
                "outbound: proxy|direct|block"
            )

    # Before the action branch below, which returns early — a whitelist placed
    # after it would be skipped by exactly the rules that need no outbound.
    for key, value in rule.items():
        if key not in _ALLOWED_RULE_KEYS:
            raise RulesParseError(
                f"rule[{i}] has unsupported key {key!r}; a rule may carry matchers "
                "plus `outbound`/`action` only (see docs/rules-format.md)"
            )
        if _contains_object(value):
            # A flat key check is only airtight while the rule is flat. sing-box's
            # one nesting shape for a route rule is `type: logical`, whose inner
            # `rules` array would carry objects nothing here reads — already
            # refused, but only as a side effect of `type` being an xray marker.
            # No accepted matcher takes an object, so refusing them outright
            # closes the shape instead of resting on that coincidence.
            raise RulesParseError(
                f"rule[{i}].{key} contains a nested object; every accepted matcher "
                "takes a scalar or a list of scalars"
            )
        if key in _MATCH_FIELDS and _has_blank_string(value):
            # Measured on 1.13.16, and an empty matcher value splits three ways.
            # `domain_keyword: [""]` and `domain_regex: [""]` pass `sing-box
            # check` and then match EVERY connection (the trace prints
            # `match[1] domain_keyword= => reject` for a raw-IP destination
            # too) — worse than a wide route rule, because
            # `_dns_rules_from_routes` mirrors a name matcher into the DNS
            # block, so `{"domain_keyword": [""], "outbound": "direct"}` sends
            # every LAN lookup plain-UDP to the direct resolver and hands the
            # ISP the browsing history. `domain`, `domain_suffix`, `ip_cidr` and
            # `port_range` are refused by sing-box itself; `network: ""`,
            # `protocol: [""]` and `process_name: [""]` match nothing at all, so
            # the rule silently never fires. Catch-all or dead, no spelling of
            # an empty matcher is what anyone meant to write.
            raise RulesParseError(
                f"rule[{i}].{key} has an empty value; an empty matcher either matches "
                "everything or nothing — drop the field instead"
            )

    action = rule.get("action")
    if action is not None:
        # Checked before the outbound branch, not inside it: the early return
        # this replaced only fired when `outbound` was ABSENT, so the *value* of
        # `action` went unexamined for any rule that also named an outbound —
        # `sing-box check` happened to catch the bogus ones, but nothing here
        # would have looked at a future action either.
        if action not in _VALID_ACTIONS:
            raise RulesParseError(f"rule[{i}].action {action!r} is not a known sing-box action")
        if action != "route":
            if "outbound" in rule:
                # Measured: `{"domain_keyword": ["example"], "action": "reject",
                # "outbound": "direct"}` passes `sing-box check`, and at run the
                # action wins — the connection is rejected while the rule reads
                # `direct`. (sing-box refuses `sniff`/`resolve` beside an
                # outbound as an unknown field, so the combination only ever
                # hides something.)
                raise RulesParseError(
                    f"rule[{i}] carries both action {action!r} and an outbound; sing-box "
                    "obeys the action and ignores the outbound, so the rule does not do "
                    "what it reads like — keep whichever one you meant"
                )
            if action in _TERMINAL_ACTIONS and not _has_matcher(rule):
                raise RulesParseError(
                    f"rule[{i}] is a bare {action!r} with no matcher, which matches every "
                    "connection — say what it applies to, or use `outbound: block` for a "
                    "rule that only drops what it names"
                )
            return
        # `route` is the explicit spelling of an ordinary route rule, so it
        # falls through to the outbound requirement below rather than returning.

    if "outbound" not in rule:
        if action == "route":
            # `sing-box check` passes this; at run every matched connection dies
            # with "outbound not found:" while the process stays up and
            # healthy-looking — the same failure class as an undefined rule-set
            # tag, and equally invisible to the check the apply path gates on.
            raise RulesParseError(
                f"rule[{i}] uses action 'route' with no outbound; sing-box accepts the "
                'config and then fails every connection it matches with "outbound not '
                'found"'
            )
        raise RulesParseError(f"rule[{i}].outbound is missing")
    tag = rule["outbound"]
    if tag not in _VALID_OUTBOUNDS:
        raise RulesParseError(
            f"rule[{i}].outbound must be one of {sorted(_VALID_OUTBOUNDS)}; got {tag!r}"
        )
    if not _has_matcher(rule):
        raise RulesParseError(
            f"rule[{i}] has no matcher — need at least one of {list(_MATCH_FIELDS[:5])}…"
        )
    regex = rule.get("domain_regex")
    if regex is not None:
        for r in regex if isinstance(regex, list) else [regex]:
            if isinstance(r, str) and len(r) > MAX_REGEX_LEN:
                raise RulesParseError(
                    f"rule[{i}].domain_regex is too long (max {MAX_REGEX_LEN} chars)"
                )


def _strip_comments(obj: Any) -> Any:
    """Recursively drop `_comment` keys (sing-box rejects unknown fields)."""
    if isinstance(obj, dict):
        return {k: _strip_comments(v) for k, v in obj.items() if k != "_comment"}
    if isinstance(obj, list):
        return [_strip_comments(x) for x in obj]
    return obj


def _contains_object(v: Any) -> bool:
    """Whether `v` holds a JSON object anywhere inside it."""
    if isinstance(v, dict):
        return True
    return isinstance(v, list) and any(_contains_object(x) for x in v)


def _has_blank_string(v: Any) -> bool:
    """Whether `v` is, or contains, an empty/whitespace-only string."""
    for item in v if isinstance(v, list) else [v]:
        if isinstance(item, str) and not item.strip():
            return True
    return False


def _has_matcher(rule: dict[str, Any]) -> bool:
    """Whether the rule carries at least one field that narrows what it matches."""
    return any(_present_and_nonempty(rule.get(f)) for f in _MATCH_FIELDS)


def _present_and_nonempty(v: Any) -> bool:
    # `False` is not a matcher. Measured with `sing-box run`: a false boolean
    # builds no rule item at all, so `{"ip_is_private": false, "outbound":
    # "direct"}` is a rule with ZERO items, which matches every connection —
    # the trace prints a bare `router: match[1] => reject` for a domain and a
    # raw-IP destination alike. It read here as a rule with a matcher and ran
    # there as "everything direct", including the domain traffic an `ip_cidr`
    # catch-all cannot touch. Same for `source_ip_is_private: false`.
    if v is None or v == "" or v is False:
        return False
    return not (isinstance(v, (list, dict)) and len(v) == 0)
