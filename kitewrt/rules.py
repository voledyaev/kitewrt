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
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from kitewrt.fetch import blocks_ssrf

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

# Standalone (non-route) actions allowed without an outbound/matcher.
_VALID_ACTIONS = {"sniff", "resolve", "reject", "hijack-dns", "route"}

# Dead giveaways of an xray rule pasted by mistake — fail with a pointer.
_XRAY_MARKERS = ("type", "outboundTag")


class RulesParseError(ValueError):
    """Raised when a rules document fails validation."""


def parse_singbox_rules(raw: bytes | str) -> dict[str, list[dict[str, Any]]]:
    """Parse, strip `_comment`s from, and validate a sing-box rules document.

    Accepted top-level shapes: {"route": {"rules": [...], "rule_set": [...]}},
    {"rules": [...], "rule_set": [...]}, or a bare [...] (rules only). Returns
    {"rules": [...], "rule_set": [...]} ready for the `route` block.

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

    return {"rules": rules, "rule_set": rule_sets}


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


def _validate_rule_set(i: int, rs: dict[str, Any]) -> None:
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
        if host and blocks_ssrf(host):
            raise RulesParseError(f"rule_set[{i}].url points at a non-public address: {host}")
    if rs_type == "local" and not rs.get("path"):
        raise RulesParseError(f"rule_set[{i}] (local) needs a `path`")


def _validate_rule(i: int, rule: dict[str, Any]) -> None:
    for marker in _XRAY_MARKERS:
        if marker in rule:
            raise RulesParseError(
                f"rule[{i}] looks like an xray rule (has {marker!r}); this is "
                "sing-box now — use domain_suffix/ip_cidr/rule_set + "
                "outbound: proxy|direct|block"
            )

    # Standalone action rule (sniff/resolve/...) needs no outbound/matcher.
    action = rule.get("action")
    if action is not None and "outbound" not in rule:
        if action not in _VALID_ACTIONS:
            raise RulesParseError(f"rule[{i}].action {action!r} is not a known sing-box action")
        return

    if "outbound" not in rule:
        raise RulesParseError(f"rule[{i}].outbound is missing")
    tag = rule["outbound"]
    if tag not in _VALID_OUTBOUNDS:
        raise RulesParseError(
            f"rule[{i}].outbound must be one of {sorted(_VALID_OUTBOUNDS)}; got {tag!r}"
        )
    if not any(_present_and_nonempty(rule.get(f)) for f in _MATCH_FIELDS):
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


def _present_and_nonempty(v: Any) -> bool:
    if v is None or v == "":
        return False
    if isinstance(v, (list, dict)) and len(v) == 0:
        return False
    return True
