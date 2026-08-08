"""Guards the bundled example preset under examples/.

It ships as a documented starting point, so a refactor of the rules parser /
route / DNS builders must not silently break it.
"""

from __future__ import annotations

import json
import pathlib

from kitewrt.rules import parse_singbox_rules
from kitewrt.singbox.config import SELECTOR_TAG, build_config
from kitewrt.singbox.dns import DNS_DIRECT, DNS_FAKE, build_dns
from kitewrt.singbox.route import build_route

_RULES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "rules-example.json"


def _parsed():
    return parse_singbox_rules(_RULES.read_text())


def test_every_shipped_example_parses():
    """Every file under examples/, not just the one this module names.

    The route-rule key whitelist is the reason this is a glob: an example that
    used a field the validator does not list would now be rejected at the
    moment a user pastes it, and the failure would be theirs, not ours.
    """
    files = sorted(_RULES.parent.glob("*.json"))
    assert files, "no examples found — the glob is silently passing"
    for path in files:
        assert parse_singbox_rules(path.read_text())["rules"], path


def test_example_preset_parses():
    parsed = _parsed()
    assert parsed["rules"]
    # geoip is a remote rule-set sing-box downloads itself (we bundle no data).
    assert parsed["rule_set"][0]["tag"] == "geoip-home"
    assert parsed["rule_set"][0]["type"] == "remote"


def test_example_preset_builds_route_with_proxy_alias_rewritten():
    parsed = _parsed()
    route = build_route(parsed["rules"], parsed["rule_set"], SELECTOR_TAG)
    assert route["final"] == SELECTOR_TAG
    # `outbound: proxy` and `download_detour: proxy` rewritten to the selector.
    assert any(r.get("outbound") == SELECTOR_TAG for r in route["rules"])
    assert route["rule_set"][0]["download_detour"] == SELECTOR_TAG


def test_example_preset_dns_mirror_splits_direct_and_proxy():
    # Name rules are mirrored into DNS: a `direct` domain resolves real via
    # dns-direct, a `proxy` domain gets a fake IP (real lookup at the exit).
    rules = _parsed()["rules"]
    dns_rules = build_dns("https://cloudflare-dns.com/dns-query", SELECTOR_TAG, rules)["rules"]
    assert any(
        d.get("server") == DNS_DIRECT and "example.com" in (d.get("domain") or [])
        for d in dns_rules
    )
    assert any(
        d.get("server") == DNS_FAKE and ".example.net" in (d.get("domain_suffix") or [])
        for d in dns_rules
    )


def test_the_documented_bypass_pairing_actually_steers_dns():
    """docs/rules-format.md's `bypass_address` example, verified end to end.

    The example used to pair the bypass with an `ip_cidr` route rule, which
    cannot work: IP rules are not mirrored into the DNS block (sing-box can't
    know a name's address before resolving it), so every A/AAAA answer stayed
    a `198.18.x` fake IP — not in the set, captured anyway, bypass inert. Only
    a *name* matcher produces the `dns-direct` rule that makes clients see real
    addresses for the set to recognise.
    """
    from kitewrt.state import Data

    def dns_for(rule: dict) -> list[dict]:
        parsed = parse_singbox_rules(
            json.dumps({"route": {"rules": [rule]}, "bypass_address": ["203.0.113.0/24"]})
        )
        d = Data()
        d.rules, d.rule_sets = parsed["rules"], parsed["rule_set"]
        d.rules_bypass_address, d.vpn_on = parsed["bypass_address"], True
        return build_config(d)["dns"]["rules"]

    by_name = dns_for({"domain_suffix": ["example.test"], "outbound": "direct"})
    assert any(r.get("server") == DNS_DIRECT for r in by_name), by_name

    by_ip = dns_for({"ip_cidr": ["203.0.113.0/24"], "outbound": "direct"})
    assert not any(r.get("server") == DNS_DIRECT for r in by_ip), by_ip


def test_every_accepted_rule_key_is_documented():
    """The whitelist and the page that describes it must not drift.

    `docs/rules-format.md` now claims to list the complete accepted set, and a
    user whose rule is rejected has nowhere else to look. Adding a key to
    `_ALLOWED_RULE_KEYS` without documenting it makes the page silently wrong;
    documenting one that is not accepted is worse, because the reader writes it
    and the fetch fails.
    """
    from kitewrt.rules import _ALLOWED_RULE_KEYS, _ALLOWED_RULE_SET_KEYS

    doc = (pathlib.Path(__file__).resolve().parent.parent / "docs" / "rules-format.md").read_text()
    accepted = _ALLOWED_RULE_KEYS | _ALLOWED_RULE_SET_KEYS
    undocumented = sorted(k for k in accepted if f'"{k}"' not in doc and f"`{k}`" not in doc)
    assert not undocumented, f"accepted but undocumented: {undocumented}"
