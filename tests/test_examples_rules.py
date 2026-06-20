"""Guards the bundled example preset under examples/.

It ships as a documented starting point, so a refactor of the rules parser /
route / DNS builders must not silently break it.
"""

from __future__ import annotations

import pathlib

from kitewrt.rules import parse_singbox_rules
from kitewrt.singbox.config import SELECTOR_TAG
from kitewrt.singbox.dns import DNS_DIRECT, DNS_FAKE, build_dns
from kitewrt.singbox.route import build_route

_RULES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "rules-example.json"


def _parsed():
    return parse_singbox_rules(_RULES.read_text())


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
