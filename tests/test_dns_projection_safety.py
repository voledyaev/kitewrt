"""DNS decisions must not broaden connection-scoped direct exceptions."""

import json

import pytest
from kitewrt.rules import parse_singbox_rules
from kitewrt.singbox.dns import DNS_DIRECT, DNS_FAKE, DNS_PROXY, build_dns


def rules_for(route_rules, *, known=None):
    return build_dns("https://1.1.1.1/dns-query", "select", route_rules, dns_rule_sets=known)[
        "rules"
    ]


def resolve(rules, domain, query_type="A", matched_sets=()):
    """Evaluate the small emitted name-matcher subset, preserving first match."""
    for rule in rules:
        if "query_type" in rule and query_type not in rule["query_type"]:
            continue
        if "domain" in rule and domain not in rule["domain"]:
            continue
        if "domain_suffix" in rule and not any(
            domain == suffix.lstrip(".") or domain.endswith("." + suffix.lstrip("."))
            for suffix in rule["domain_suffix"]
        ):
            continue
        if "rule_set" in rule and not any(tag in matched_sets for tag in rule["rule_set"]):
            continue
        return rule["server"]
    return DNS_PROXY


@pytest.mark.parametrize(
    "qualifier",
    [
        {"source_ip_cidr": ["192.0.2.50/32"]},
        {"source_ip_is_private": True},
        {"port": [443]},
        {"port_range": ["400:499"]},
        {"source_port": [50000]},
        {"network": "tcp"},
        {"protocol": ["tls"]},
        {"ip_cidr": ["203.0.113.0/24"]},
        {"process_name": ["browser"]},
    ],
)
@pytest.mark.parametrize("query_type,expected", [("A", DNS_FAKE), ("HTTPS", DNS_PROXY)])
def test_mixed_direct_rule_never_becomes_global_direct_dns(qualifier, query_type, expected):
    raw = [
        {"domain_suffix": ["private.example"], **qualifier, "outbound": "direct"},
        {"domain_suffix": ["example"], "outbound": "direct"},
    ]
    # Exercise the public validator as well as the builder: this is accepted
    # routing input, not an impossible malformed config.
    route = parse_singbox_rules(json.dumps(raw))["rules"]
    dns = rules_for(route)
    assert resolve(dns, "private.example", query_type) == expected
    assert resolve(dns, "other.example", query_type) == DNS_DIRECT


@pytest.mark.parametrize("query_type", ["A", "AAAA", "HTTPS", "SVCB", "TXT"])
def test_pure_proxy_override_precedes_later_direct_for_every_query_type(query_type):
    dns = rules_for(
        [
            {"domain": ["proxy.example"], "outbound": "proxy"},
            {"domain_suffix": ["example"], "outbound": "direct"},
        ]
    )
    expected = DNS_FAKE if query_type in ("A", "AAAA") else DNS_PROXY
    assert resolve(dns, "proxy.example", query_type) == expected
    assert resolve(dns, "direct.example", query_type) == DNS_DIRECT


@pytest.mark.parametrize("known", [None, {"names"}])
def test_unknown_or_mixed_set_does_not_disappear_from_a_direct_predicate(known):
    dns = rules_for(
        [
            {"domain": ["first.example"], "outbound": "direct"},
            {"rule_set": ["names", "addresses"], "outbound": "direct"},
            {"domain_suffix": ["example"], "outbound": "direct"},
        ],
        known=known,
    )
    assert resolve(dns, "first.example") == DNS_DIRECT
    assert resolve(dns, "later.example", "A") == DNS_FAKE
    assert resolve(dns, "later.example", "TXT") == DNS_PROXY
    assert all("rule_set" not in rule for rule in dns)


def test_known_pure_domain_set_keeps_its_direct_decision():
    dns = rules_for([{"rule_set": ["names"], "outbound": "direct"}], known={"names"})
    assert resolve(dns, "direct.example", matched_sets={"names"}) == DNS_DIRECT
    assert resolve(dns, "proxy.example") == DNS_FAKE


def test_inverted_rule_never_loses_the_inversion_and_becomes_direct():
    dns = rules_for(
        [
            {"domain_suffix": ["example"], "invert": True, "outbound": "direct"},
            {"domain_suffix": ["example"], "outbound": "direct"},
        ]
    )
    assert resolve(dns, "private.example") == DNS_FAKE
    assert resolve(dns, "private.example", "TXT") == DNS_PROXY


def test_proxy_source_only_rule_prevents_later_global_direct_projection():
    dns = rules_for(
        [
            {"source_ip_cidr": ["192.0.2.50/32"], "outbound": "proxy"},
            {"domain_suffix": ["example"], "outbound": "direct"},
        ]
    )
    assert resolve(dns, "private.example") == DNS_FAKE
    assert resolve(dns, "private.example", "TXT") == DNS_PROXY
