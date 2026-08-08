"""Tests for the sing-box rules validator/normaliser (parse_singbox_rules).

parse_singbox_rules returns {"rules": [...], "rule_set": [...]}.
"""

from __future__ import annotations

import json

import pytest
from kitewrt import divert
from kitewrt.rules import _MATCH_FIELDS, RulesParseError, parse_singbox_rules


def test_route_wrapped_shape():
    out = parse_singbox_rules(
        b'{"route": {"rules": [{"domain_suffix": [".ru"], "outbound": "direct"}]}}'
    )
    assert out["rules"] == [{"domain_suffix": [".ru"], "outbound": "direct"}]
    assert out["rule_set"] == []


def test_rules_wrapped_shape():
    # The rule_set has to be *defined*: a reference to a tag no definition
    # satisfies passes `sing-box check` and then FATALs at run, so the parser
    # refuses it now.
    out = parse_singbox_rules(
        b'{"rules": [{"rule_set": ["geoip-x"], "outbound": "direct"}],'
        b' "rule_set": [{"tag": "geoip-x", "type": "remote", "format": "binary",'
        b' "url": "https://example.com/x.srs"}]}'
    )
    assert len(out["rules"]) == 1


def test_bare_array_shape():
    out = parse_singbox_rules(b'[{"domain_suffix": ["example.test"], "outbound": "proxy"}]')
    assert out["rules"][0]["outbound"] == "proxy"
    assert out["rule_set"] == []


def test_comments_are_stripped_recursively():
    raw = json.dumps(
        {
            "_comment": "top",
            "rules": [{"_comment": "rule note", "domain_suffix": ["x.com"], "outbound": "direct"}],
        }
    )
    out = parse_singbox_rules(raw)
    assert out["rules"] == [{"domain_suffix": ["x.com"], "outbound": "direct"}]


def test_proxy_outbound_allowed_as_alias():
    out = parse_singbox_rules(b'[{"domain_suffix": ["bbc.com"], "outbound": "proxy"}]')
    assert out["rules"][0]["outbound"] == "proxy"


def test_action_rule_without_outbound_ok():
    out = parse_singbox_rules(b'[{"action": "sniff"}]')
    assert out["rules"] == [{"action": "sniff"}]


# --- rule-set definitions ---------------------------------------------------


def test_remote_rule_set_extracted_and_validated():
    raw = json.dumps(
        {
            "rules": [{"rule_set": ["geoip-x"], "outbound": "direct"}],
            "rule_set": [
                {
                    "_comment": "remote geo",
                    "type": "remote",
                    "tag": "geoip-x",
                    "format": "binary",
                    "url": "https://example.test/geoip-x.srs",
                    "download_detour": "proxy",
                }
            ],
        }
    )
    out = parse_singbox_rules(raw)
    assert len(out["rule_set"]) == 1
    rs = out["rule_set"][0]
    assert rs["tag"] == "geoip-x" and rs["type"] == "remote"
    assert "_comment" not in rs  # stripped


def test_rule_set_under_route_key():
    raw = json.dumps(
        {
            "route": {
                "rules": [{"rule_set": ["x"], "outbound": "direct"}],
                "rule_set": [
                    {"type": "remote", "tag": "x", "format": "binary", "url": "https://e/x.srs"}
                ],
            }
        }
    )
    assert parse_singbox_rules(raw)["rule_set"][0]["tag"] == "x"


def test_remote_rule_set_without_url_rejected():
    raw = json.dumps(
        {
            "rules": [{"rule_set": ["x"], "outbound": "direct"}],
            "rule_set": [{"type": "remote", "tag": "x", "format": "binary"}],
        }
    )
    with pytest.raises(RulesParseError, match="needs a `url`"):
        parse_singbox_rules(raw)


def test_rule_set_bad_type_rejected():
    raw = json.dumps(
        {
            "rules": [{"rule_set": ["x"], "outbound": "direct"}],
            "rule_set": [{"type": "magic", "tag": "x"}],
        }
    )
    with pytest.raises(RulesParseError, match="must be 'remote' or 'local'"):
        parse_singbox_rules(raw)


# --- rejections -------------------------------------------------------------


def test_invalid_action_rejected():
    with pytest.raises(RulesParseError, match="not a known sing-box action"):
        parse_singbox_rules(b'[{"action": "teleport"}]')


def test_missing_outbound_rejected():
    with pytest.raises(RulesParseError, match="outbound is missing"):
        parse_singbox_rules(b'[{"domain_suffix": ["x.com"]}]')


def test_unknown_outbound_rejected():
    with pytest.raises(RulesParseError, match="must be one of"):
        parse_singbox_rules(b'[{"domain_suffix": ["x.com"], "outbound": "wormhole"}]')


def test_rule_without_matcher_rejected():
    with pytest.raises(RulesParseError, match="no matcher"):
        parse_singbox_rules(b'[{"outbound": "direct"}]')


def test_xray_rule_rejected_with_pointer():
    with pytest.raises(RulesParseError, match="looks like an xray rule"):
        parse_singbox_rules(b'[{"type": "field", "outboundTag": "direct", "ip": ["10.0.0.0/8"]}]')


def test_empty_rules_rejected():
    with pytest.raises(RulesParseError, match="empty"):
        parse_singbox_rules(b'{"rules": []}')


def test_invalid_json_rejected():
    with pytest.raises(RulesParseError, match="not valid JSON"):
        parse_singbox_rules(b"{not json")


# --- rule-set URL + regex hardening ----------------------------------------


def test_rule_set_remote_requires_http_url():
    with pytest.raises(RulesParseError, match="http"):
        parse_singbox_rules(
            json.dumps(
                {
                    "rule_set": [{"tag": "g", "type": "remote", "url": "ftp://x/y.srs"}],
                    "rules": [{"rule_set": ["g"], "outbound": "proxy"}],
                }
            )
        )


def test_rule_set_remote_rejects_loopback_url():
    with pytest.raises(RulesParseError, match="non-public"):
        parse_singbox_rules(
            json.dumps(
                {
                    "rule_set": [{"tag": "g", "type": "remote", "url": "http://127.0.0.1:9090/x"}],
                    "rules": [{"rule_set": ["g"], "outbound": "proxy"}],
                }
            )
        )


def test_rule_set_remote_accepts_public_https_url():
    out = parse_singbox_rules(
        json.dumps(
            {
                "rule_set": [
                    {"tag": "g", "type": "remote", "url": "https://cdn.example.com/geo.srs"}
                ],
                "rules": [{"rule_set": ["g"], "outbound": "proxy"}],
            }
        )
    )
    assert out["rule_set"][0]["url"].startswith("https://")


def test_domain_regex_length_is_capped():
    huge = "a" * 2000
    with pytest.raises(RulesParseError, match="too long"):
        parse_singbox_rules(json.dumps({"rules": [{"domain_regex": huge, "outbound": "block"}]}))


@pytest.mark.parametrize(
    "host",
    [
        "localhost",  # RFC 6761: loopback wherever it is resolved
        "app.localhost",
        "metadata.google.internal",  # the reserved private-use TLD
        "2130706433",  # 127.0.0.1, spelled as one integer
        "127.1",
        "0177.0.0.1",
    ],
)
def test_rule_set_remote_rejects_a_host_that_is_local_by_definition(host):
    """The IP-literal guard alone accepted every one of these, and sing-box —
    not us — makes the request. `localhost` is not theoretical: dns.py sends
    `*.localhost` / `*.lan` to `dns-local` (dnsmasq), so it resolves to the
    router and the GET lands on the local Clash controller on :9090."""
    with pytest.raises(RulesParseError, match="non-public"):
        parse_singbox_rules(
            json.dumps(
                {
                    "rule_set": [{"tag": "g", "type": "remote", "url": f"http://{host}:9090/x"}],
                    "rules": [{"rule_set": ["g"], "outbound": "proxy"}],
                }
            )
        )


def test_the_rule_set_url_guard_never_resolves(monkeypatch):
    """Pinning the design choice, not an implementation detail.

    Resolving here would describe a different namespace than the one sing-box
    dials: it resolves a rule-set host over `dns-bootstrap` (DoH), or at the
    exit node under `download_detour: "proxy"`, minutes to hours later. So the
    guard rules on the *name*, which means there is also no DNS failure mode to
    decide how to fail on.
    """
    import socket

    def boom(*a, **k):
        raise AssertionError("the rules parser resolved a hostname")

    monkeypatch.setattr(socket, "getaddrinfo", boom)

    def doc(host):
        return json.dumps(
            {
                "rule_set": [{"tag": "g", "type": "remote", "url": f"https://{host}/geo.srs"}],
                "rules": [{"rule_set": ["g"], "outbound": "proxy"}],
            }
        )

    assert parse_singbox_rules(doc("raw.githubusercontent.com"))["rule_set"][0]["tag"] == "g"
    with pytest.raises(RulesParseError, match="non-public"):
        parse_singbox_rules(doc("localhost"))


# --- the route-rule key whitelist ------------------------------------------


def test_a_rule_may_not_carry_an_unlisted_key():
    """Measured: this document passed both this validator and `sing-box check`.

    `override_address` / `override_port` rewrite the dial destination for
    matched domains — a redirect/interception primitive delivered by a document
    fetched from a URL, so every check that only asks "is something required
    present?" misses it.
    """
    doc = json.dumps(
        {
            "rules": [
                {"domain_suffix": ["ok.test"], "outbound": "direct"},
                {
                    "domain_suffix": ["victim-bank.example"],
                    "outbound": "proxy",
                    "override_address": "203.0.113.66",
                    "override_port": 8443,
                },
            ]
        }
    )
    with pytest.raises(RulesParseError) as ei:
        parse_singbox_rules(doc)
    msg = str(ei.value)
    # The user is debugging someone else's document: name the key AND the rule.
    assert "override_address" in msg
    assert "rule[1]" in msg


def test_the_key_whitelist_runs_before_the_action_early_return():
    """An `action` rule with no `outbound` returns early, so a whitelist placed
    after that branch would be skipped for exactly the rules that need no
    outbound — i.e. it would be optional to bypass."""
    with pytest.raises(RulesParseError, match="override_address"):
        parse_singbox_rules(b'[{"action": "sniff", "override_address": "203.0.113.66"}]')


def test_a_nested_object_cannot_smuggle_a_key_past_the_flat_check():
    """No accepted matcher takes an object, so a rule that contains one is
    either a mistake or somewhere to hide a field the flat check never reads."""
    doc = json.dumps(
        {
            "rules": [
                {
                    "domain_suffix": [{"override_address": "203.0.113.66"}],
                    "outbound": "proxy",
                }
            ]
        }
    )
    with pytest.raises(RulesParseError, match="nested object"):
        parse_singbox_rules(doc)


@pytest.mark.parametrize("field", list(_MATCH_FIELDS))
def test_every_matcher_the_validator_accepts_survives_the_whitelist(field):
    """The whitelist is derived from `_MATCH_FIELDS`; if the two ever drift, a
    field this validator counts as a matcher would be rejected as unknown."""
    doc: dict = {"rules": [{field: ["x"], "outbound": "direct"}]}
    if field == "rule_set":
        # ...and a rule_set reference now has to resolve, or the parser refuses
        # it before the whitelist is even the question.
        doc["rule_set"] = [
            {"tag": "x", "type": "remote", "format": "binary", "url": "https://example.com/x.srs"}
        ]
    out = parse_singbox_rules(json.dumps(doc))
    assert out["rules"][0][field] == ["x"]


# --- bypass_address ---------------------------------------------------------
#
# The only knob that keeps traffic on the router's *hardware* fast path. A
# route rule with `outbound: direct` does not do this — the packet still goes
# through sing-box, leaving netfilter's `forward` chain where the flow offload
# lives. Plain CIDRs, loaded into an ipset: the tun-era spelling expanded
# rule-set tags into one kernel route per prefix and took a real router down
# at 21,619 of them.


def _doc(**extra):
    base = {"rules": [{"domain_suffix": ["example.test"], "outbound": "direct"}]}
    base.update(extra)
    return json.dumps(base)


def test_bypass_absent_defaults_to_empty():
    assert parse_singbox_rules(_doc())["bypass_address"] == []


def test_bypass_top_level_and_inside_route():
    assert parse_singbox_rules(_doc(bypass_address=["10.0.0.0/8"]))["bypass_address"] == [
        "10.0.0.0/8"
    ]
    doc = json.dumps(
        {
            "route": {
                "rules": [{"domain": ["x.test"], "outbound": "direct"}],
                "bypass_address": ["203.0.113.0/24"],
            }
        }
    )
    assert parse_singbox_rules(doc)["bypass_address"] == ["203.0.113.0/24"]


def test_bypass_normalises_host_bits_and_dedupes():
    """Hand-written and generated lists routinely carry host bits; rejecting
    them would be pedantry, and keeping both spellings would double the set."""
    out = parse_singbox_rules(_doc(bypass_address=["10.0.0.1/8", "10.0.0.0/8", "10.9.9.9/8"]))
    assert out["bypass_address"] == ["10.0.0.0/8"]


def test_bypass_accepts_a_single_host():
    assert parse_singbox_rules(_doc(bypass_address=["8.8.8.8/32"]))["bypass_address"] == [
        "8.8.8.8/32"
    ]


def test_bypass_rejects_ipv6():
    """The capture is IPv4-only (divert speaks iptables, not ip6tables), so a
    v6 entry would load into a set nothing consults — silently doing nothing."""
    with pytest.raises(RulesParseError, match="IPv6"):
        parse_singbox_rules(_doc(bypass_address=["2001:db8::/32"]))


@pytest.mark.parametrize("bad", ["10.0.0.0/8", {"net": "10.0.0.0/8"}, 42])
def test_bypass_rejects_non_array(bad):
    with pytest.raises(RulesParseError, match="must be an array"):
        parse_singbox_rules(_doc(bypass_address=bad))


@pytest.mark.parametrize("bad", ["", "  ", "not-a-cidr", "10.0.0.0/33", "999.1.1.1/24"])
def test_bypass_rejects_malformed_entries(bad):
    """A typo here fails open — the address just isn't bypassed, traffic gets
    proxied, and nothing looks wrong. Catch it while the document is in hand."""
    with pytest.raises(RulesParseError):
        parse_singbox_rules(_doc(bypass_address=[bad]))


def test_bypass_address_longer_than_the_kernel_set_is_rejected(monkeypatch):
    """The kernel refuses a hash:net past its maxelem, and the install then
    quietly drops the bypass entirely. Saying so against the document the user
    just pasted beats a warning buried in syslog days later — and it was the
    reachable trigger for the rebuild-every-tick outage, needing no stale state
    file, just a large pasted country list.

    The real ceiling is 262144; monkeypatched here because building and parsing
    that many CIDRs takes three minutes, which is not worth it in CI.
    """
    monkeypatch.setattr(divert, "BYPASS_MAX_NETWORKS", 4)
    nets = [f"203.0.113.{i}/32" for i in range(5)]
    doc = json.dumps(
        {"rules": [{"domain": ["a.test"], "outbound": "direct"}], "bypass_address": nets}
    )
    with pytest.raises(RulesParseError, match="at most 4"):
        parse_singbox_rules(doc)

    # At the limit it parses.
    doc = json.dumps(
        {"rules": [{"domain": ["a.test"], "outbound": "direct"}], "bypass_address": nets[:4]}
    )
    assert len(parse_singbox_rules(doc)["bypass_address"]) == 4


@pytest.mark.parametrize(
    "net",
    [
        "198.18.0.0/15",  # the range itself
        "198.18.0.7/32",  # a single address inside it
        "198.16.0.0/14",  # a supernet that swallows it
    ],
)
def test_bypass_address_may_not_cover_the_fake_ip_range(net):
    """`divert._RESERVED` deliberately omits 198.18.0.0/15 and `body_matches`
    rejects a chain that escapes it — because only sing-box can map a synthetic
    address back to a domain, so bypassing those connections sends them out the
    WAN to an address that exists nowhere. Every proxied *hostname* breaks while
    raw-IP traffic keeps working, which reads as "some sites are down". The
    ipset was an unguarded second way to do exactly that.
    """
    doc = json.dumps(
        {"rules": [{"domain": ["a.test"], "outbound": "direct"}], "bypass_address": [net]}
    )
    with pytest.raises(RulesParseError, match="fake-IP"):
        parse_singbox_rules(doc)


def test_bypass_cannot_cover_the_whole_internet_via_many_cidrs():
    """Each per-entry guard passes; together they miss the composition.

    The complement of the fake-IP range is 15 CIDRs — every one with a non-zero
    prefix, none overlapping 198.18.0.0/15, and 15 is nowhere near the count
    cap. It walks through all three checks and covers 99.9969% of IPv4, which
    means the VPN is off while the dashboard says it is on.
    """
    import json
    from ipaddress import ip_network

    evasion = [str(n) for n in ip_network("0.0.0.0/0").address_exclude(ip_network("198.18.0.0/15"))]
    assert len(evasion) == 15
    assert all(ip_network(n).prefixlen != 0 for n in evasion)  # guard 1 passes
    assert not any(ip_network(n).overlaps(ip_network("198.18.0.0/15")) for n in evasion)  # guard 2
    assert len(evasion) < 65536  # guard 3 passes

    doc = json.dumps(
        {"rules": [{"domain_suffix": ["x.test"], "outbound": "proxy"}], "bypass_address": evasion}
    )
    with pytest.raises(RulesParseError, match="address space"):
        parse_singbox_rules(doc)


def test_a_country_sized_bypass_list_is_still_accepted():
    """The guard must not break the case it was built for: the real RU list is
    8639 networks and covers well under 2% of the space."""
    import json

    nets = [f"10.{i // 256}.{i % 256}.0/24" for i in range(8639)]
    doc = json.dumps(
        {"rules": [{"domain_suffix": ["x.test"], "outbound": "proxy"}], "bypass_address": nets}
    )
    assert len(parse_singbox_rules(doc)["bypass_address"]) == 8639


def test_a_rule_set_may_not_carry_an_unlisted_key():
    """Same defect as the route-rule whitelist, one level down. The rule-set
    schema was left open in the first pass because the route-rule exploit was
    louder, but `download_detour` takes any outbound tag — so a hostile
    document sends the `.srs` fetch outside the tunnel, telling the ISP which
    rule-set this router downloads."""
    doc = json.dumps(
        {
            "rules": [{"rule_set": ["geo"], "outbound": "direct"}],
            "rule_set": [
                {
                    "tag": "geo",
                    "type": "remote",
                    "url": "https://example.com/geo.srs",
                    "format": "binary",
                    "headers": {"X-Exfil": "secret"},
                }
            ],
        }
    )
    with pytest.raises(RulesParseError, match="unsupported key 'headers'"):
        parse_singbox_rules(doc)


@pytest.mark.parametrize("detour", ["block", "some-node", ""])
def test_download_detour_is_limited_to_the_two_outbounds_that_exist(detour):
    """Not merely unknown: sing-box refuses to start on an outbound tag it does
    not have, so a stray value takes the whole data plane down rather than
    degrading one rule-set."""
    doc = json.dumps(
        {
            "rules": [{"rule_set": ["geo"], "outbound": "direct"}],
            "rule_set": [
                {
                    "tag": "geo",
                    "type": "remote",
                    "url": "https://example.com/geo.srs",
                    "format": "binary",
                    "download_detour": detour,
                }
            ],
        }
    )
    with pytest.raises(RulesParseError, match="download_detour"):
        parse_singbox_rules(doc)


def test_the_documented_rule_set_shape_still_parses():
    """The whitelist must not break what the docs tell people to write."""
    doc = json.dumps(
        {
            "rules": [{"rule_set": ["geo"], "outbound": "direct"}],
            "rule_set": [
                {
                    "tag": "geo",
                    "type": "remote",
                    "url": "https://example.com/geo.srs",
                    "format": "binary",
                    "download_detour": "proxy",
                    "update_interval": "7d",
                }
            ],
        }
    )
    assert parse_singbox_rules(doc)["rule_set"][0]["tag"] == "geo"


def test_a_rule_referencing_an_undefined_rule_set_is_refused():
    """The measured LAN blackout. A tag no `rule_set` defines — a one-character
    typo is enough — passes every per-object check AND `sing-box check`, then
    FATALs at run: "initialize DNS rule[1]: rule-set not found". procd reports
    the start as successful, so the rollback to `config.json.last-good` never
    fires and the capture stays installed over a dead listener: no TCP, no DNS,
    for the whole LAN, until someone SSHes in.
    """
    doc = json.dumps(
        {
            "rules": [{"rule_set": ["geo-home"], "outbound": "direct"}],
            "rule_set": [
                {
                    "tag": "geo-hom",  # the typo
                    "type": "remote",
                    "format": "binary",
                    "url": "https://example.com/a.srs",
                }
            ],
        }
    )
    with pytest.raises(RulesParseError, match="geo-home"):
        parse_singbox_rules(doc)


def test_a_rule_set_reference_with_no_definitions_at_all_is_refused():
    with pytest.raises(RulesParseError, match="does not define"):
        parse_singbox_rules(json.dumps([{"rule_set": ["ghost"], "outbound": "direct"}]))


def test_a_stored_bypass_list_that_covers_the_internet_is_dropped_on_load():
    """`bypass_address` is persisted and fed to the ipset on every boot, and the
    re-validation added for `rules`/`rule_set` forgot it. A list accepted before
    the coverage cap existed — `0.0.0.0/0` minus the fake-IP range is 15 CIDRs,
    99.9969% of IPv4, each individually legal — therefore kept bypassing
    effectively everything forever, with the dashboard reporting the VPN on.
    """
    from kitewrt.rules import revalidate_persisted

    evil = [
        "0.0.0.0/1",
        "128.0.0.0/2",
        "192.0.0.0/9",
        "192.128.0.0/11",
        "192.160.0.0/13",
        "192.168.0.0/16",
        "192.169.0.0/16",
        "192.170.0.0/15",
        "192.172.0.0/14",
        "192.176.0.0/12",
        "192.192.0.0/10",
        "193.0.0.0/8",
        "194.0.0.0/7",
        "196.0.0.0/6",
        "200.0.0.0/5",
    ]
    rules, sets, bypass, dropped = revalidate_persisted([], [], evil)
    assert bypass == [], "a list this wrong has no safe subset"
    assert any("bypass_address" in d for d in dropped)


def test_a_sane_stored_bypass_list_survives_load_untouched():
    from kitewrt.rules import revalidate_persisted

    good = ["203.0.113.0/24", "198.51.100.0/24"]
    _, _, bypass, dropped = revalidate_persisted([], [], good)
    assert bypass == good
    assert dropped == []


# --- documents that switch the VPN off ---------------------------------------
#
# Everything below passed the validator, `sing-box check` AND `sing-box run`.
# The guiding question is not "is this valid sing-box" but "can a document the
# user did not write turn the VPN off, or redirect it, without saying so".


def test_a_catch_all_direct_rule_is_refused():
    """One rule, fetched from a URL, and every raw-IP destination leaves the
    tunnel while the dashboard still reports the VPN on.

    The asymmetry is the finding: `_extract_bypass_address` spends three guards
    preventing exactly this outcome (prefixlen 0, fake-IP overlap, a coverage
    cap) and the route-rule path had none.
    """
    doc = json.dumps({"rules": [{"ip_cidr": ["0.0.0.0/0"], "outbound": "direct"}]})
    with pytest.raises(RulesParseError, match="turn the VPN off instead"):
        parse_singbox_rules(doc)


def test_the_direct_coverage_is_summed_across_the_whole_document():
    """A per-rule check would be theatre: `0.0.0.0/1` and `128.0.0.0/1` in two
    rules are the same document, and the 15-CIDR complement of the fake-IP range
    is the same evasion `bypass_address` already had to answer."""
    doc = json.dumps(
        {
            "rules": [
                {"ip_cidr": ["0.0.0.0/1"], "outbound": "direct"},
                {"ip_cidr": ["128.0.0.0/1"], "outbound": "direct"},
            ]
        }
    )
    with pytest.raises(RulesParseError, match="address space"):
        parse_singbox_rules(doc)


def test_a_country_sized_direct_rule_is_still_accepted():
    """The guard must not break the case the format exists for. The shipped
    example routes a whole country direct, and the RU list this project was
    built for is 8,639 networks — well under 2% of the space."""
    nets = [f"10.{i // 256}.{i % 256}.0/24" for i in range(8639)]
    doc = json.dumps({"rules": [{"ip_cidr": nets, "outbound": "direct"}]})
    assert len(parse_singbox_rules(doc)["rules"]) == 1


@pytest.mark.parametrize("outbound", ["proxy", "block"])
def test_a_catch_all_that_is_not_direct_is_left_alone(outbound):
    """Deliberate, not an oversight. `proxy` for everything is what `final`
    already does, and a `block` catch-all takes the internet down in seconds
    where nobody can miss it — that is the shape of a default-deny document,
    not of a VPN quietly switched off."""
    doc = json.dumps({"rules": [{"ip_cidr": ["0.0.0.0/0"], "outbound": outbound}]})
    assert len(parse_singbox_rules(doc)["rules"]) == 1


def test_a_stored_catch_all_direct_rule_is_dropped_on_load():
    """Same lesson as `bypass_address`: the document is persisted and replayed
    on every boot, so a validator tightened afterwards never sees it again
    unless the re-validation asks. Coverage is a property of the document, not
    of any one rule, so the per-rule loop cannot notice it."""
    from kitewrt.rules import revalidate_persisted

    evil = [
        {"ip_cidr": ["0.0.0.0/1"], "outbound": "direct"},
        {"ip_cidr": ["128.0.0.0/1"], "outbound": "direct"},
        {"domain_suffix": ["keep.test"], "outbound": "proxy"},
    ]
    rules, _, _, dropped = revalidate_persisted(evil, [])
    assert rules == [{"domain_suffix": ["keep.test"], "outbound": "proxy"}]
    assert any("address space" in d for d in dropped)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("domain_keyword", [""]),
        ("domain_regex", [""]),
        ("domain", [""]),
        ("domain_suffix", ["ok.test", ""]),  # not just the first element
        ("ip_cidr", [""]),
        ("network", ""),
        ("protocol", [""]),
        ("process_name", [""]),
        ("port_range", [""]),
    ],
)
def test_an_empty_matcher_value_is_refused(field, value):
    """Measured on sing-box 1.13.16, and it splits three ways.

    `domain_keyword: [""]` and `domain_regex: [""]` pass `sing-box check` and
    then match **every** connection (the trace prints `match[1] domain_keyword=
    => reject` for a raw-IP destination too). Worse than a wide route rule,
    because `_dns_rules_from_routes` mirrors a name matcher into the DNS block:
    `{"domain_keyword": [""], "outbound": "direct"}` sends every LAN lookup
    plain-UDP to the direct resolver and hands the ISP the browsing history.

    `domain`, `domain_suffix`, `ip_cidr` and `port_range` are refused by
    sing-box itself; `network: ""`, `protocol: [""]` and `process_name: [""]`
    match nothing at all, so the rule silently never fires. No spelling of an
    empty matcher is what anyone meant, so none of them is accepted here.
    """
    doc = json.dumps({"rules": [{field: value, "outbound": "direct"}]})
    with pytest.raises(RulesParseError, match="empty"):
        parse_singbox_rules(doc)


@pytest.mark.parametrize("field", ["ip_is_private", "source_ip_is_private"])
def test_a_false_boolean_is_not_a_matcher(field):
    """Measured with `sing-box run`: a *false* boolean builds no rule item at
    all, so the rule is left with zero items and matches every connection — the
    trace prints a bare `router: match[1] => reject` for a domain and a raw-IP
    destination alike. `_present_and_nonempty` counted it as a matcher, so
    `{"ip_is_private": false, "outbound": "direct"}` read here as a narrow rule
    and ran there as "everything direct" — including the domain traffic an
    `ip_cidr` catch-all cannot touch.
    """
    doc = json.dumps({"rules": [{field: False, "outbound": "direct"}]})
    with pytest.raises(RulesParseError, match="no matcher"):
        parse_singbox_rules(doc)


def test_a_true_boolean_is_still_a_matcher():
    doc = json.dumps({"rules": [{"ip_is_private": True, "outbound": "direct"}]})
    assert parse_singbox_rules(doc)["rules"] == [{"ip_is_private": True, "outbound": "direct"}]


@pytest.mark.parametrize("action", ["reject", "hijack-dns"])
def test_a_standalone_terminal_action_needs_a_matcher(action):
    """The early return for standalone actions skipped the "at least one
    matcher" requirement, and measured, both of these match everything:
    `{"action": "reject"}` closes every connection ("router: match[1] =>
    reject") and `{"action": "hijack-dns"}` feeds every one of them to the DNS
    server, where they hang. `sing-box check` accepts both and the process looks
    healthy the whole time.
    """
    with pytest.raises(RulesParseError, match="every connection"):
        parse_singbox_rules(json.dumps([{"action": action}]))


@pytest.mark.parametrize("action", ["sniff", "resolve"])
def test_a_standalone_annotating_action_still_needs_no_matcher(action):
    """`sniff` and `resolve` only annotate the connection — matching continues
    past them (measured), which is why kitewrt's own baseline opens with a
    matcher-free `{"action": "sniff"}`. Requiring a matcher here would reject
    the shape this project generates."""
    assert parse_singbox_rules(json.dumps([{"action": action}]))["rules"] == [{"action": action}]


def test_the_action_value_is_checked_even_when_an_outbound_is_present():
    """The old early return only fired when `outbound` was absent, so the value
    of `action` went unexamined for any rule that also named an outbound."""
    doc = json.dumps([{"domain": ["x.test"], "action": "teleport", "outbound": "direct"}])
    with pytest.raises(RulesParseError, match="not a known sing-box action"):
        parse_singbox_rules(doc)


def test_an_action_may_not_sit_beside_an_outbound_it_silently_overrides():
    """Measured: `{"domain_keyword": ["example"], "action": "reject",
    "outbound": "direct"}` passes `sing-box check`, and at run the *action*
    wins — the connection is rejected while the rule reads `direct`. A document
    that says one thing and does another is the whole of what this validator is
    for."""
    doc = json.dumps([{"domain": ["x.test"], "action": "reject", "outbound": "direct"}])
    with pytest.raises(RulesParseError, match="both"):
        parse_singbox_rules(doc)


@pytest.mark.parametrize("rule", [{"action": "route"}, {"domain": ["x.test"], "action": "route"}])
def test_action_route_without_an_outbound_is_refused(rule):
    """`sing-box check` passes it; at run every matched connection dies with
    "outbound not found:" while the process stays up and healthy-looking — the
    same failure class as the undefined rule-set tag, and equally invisible to
    the check the apply path gates on."""
    with pytest.raises(RulesParseError, match="outbound not found"):
        parse_singbox_rules(json.dumps([rule]))


def test_action_route_with_an_outbound_is_the_explicit_spelling_and_parses():
    doc = json.dumps([{"domain": ["x.test"], "action": "route", "outbound": "proxy"}])
    assert parse_singbox_rules(doc)["rules"][0]["action"] == "route"


@pytest.mark.parametrize(
    "path",
    [
        "/etc/shadow",
        "/etc/sing-box/../../etc/shadow",  # traversal back out
        "geo.srs",  # relative: resolved against whatever CWD the reader has
        "../geo.srs",
        "/etc/sing-box",  # the directory itself
    ],
)
def test_a_local_rule_set_path_must_live_in_sing_boxs_own_directory(path):
    """`path` was checked for truthiness only, and `sing-box check`'s stderr is
    captured into `last_error` and served on `/api/state` and the WebSocket — so
    a document fetched from a URL could ask about any path on the router and
    read the answer off the dashboard. Measured, the replies tell the cases
    apart: "no such file or directory" / "permission denied" / "invalid sing-box
    rule-set file" / "json: cannot unmarshal number into ..." / "is a
    directory".
    """
    doc = json.dumps(
        {
            "rules": [{"rule_set": ["g"], "outbound": "direct"}],
            "rule_set": [{"tag": "g", "type": "local", "format": "binary", "path": path}],
        }
    )
    with pytest.raises(RulesParseError, match="path"):
        parse_singbox_rules(doc)


def test_a_local_rule_set_inside_that_directory_still_parses():
    """The owner who scp'd a `.srs` onto the router keeps working; only the
    arbitrary-path oracle goes away."""
    doc = json.dumps(
        {
            "rules": [{"rule_set": ["g"], "outbound": "direct"}],
            "rule_set": [
                {"tag": "g", "type": "local", "format": "binary", "path": "/etc/sing-box/geo.srs"}
            ],
        }
    )
    assert parse_singbox_rules(doc)["rule_set"][0]["path"] == "/etc/sing-box/geo.srs"
