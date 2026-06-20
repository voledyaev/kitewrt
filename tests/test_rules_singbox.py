"""Tests for the sing-box rules validator/normaliser (parse_singbox_rules).

parse_singbox_rules returns {"rules": [...], "rule_set": [...]}.
"""

from __future__ import annotations

import json

import pytest
from kitewrt.rules import RulesParseError, parse_singbox_rules


def test_route_wrapped_shape():
    out = parse_singbox_rules(
        b'{"route": {"rules": [{"domain_suffix": [".ru"], "outbound": "direct"}]}}'
    )
    assert out["rules"] == [{"domain_suffix": [".ru"], "outbound": "direct"}]
    assert out["rule_set"] == []


def test_rules_wrapped_shape():
    out = parse_singbox_rules(b'{"rules": [{"rule_set": ["geoip-x"], "outbound": "direct"}]}')
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
