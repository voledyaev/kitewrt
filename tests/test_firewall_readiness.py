"""Readiness must match effective rules, not comments or numeric substrings."""

from __future__ import annotations

import shlex

import pytest
from kitewrt import divert


class InputKernel:
    def __init__(self, rules):
        self.rules = [list(r) for r in rules]
        self.calls = []
        self.concurrent = False
        self.fail_insert = False
        self.unknown = False

    async def capture(self, args, **kw):
        if self.unknown:
            return None
        return "\n".join("-A INPUT " + shlex.join(r) for r in self.rules)

    async def ipt(self, args, **kw):
        self.calls.append(args)
        assert args[:2] == ["-t", "filter"]
        if args[2] == "-I":
            if self.fail_insert:
                return 4
            self.rules.insert(int(args[4]) - 1, args[5:])
            if self.concurrent:
                self.rules.insert(1, ["-j", "vendor-new"])
        elif args[2] == "-D":
            assert args[4:] in self.rules, "only exact rules may be deleted"
            self.rules.remove(args[4:])
        return 0


async def test_input_repair_preserves_concurrent_vendor_insert(monkeypatch):
    stale = ["-m", "comment", "--comment", divert._INPUT_ACCEPT_COMMENT, "-j", "DROP"]
    vendor = ["-j", "vendor-old"]
    k = InputKernel([vendor, stale])
    k.concurrent = True
    monkeypatch.setattr(divert, "_capture", k.capture)
    monkeypatch.setattr(divert, "_ipt", k.ipt)
    assert await divert._ensure_input_accept(0x2023)
    assert k.rules == [divert._input_accept_rule(0x2023), ["-j", "vendor-new"], vendor]


async def test_input_failed_insert_or_unknown_read_never_removes_live_protection(monkeypatch):
    correct = divert._input_accept_rule(0x2023)
    k = InputKernel([["-j", "vendor"], correct])
    monkeypatch.setattr(divert, "_capture", k.capture)
    monkeypatch.setattr(divert, "_ipt", k.ipt)
    k.fail_insert = True
    assert not await divert._ensure_input_accept(0x2023)
    assert k.rules[-1] == correct
    k.unknown = True
    k.calls.clear()
    assert not await divert._ensure_input_accept(0x2023)
    assert not k.calls


@pytest.mark.parametrize("mark", ["0x20230", "0x2023/0xffff", "0x1"])
def test_input_comment_cannot_hide_wrong_mark(mark):
    rule = divert._input_accept_rule(0x2023)
    rule[rule.index("--mark") + 1] = mark
    assert not divert._input_accept_matches("-A INPUT " + shlex.join(rule), 0x2023)


def test_input_comment_cannot_hide_drop_or_partial_spec():
    rule = divert._input_accept_rule(0x2023)
    rule[-1] = "DROP"
    assert not divert._input_accept_matches("-A INPUT " + shlex.join(rule), 0x2023)
    assert not divert._owned_input_accept(["--comment", "not-" + divert._INPUT_ACCEPT_COMMENT])


@pytest.mark.parametrize(
    "text",
    [
        "0: from all fwmark 0x20230 lookup 2023",
        "0: from all fwmark 0x2023 lookup 20230",
        "0: from all fwmark 0x2023/0xffff lookup 2023",
        "0: from 192.0.2.0/24 fwmark 0x2023 lookup 2023",
        "0: from all fwmark 0x2023 iif eth1 lookup 2023",
    ],
)
async def test_bad_policy_rule_does_not_suppress_install(monkeypatch, text):
    calls = []

    async def capture(*args, **kw):
        return text

    async def ip(args, **kw):
        calls.append(args)
        return 0

    monkeypatch.setattr(divert, "_capture", capture)
    monkeypatch.setattr(divert, "_ip", ip)
    assert await divert._ensure_ip_rule(0x2023)
    assert calls == [["rule", "add", "fwmark", "0x2023", "lookup", "2023"]]


@pytest.mark.parametrize("mark", ["0x2023", "0x2023/0xffffffff", "8227/4294967295"])
def test_full_mark_policy_spellings_are_valid(mark):
    assert divert._ip_rule_matches(f"100: from all fwmark {mark} lookup 2023", 0x2023)


@pytest.mark.parametrize("replacement", ["0x20230", "0x2023/0xffff"])
def test_tproxy_body_requires_exact_full_mark(replacement):
    body = [
        " ".join(r).replace("--tproxy-mark 0x2023", "--tproxy-mark " + replacement)
        for r in divert._chain_rules(7895, 0x2023, ["eth1"])
    ]
    assert not divert.body_matches(body, ["eth1"], 7895, 0x2023, bypass=False)


async def test_earlier_firmware_accept_is_not_a_healthy_capture(monkeypatch):
    async def capture(args, **kw):
        return f"-A PREROUTING -i br-lan -j ACCEPT\n-A PREROUTING -j {divert.CHAIN}\n"

    monkeypatch.setattr(divert, "_capture", capture)
    assert await divert._matches(["eth1"], 7895, 0x2023) is False


async def test_staging_displaced_by_vendor_preserves_old_capture(monkeypatch):
    calls = []

    async def capture(*args, **kwargs):
        return f"-A PREROUTING -j vendor\n-A PREROUTING -j {divert.STAGING_CHAIN}\n-A PREROUTING -j {divert.CHAIN}\n"

    async def ipt(args, **kwargs):
        calls.append(args)
        return 0

    monkeypatch.setattr(divert, "_staging_hooked", True)
    monkeypatch.setattr(divert, "_capture", capture)
    monkeypatch.setattr(divert, "_ipt", ipt)
    assert not await divert._finish_swap()
    assert not calls


async def test_legacy_old_then_staging_handover_can_recover(monkeypatch):
    hooks = [divert.CHAIN, divert.STAGING_CHAIN]

    async def capture(*args, **kwargs):
        return "\n".join(f"-A PREROUTING -j {name}" for name in hooks)

    async def ipt(args, **kwargs):
        if args[:4] == ["-t", "mangle", "-D", "PREROUTING"]:
            hooks.remove(args[-1])
        elif args[:3] == ["-t", "mangle", "-E"]:
            hooks[hooks.index(args[3])] = args[4]
        return 0

    monkeypatch.setattr(divert, "_staging_hooked", True)
    monkeypatch.setattr(divert, "_capture", capture)
    monkeypatch.setattr(divert, "_ipt", ipt)
    assert await divert._finish_swap()
    assert hooks == [divert.CHAIN]
