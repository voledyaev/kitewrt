"""Routing repair failures retain capture and readiness checks the actual policy."""

from __future__ import annotations

import pytest
from kitewrt import divert, killswitch

from tests.test_divert import _FakeMangle
from tests.test_divert_nat_guard import Kernel


@pytest.fixture(autouse=True)
def clean_divert_state():
    divert._lock = None
    divert._frozen = False
    yield
    divert._lock = None
    divert._frozen = False


@pytest.mark.parametrize("operation", ["rule", "route"])
async def test_failed_policy_repair_retains_existing_capture(monkeypatch, operation):
    kernel = _FakeMangle([divert.CHAIN])
    kernel.install_into(monkeypatch)
    if operation == "rule":
        kernel.policy = "0: from all lookup local\n"

    async def failed_ip(args, **kw):
        return 2 if args[0] == operation else 0

    monkeypatch.setattr(divert, "_ip", failed_ip)
    assert await divert.install(["eth1"]) is False
    assert kernel.hooks == [divert.CHAIN]
    assert ["-t", "mangle", "-F", divert.CHAIN] not in kernel.calls
    assert ["-t", "mangle", "-D", "PREROUTING", "-j", divert.CHAIN] not in kernel.calls


@pytest.mark.parametrize(
    "earlier",
    [
        "100: from all fwmark 0x2023 lookup 100",
        "100: from all fwmark 0x2000/0xf000 lookup 100",
        "100: from 192.0.2.0/24 lookup 100",
        "100: from all iif br-lan lookup 100",
        "100: from all lookup main",
        "100: not from all fwmark 0x1 lookup 100",
        "100: not from 192.0.2.0/24 fwmark 0x2023 lookup 100",
    ],
)
async def test_readiness_refuses_shadowing_policy(monkeypatch, earlier):
    kernel = Kernel([divert._nat_guard_rule(0x2023)], captured=True)
    real_capture = kernel.capture

    async def capture(args, **kw):
        if args == ["ip", "rule", "show"]:
            return f"0: from all lookup local\n{earlier}\n32765: from all fwmark 0x2023 lookup 2023"
        return await real_capture(args, **kw)

    monkeypatch.setattr(divert, "_capture", capture)
    assert await divert._matches(["eth1"], 7895, 0x2023) is False


@pytest.mark.parametrize("mark_rule", ["fwmark 0x1", "fwmark 0x1000/0xf000"])
def test_disjoint_mark_policy_does_not_false_alarm(mark_rule):
    rules = f"0: from all lookup local\n100: from all {mark_rule} lookup 100\n32765: from all fwmark 0x2023 lookup 2023\n32766: from all lookup main"
    assert divert._policy_rules_match(rules, 0x2023)


@pytest.mark.parametrize(
    "extra",
    [
        "blackhole 203.0.113.0/24",
        "203.0.113.0/24 dev eth1",
        "local 203.0.113.0/24 dev eth1",
        "throw 203.0.113.0/24",
    ],
)
async def test_readiness_refuses_nonlocal_specific_routes(monkeypatch, extra):
    kernel = Kernel([divert._nat_guard_rule(0x2023)], captured=True)
    real_capture = kernel.capture

    async def capture(args, **kw):
        if args == ["ip", "route", "show", "table", "2023"]:
            return f"local default dev lo scope host\n{extra}"
        return await real_capture(args, **kw)

    monkeypatch.setattr(divert, "_capture", capture)
    assert await divert._matches(["eth1"], 7895, 0x2023) is False


async def test_policy_conflict_does_not_claim_success_or_remove_live_capture(monkeypatch):
    kernel = _FakeMangle([divert.CHAIN])
    kernel.install_into(monkeypatch)
    kernel.policy = "0: from all lookup local\n100: from all lookup main\n32765: from all fwmark 0x2023 lookup 2023"
    assert await divert.install(["eth1"]) is False
    assert kernel.hooks == [divert.CHAIN]
    assert ["-t", "mangle", "-F", divert.CHAIN] not in kernel.calls
    assert not any(c[:3] == ["-t", "mangle", "-N"] for c in kernel.calls)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_missing_catchall_tproxy_cannot_hide_behind_rule_count(protocol):
    body = [" ".join(r) for r in divert._chain_rules(7895, 0x2023, ["eth1"])]
    body = [
        line.replace(
            f"-p {protocol} -j TPROXY --on-port 7895 --tproxy-mark 0x2023",
            f"-p {protocol} -j RETURN",
        )
        for line in body
    ]
    assert not divert.body_matches(body, ["eth1"], 7895, 0x2023, bypass=False)


def test_kernel_renderings_still_match_without_rebuild():
    body = []
    for rule in divert._chain_rules(7895, 0x2023, ["eth1"], bypass=True):
        line = " ".join(rule)
        for protocol in ("tcp", "udp"):
            line = line.replace(f"-p {protocol} ", f"-p {protocol} -m {protocol} ")
        line = line.replace("--on-port 7895", "--on-port 7895 --on-ip 0.0.0.0")
        line = line.replace("--tproxy-mark 0x2023", "--tproxy-mark 0x2023/0xffffffff")
        body.append(line)
    assert divert.body_matches(body, ["eth1"], 7895, 0x2023, bypass=True)


async def test_capture_accept_is_installed_after_armed_runtime_drop(monkeypatch):
    from tests.test_firewall_readiness import InputKernel

    guard = killswitch._reload_rule(0x2023)
    k = InputKernel([guard, ["-j", "vendor"]])
    monkeypatch.setattr(divert, "_capture", k.capture)
    monkeypatch.setattr(divert, "_ipt", k.ipt)
    assert await divert._ensure_input_accept(0x2023)
    assert k.rules == [guard, divert._input_accept_rule(0x2023), ["-j", "vendor"]]


def test_negated_exact_mark_excludes_our_traffic():
    rules = "0: from all lookup local\n100: not from all fwmark 0x2023 lookup 100\n32765: from all fwmark 0x2023 lookup 2023"
    assert divert._policy_rules_match(rules, 0x2023)


@pytest.mark.parametrize("copies", [1, 2])
async def test_both_runtime_guards_remain_ahead_of_capture_accept(monkeypatch, copies):
    from tests.test_firewall_readiness import InputKernel

    guards = [killswitch._reload_proxy_rule(), killswitch._reload_rule(0x2023)] * copies
    # Kernel can render the implicit full-mask in either form.
    guards[-1] = list(guards[-1])
    guards[-1][guards[-1].index("--mark") + 1] = "0x2023/0xffffffff"
    k = InputKernel([*guards, ["-j", "vendor"]])
    monkeypatch.setattr(divert, "_capture", k.capture)
    monkeypatch.setattr(divert, "_ipt", k.ipt)
    assert await divert._ensure_input_accept(0x2023)
    assert k.rules == [*guards, divert._input_accept_rule(0x2023), ["-j", "vendor"]]


@pytest.mark.parametrize("displaced", [False, True])
async def test_malformed_or_displaced_runtime_guard_is_never_bypassed(monkeypatch, displaced):
    from tests.test_firewall_readiness import InputKernel

    guard = killswitch._reload_rule(0x2023)
    if not displaced:
        guard[guard.index("--mark") + 1] = "0x2023/0xffff"
    rules = [["-j", "vendor"], guard] if displaced else [guard, ["-j", "vendor"]]
    k = InputKernel(rules)
    monkeypatch.setattr(divert, "_capture", k.capture)
    monkeypatch.setattr(divert, "_ipt", k.ipt)
    assert not await divert._ensure_input_accept(0x2023)
    assert k.rules == rules
    assert not k.calls
