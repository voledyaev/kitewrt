"""TPROXY marks must survive firmware PREROUTING redirects unchanged.

No live firewall: a stateful command fake checks ownership, ordering and failure
lifecycle. The packet-path regression itself was measured on the target kernel.
"""

from __future__ import annotations

import shlex

import pytest
from kitewrt import divert

_REDIRECT = ["-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"]
_DNAT = ["-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "192.0.2.10:8080"]


class Kernel:
    def __init__(self, rules=(), *, captured=False):
        self.rules = [list(rule) for rule in rules]
        self.captured = captured
        self.calls = []
        self.fail_insert = False
        self.fail_stage = False
        self.fail_teardown = False
        self.nat_unknown = False

    async def capture(self, argv, timeout=10):
        if "-t" in argv and argv[argv.index("-t") + 1] == "nat":
            if self.nat_unknown:
                return None
            return "\n".join("-A PREROUTING " + shlex.join(rule) for rule in self.rules)
        if "-S" in argv:
            chain = argv[argv.index("-S") + 1] if argv[-1] != "-S" else None
            if chain == "PREROUTING":
                return f"-A PREROUTING -j {divert.CHAIN}" if self.captured else ""
            if chain == divert.CHAIN:
                return "\n".join(" ".join(r) for r in divert._chain_rules(7895, 0x2023, ["eth1"]))
            if chain == "INPUT":
                return "-A INPUT " + " ".join(divert._input_accept_rule(0x2023))
            return f"-N {divert.CHAIN}\n" if self.captured else ""
        if "rule" in argv:
            return "0: from all fwmark 0x2023 lookup 2023\n"
        if "route" in argv:
            return "local default dev lo\n"
        return ""

    async def ipt(self, args, timeout=10):
        self.calls.append(list(args))
        if args[:2] == ["-t", "nat"]:
            op, chain, *rest = args[2:]
            assert chain == "PREROUTING"
            if op == "-I":
                if self.fail_insert:
                    return 4
                position, *rule = rest
                self.rules.insert(int(position) - 1, rule)
            elif op == "-D":
                if len(rest) == 1:
                    del self.rules[int(rest[0]) - 1]
                elif rest in self.rules:
                    self.rules.remove(rest)
                else:
                    return 1
            else:
                pytest.fail(f"unexpected NAT mutation: {args}")
            return 0
        if args[:3] == ["-t", "mangle", "-N"] and self.fail_stage:
            return 1
        if args[:3] == ["-t", "mangle", "-F"] and (self.fail_teardown or self.fail_stage):
            return 4
        if args[:4] == ["-t", "mangle", "-A", "PREROUTING"]:
            self.captured = True
        if args[:4] == ["-t", "mangle", "-D", "PREROUTING"]:
            if self.fail_teardown:
                return 4
            if args[-1] == divert.CHAIN:
                self.captured = False
        if args[:3] == ["-t", "filter", "-D"]:
            return 1
        return 0


@pytest.fixture
def kernel(monkeypatch):
    k = Kernel()
    monkeypatch.setattr(divert, "_capture", k.capture)
    monkeypatch.setattr(divert, "_ipt", k.ipt)
    return k


async def test_first_guard_protects_any_port_and_preserves_vendor_rules(kernel):
    kernel.rules = [list(_REDIRECT), list(_DNAT)]
    assert await divert._ensure_nat_guard(0x2023)
    assert kernel.rules == [divert._nat_guard_rule(0x2023), _REDIRECT, _DNAT]
    assert "--dport" not in kernel.rules[0]
    assert "-i" not in kernel.rules[0]
    assert await divert._ensure_nat_guard(0x2023)
    assert len(kernel.calls) == 1  # unchanged capture is mutation-free


async def test_displaced_exact_copy_is_harmless_not_deleted_by_index(kernel):
    exact = divert._nat_guard_rule(0x2023)
    kernel.rules = [list(_REDIRECT), exact]
    assert await divert._ensure_nat_guard(0x2023)
    assert kernel.rules == [exact, _REDIRECT, exact]
    assert await divert._ensure_nat_guard(0x2023)
    assert len(kernel.calls) == 1


async def test_stale_guard_deleted_by_spec_even_if_firmware_inserts_concurrently(
    kernel, monkeypatch
):
    stale = divert._nat_guard_rule(0x2023)
    stale[-1] = "RETURN"
    kernel.rules = [stale, list(_REDIRECT)]
    original = kernel.ipt

    async def raced(args, timeout=10):
        result = await original(args, timeout)
        if args[:3] == ["-t", "nat", "-I"]:
            # A third-party write shifts every old index after our insertion.
            kernel.rules.insert(1, list(_DNAT))
        return result

    monkeypatch.setattr(divert, "_ipt", raced)
    assert await divert._ensure_nat_guard(0x2023)
    assert kernel.rules == [divert._nat_guard_rule(0x2023), _DNAT, _REDIRECT]
    deletions = [c for c in kernel.calls if c[:3] == ["-t", "nat", "-D"]]
    assert deletions == [["-t", "nat", "-D", "PREROUTING", *stale]]


async def test_concurrent_new_redirect_at_head_cannot_report_success(kernel, monkeypatch):
    original = kernel.ipt

    async def raced(args, timeout=10):
        result = await original(args, timeout)
        if args[:3] == ["-t", "nat", "-I"]:
            kernel.rules.insert(0, list(_REDIRECT))
        return result

    monkeypatch.setattr(divert, "_ipt", raced)
    assert not await divert._ensure_nat_guard(0x2023)
    assert kernel.rules[0] == _REDIRECT


async def test_guard_insert_failure_does_not_remove_existing_rules(kernel):
    kernel.rules = [list(_REDIRECT)]
    kernel.fail_insert = True
    assert not await divert._ensure_nat_guard(0x2023)
    assert kernel.rules == [_REDIRECT]


async def test_unknown_nat_read_is_not_mutated(kernel):
    kernel.nat_unknown = True
    assert not await divert._ensure_nat_guard(0x2023)
    assert kernel.calls == []


async def test_cleanup_removes_only_owned_guards(kernel):
    exact = divert._nat_guard_rule(0x2023)
    kernel.rules = [exact, list(_REDIRECT), exact, list(_DNAT)]
    assert await divert._remove_nat_guard()
    assert kernel.rules == [_REDIRECT, _DNAT]


@pytest.mark.parametrize("capture", [True, None])
async def test_failed_install_preserves_guard_with_live_or_unknown_capture(
    kernel, monkeypatch, capture
):
    async def installed():
        return capture

    monkeypatch.setattr(divert, "installed_state", installed)
    kernel.rules = [divert._nat_guard_rule(0x2023)]
    await divert._cleanup_nat_guard_if_uncaptured()
    assert kernel.rules


async def test_failed_initial_install_removes_inert_guard(kernel, monkeypatch):
    async def absent():
        return False

    monkeypatch.setattr(divert, "installed_state", absent)
    kernel.rules = [divert._nat_guard_rule(0x2023), list(_REDIRECT)]
    await divert._cleanup_nat_guard_if_uncaptured()
    assert kernel.rules == [_REDIRECT]


@pytest.mark.parametrize("mark", ["0x2023", "0x2023/0xffffffff", "8227/4294967295"])
def test_exact_full_mark_spellings_are_equivalent(mark):
    rule = divert._nat_guard_rule(0x2023)
    rule[rule.index("--mark") + 1] = mark
    assert divert._exact_nat_guard(rule, 0x2023)


@pytest.mark.parametrize("mark", ["0x2023/0xffff", "0x2024", "invalid"])
def test_wrong_or_partial_mark_never_satisfies_guard(mark):
    rule = divert._nat_guard_rule(0x2023)
    rule[rule.index("--mark") + 1] = mark
    assert not divert._exact_nat_guard(rule, 0x2023)


async def _zero(*args, **kwargs):
    return 0


async def _run_ok(*args, **kwargs):
    return 0, ""


@pytest.mark.parametrize("captured", [False, True])
async def test_install_failure_keeps_live_guard_but_cleans_initial_scaffolding(
    kernel, monkeypatch, captured
):
    kernel.captured = captured
    kernel.rules = [list(_REDIRECT)]
    monkeypatch.setattr(divert, "_frozen", False)
    monkeypatch.setattr(divert, "_lock", None)
    monkeypatch.setattr(divert, "_staging_hooked", False)

    async def mismatch(*args, **kwargs):
        return False

    async def reclaimed():
        return True

    monkeypatch.setattr(divert, "_matches", mismatch)
    monkeypatch.setattr(divert, "_reclaim_staging", reclaimed)
    monkeypatch.setattr(divert, "_ip", _zero)
    monkeypatch.setattr(divert, "_run", _run_ok)
    original = kernel.ipt

    async def fail_at_staging(args, timeout=10):
        if args[:4] == ["-t", "mangle", "-N", divert.STAGING_CHAIN]:
            # The protection must already be present before building/arming capture.
            assert kernel.rules[0] == divert._nat_guard_rule(0x2023)
            raise OSError("synthetic staging failure")
        return await original(args, timeout)

    monkeypatch.setattr(divert, "_ipt", fail_at_staging)
    assert await divert.install(["eth1"]) is False
    assert (divert._nat_guard_rule(0x2023) in kernel.rules) is captured
    assert _REDIRECT in kernel.rules


@pytest.mark.parametrize("fail_teardown", [False, True])
async def test_remove_guard_only_after_capture_stopped(kernel, monkeypatch, fail_teardown):
    kernel.captured = True
    kernel.fail_teardown = fail_teardown
    kernel.rules = [divert._nat_guard_rule(0x2023), list(_REDIRECT)]
    monkeypatch.setattr(divert, "_ip", _zero)
    monkeypatch.setattr(divert, "_run", _run_ok)
    assert await divert._remove_locked() is (not fail_teardown)
    assert (divert._nat_guard_rule(0x2023) in kernel.rules) is fail_teardown
    assert _REDIRECT in kernel.rules
    deletes = [i for i, c in enumerate(kernel.calls) if c[:3] == ["-t", "nat", "-D"]]
    if not fail_teardown:
        unhook = next(
            i for i, c in enumerate(kernel.calls) if c[:4] == ["-t", "mangle", "-D", "PREROUTING"]
        )
        assert deletes and min(deletes) > unhook
    else:
        assert not deletes
