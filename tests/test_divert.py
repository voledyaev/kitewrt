"""Tests for the TPROXY capture plumbing (kitewrt.divert).

Both of the behaviours pinned here are ones that fail *silently* on a real
router — the rules look installed, nothing logs an error, and traffic quietly
goes somewhere wrong. Each was found by testing against a real kernel, not by
reading the code.
"""

from __future__ import annotations

import asyncio

import pytest
from kitewrt import divert


@pytest.fixture(autouse=True)
def _fresh_lock():
    """Clear the module's lazily-built lock before every test.

    On python 3.9 an `asyncio.Lock` binds to the running loop at construction,
    the module builds it once, and pytest gives each test a fresh loop — so a
    leftover lock silently succeeds on an uncontended `acquire()` and raises
    `RuntimeError: got Future attached to a different loop` on a contended one.
    Doing this here rather than per-test means a `monkeypatch.setattr` can't
    "restore" the stale one at teardown. Production has a single loop for the
    process lifetime, which is why the daemon never hits this.
    """
    divert._lock = None
    divert._frozen = False
    yield
    divert._lock = None
    divert._frozen = False


def _flat(rules):
    return [" ".join(r) for r in rules]


def test_loopback_is_let_through_first():
    """The P0 the enumerate-LANs approach introduced.

    Router-origin traffic takes OUTPUT and isn't captured, but loopback packets
    DO traverse PREROUTING with iif=lo. Without this RETURN, the router's own
    DNS to 127.0.0.1 gets TPROXY'd and answered with a fake IP — breaking opkg
    and ntpd — and loops, because sing-box's `dns-local` resolves through
    /etc/resolv.conf, i.e. straight back in here.
    """
    flat = _flat(divert._chain_rules(divert.TPROXY_PORT, divert.TPROXY_MARK))
    assert flat[0] == f"-A {divert.CHAIN} -i lo -j RETURN"


def test_uplinks_are_let_through_before_anything_is_diverted():
    """mangle/PREROUTING runs before reverse-NAT, so a captured uplink's return
    packets carry the router's public address — not private, so no RETURN below
    catches them — and TPROXY swallows the WAN."""
    flat = _flat(divert._chain_rules(divert.TPROXY_PORT, divert.TPROXY_MARK, ["eth1", "wwan0"]))
    first_divert = next(i for i, r in enumerate(flat) if "-j TPROXY" in r)
    for dev in ("eth1", "wwan0"):
        idx = next(i for i, r in enumerate(flat) if f"-i {dev} " in r and "RETURN" in r)
        assert idx < first_divert


def test_capture_is_not_scoped_to_named_interfaces():
    """We hook PREROUTING unconditionally and exclude what isn't LAN. Scoping
    to an enumerated list means any network the list misses egresses direct
    while the UI says VPN on — and iptables accepts `-i` for an interface that
    doesn't exist, so it installs cleanly and captures nothing."""
    rules = divert._chain_rules(divert.TPROXY_PORT, divert.TPROXY_MARK, ["eth1"])
    diverts = [r for r in rules if "-j" in r and "TPROXY" in " ".join(r)]
    assert diverts and all("-i" not in r for r in diverts)


def test_dns_is_diverted_before_the_private_range_escapes():
    """The load-bearing ordering bug.

    LAN clients are handed the router as their resolver over DHCP, so their
    queries go to a *private* address (192.168.x.1:53). If the reserved-range
    RETURNs came first, every query would fall through to dnsmasq and out to
    the ISP — no fake-IP, no DNS over the proxy, and no error anywhere.
    """
    flat = _flat(divert._chain_rules(divert.TPROXY_PORT, divert.TPROXY_MARK))
    first_dns = next(i for i, r in enumerate(flat) if "--dport 53" in r)
    first_private = next(i for i, r in enumerate(flat) if "192.168.0.0/16" in r)
    assert first_dns < first_private, flat


def test_dns_diverted_for_both_udp_and_tcp():
    flat = _flat(divert._chain_rules(divert.TPROXY_PORT, divert.TPROXY_MARK))
    dns = [r for r in flat if "--dport 53" in r]
    assert any("-p udp" in r for r in dns)
    assert any("-p tcp" in r for r in dns)


def test_udp_is_diverted_so_quic_keeps_working():
    """QUIC/HTTP3 is UDP; a TCP-only divert downgrades or breaks HTTP/3 sites."""
    flat = _flat(divert._chain_rules(divert.TPROXY_PORT, divert.TPROXY_MARK))
    catch_all = [r for r in flat if "--dport" not in r and "-j TPROXY" in r]
    assert any("-p udp" in r for r in catch_all), flat
    assert any("-p tcp" in r for r in catch_all), flat


def test_fakeip_range_is_never_excluded():
    """Fake-IP connections must reach sing-box so it can map the synthetic
    198.18.x address back to a domain. Excluding the range breaks every
    proxied name while leaving everything else working — a nasty failure."""
    assert not any(net.startswith("198.18") for net in divert._RESERVED)


def test_reserved_ranges_cover_the_private_space():
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"):
        assert net in divert._RESERVED


def test_parse_hooks_keeps_the_full_rule_spec():
    """iptables matches `-D` on the whole spec. Our hook carries `-i <dev>`, so
    deleting by `-j CHAIN` alone silently fails and leaves the capture live —
    traffic keeps going to a port nothing listens on. Found on a real kernel."""
    dump = "\n".join(
        [
            "-P PREROUTING ACCEPT",
            f"-A PREROUTING -i br-lan -j {divert.CHAIN}",
            "-A PREROUTING -j MINIUPNPD",
            f"-A PREROUTING -i eth0 -j {divert.CHAIN}",
        ]
    )
    assert divert.parse_hooks(dump) == [
        ["-i", "br-lan", "-j", divert.CHAIN],
        ["-i", "eth0", "-j", divert.CHAIN],
    ]


def test_parse_hooks_ignores_other_chains():
    dump = "-A PREROUTING -j MINIUPNPD\n-A PREROUTING -i br-lan -j something_else"
    assert divert.parse_hooks(dump) == []


def test_parse_hooks_tolerates_empty_input():
    assert divert.parse_hooks("") == []


def _body(uplinks=("eth1",), *, bypass=False):
    """The lines `iptables -S <CHAIN>` renders for the chain we install."""
    return _flat(
        divert._chain_rules(divert.TPROXY_PORT, divert.TPROXY_MARK, list(uplinks), bypass=bypass)
    )


def test_a_correctly_installed_chain_matches():
    """The regression that made every apply and every 30s watchdog tick tear a
    *working* capture down and rebuild it — ~27 iptables calls with the LAN
    uncaptured in between. `_matches` never returned True, so the short-circuit
    that exists to avoid exactly that leak window was dead code.
    """
    for bypass in (False, True):
        for uplinks in ((), ("eth1",), ("eth1", "wwan0")):
            assert divert.body_matches(
                _body(uplinks, bypass=bypass),
                uplinks,
                divert.TPROXY_PORT,
                divert.TPROXY_MARK,
                bypass=bypass,
            ), (uplinks, bypass)


def test_interface_escapes_do_not_count_as_the_private_range_escapes():
    """The precise cause: `-i lo -j RETURN` is the chain's first rule and also
    ends in `-j RETURN`, so scanning for any RETURN put the DNS divert
    'after the escapes' on a perfectly ordered chain."""
    body = _body()
    assert body[0].endswith("-j RETURN")
    assert divert.body_matches(body, ["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False)


def test_dns_moved_after_the_escapes_is_rejected():
    """The failure the ordering check is actually for: queries fall through to
    dnsmasq and out to the ISP, with no error anywhere."""
    body = _body()
    dns = [ln for ln in body if "--dport 53" in ln]
    rest = [ln for ln in body if "--dport 53" not in ln]
    reordered = rest[:3] + dns + rest[3:]
    assert not divert.body_matches(
        reordered, ["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False
    )


def test_wrong_port_or_mark_is_rejected():
    """A stale chain from an older build sends the LAN to a dead socket."""
    body = _body()
    assert not divert.body_matches(body, ["eth1"], 9999, divert.TPROXY_MARK, bypass=False)
    assert not divert.body_matches(body, ["eth1"], divert.TPROXY_PORT, 0x1234, bypass=False)


def test_missing_or_extra_uplink_escape_is_rejected():
    body = _body(("eth1",))
    assert not divert.body_matches(
        body, ["eth1", "wwan0"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False
    )
    assert not divert.body_matches(body, [], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False)


def test_bypass_rule_naming_the_wrong_set_is_rejected():
    body = [ln.replace(divert.BYPASS_SET, "someone_elses_set") for ln in _body(bypass=True)]
    assert not divert.body_matches(
        body, ["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=True
    )


def test_a_swapped_reserved_range_is_rejected():
    """Counting the escapes isn't enough — it accepts a chain that RETURNs the
    fake-IP range in place of a real reserved one. That single substitution
    breaks every proxied *name* (198.18.x never reaches sing-box, so nothing
    maps it back to a domain) while raw-IP traffic keeps working, and the
    capture otherwise looks perfect.
    """
    body = [ln.replace("-d 0.0.0.0/8", "-d 198.18.0.0/15") for ln in _body()]
    assert len(body) == len(_body())
    assert not divert.body_matches(
        body, ["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False
    )


def test_loopback_escape_after_the_dns_divert_is_rejected():
    """The router-DNS loop, which the `-d`-scoped ordering check can't see:
    queries to 127.0.0.1 get TPROXY'd and answered with a fake IP, and
    sing-box's own `dns-local` resolves through /etc/resolv.conf — back here.
    """
    body = _body()
    lo = body[0]
    assert " -i lo " in lo
    dns_end = max(i for i, ln in enumerate(body) if "--dport 53" in ln)
    moved = [*body[1 : dns_end + 1], lo, *body[dns_end + 1 :]]
    assert len(moved) == len(body)
    assert not divert.body_matches(
        moved, ["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False
    )


def test_truncated_chain_is_rejected():
    assert not divert.body_matches(
        _body()[:-1], ["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False
    )


def test_mark_and_table_are_consistent():
    """The mark is what steers packets into the table; a mismatch means the
    divert marks packets nothing routes."""
    assert divert.TPROXY_MARK == 0x2023
    assert divert.ROUTE_TABLE == 2023


# --- install() settling behaviour -------------------------------------------


async def _install_with(monkeypatch, *, load_ok, installed_bypass=None):
    """Drive `install()` with the kernel faked out.

    `installed_bypass` models what is already in the chain: None = nothing.
    Returns (result, rebuilt) where `rebuilt` counts how many times the capture
    was actually rebuilt — the thing that must not happen on a settled tick.

    Counted by the *staging chain being created*, not by a teardown: a rebuild
    no longer removes the live capture first, which is the entire point of it.
    Counting teardowns here would report 0 for every rebuild and quietly retire
    both of the regression tests below.
    """
    state = {"bypass": installed_bypass, "rebuilt": 0}

    async def fake_matches(uplinks, port, mark, *, bypass):
        return state["bypass"] is not None and state["bypass"] == bypass

    async def fake_remove(**_kw):
        state["bypass"] = None

    async def fake_load(nets):
        return load_ok

    async def fake_ipt(args, timeout=10.0):
        if args[:4] == ["-t", "mangle", "-N", divert.STAGING_CHAIN]:
            state["rebuilt"] += 1
        return 0

    monkeypatch.setattr(divert, "_matches", fake_matches)
    monkeypatch.setattr(divert, "_remove_locked", fake_remove)
    monkeypatch.setattr(divert, "_load_bypass_set", fake_load)
    monkeypatch.setattr(divert, "_supports_bypass", lambda: _true())
    monkeypatch.setattr(divert, "_ipt", fake_ipt)
    monkeypatch.setattr(divert, "_ip", lambda *a, **k: _zero())
    monkeypatch.setattr(divert, "_capture", lambda *a, **k: _empty())

    async def install(nets):
        before = state["rebuilt"]
        # The post-install verification reads the kernel, which we stubbed out
        # to nothing; short-circuit it, we're testing the decision path.
        # Both hooks: the staging one has to be visible, because the swap now
        # verifies that the hook it installed is still there. A fake that
        # answers "no staging hook" is describing a wiped PREROUTING, which
        # is a genuine failure and must not read as a successful install.
        monkeypatch.setattr(
            divert,
            "parse_hooks",
            lambda _d: [["-j", divert.CHAIN], ["-j", divert.STAGING_CHAIN]],
        )
        ok = await divert.install(["eth1"], bypass_nets=nets)
        state["bypass"] = False if ok else state["bypass"]
        return ok, state["rebuilt"] - before

    return install, state


async def _rc0(*_a, **_k):
    return 0, ""


async def _none(*_a, **_k):
    return None


async def _true():
    return True


async def _zero():
    return 0


async def _empty():
    return ""


async def test_a_rejected_bypass_list_settles_instead_of_rebuilding_every_tick(monkeypatch):
    """The P0 that fixing the previous P0 introduced.

    Degrading to `bypass=False` *after* `_matches` had been asked with
    `bypass=True` meant the next tick asked about a chain we never installed —
    14 rules vs 15 — so it mismatched forever. Every apply and every 30s
    watchdog tick then tore the capture down and rebuilt it, measured at ~0.9s
    of fail-OPEN unproxied LAN each time, with install() returning True and the
    dashboard green. Indefinitely.
    """
    divert._bypass_rejected = None
    divert._loaded_bypass = None
    install, _state = await _install_with(monkeypatch, load_ok=False)

    ok, rebuilt = await install(["0.0.0.0/0"])
    assert ok and rebuilt == 1  # first install legitimately builds the chain

    for _ in range(3):
        ok, rebuilt = await install(["0.0.0.0/0"])
        assert ok, "must keep the VPN — degrading is not failing"
        assert rebuilt == 0, "settled: a rejected list must not rebuild the capture"

    divert._bypass_rejected = None


async def test_a_corrected_bypass_list_is_retried(monkeypatch):
    """The memo is keyed on the list, so fixing it doesn't need a restart."""
    divert._bypass_rejected = None
    divert._loaded_bypass = None
    install, _ = await _install_with(monkeypatch, load_ok=False)
    await install(["0.0.0.0/0"])
    await install(["0.0.0.0/0"])
    assert divert._bypass_rejected == ("0.0.0.0/0",)

    _, rebuilt = await install(["203.0.113.0/24"])
    assert rebuilt == 1, "a different list must be attempted, not written off"
    divert._bypass_rejected = None


def test_norm_cidr_makes_either_kernel_rendering_compare_equal():
    """The helper added to *prevent* rebuild-every-tick guessed the rendering,
    and guessed wrong: iptables 1.8.7 on OpenWrt 21.02 prints `-d 8.8.8.8/32`,
    not the bare form its docstring claimed. Normalising both sides is immune
    to which one a given kernel uses."""
    assert divert._norm_cidr("8.8.8.8/32") == divert._norm_cidr("8.8.8.8")
    assert divert._norm_cidr("10.0.0.0/8") == "10.0.0.0/8"


async def test_remove_waits_for_the_lock_unless_explicitly_forced(monkeypatch):
    """Forcing a teardown out from under a running install black-holes the LAN.

    The installer's next `-A` lands in a chain that was just `-X`'d, and it can
    re-add the PREROUTING hook afterwards — pointing every LAN packet at a
    chain that no longer exists. `stop()` and the watchdog's give-up path both
    reach `remove()` on a *live* daemon, so waiting has to be the default; only
    the lifespan teardown, which runs after the pipeline and watchdog have
    stopped, may force.
    """
    order: list[str] = []

    async def slow_remove(**_kw):
        order.append("removed")

    monkeypatch.setattr(divert, "_remove_locked", slow_remove)

    lock = divert._get_lock()
    await lock.acquire()
    try:
        waiting = asyncio.ensure_future(divert.remove())
        await asyncio.sleep(0.05)
        assert order == [], "remove() tore down while the lock was held"

        forced = asyncio.ensure_future(divert.remove(force_after_s=0.05))
        await asyncio.sleep(0.2)
        assert order == ["removed"], "an explicit force must not wait forever"
    finally:
        lock.release()
        await waiting
        await forced
    assert order == ["removed", "removed"]


async def test_a_transient_load_failure_is_retried_on_a_timer(monkeypatch):
    """The memo must not be permanent, and must not be cleared by an unrelated
    rebuild either.

    Every cause that reaches it is transient — a momentarily full /tmp, an
    `ipset` timeout — because `0.0.0.0/0` and an over-capacity list are
    rejected at parse time. Clearing it only in `_remove_locked` meant "retried
    when something *else* forces a rebuild", which on a stable router is days
    or never; and clearing it *inside* that call made the very next tick tear
    down a correct capture just to re-add the bypass rule. A timer does
    neither.
    """
    want = ("203.0.113.0/24",)
    loads: list[str] = []

    async def load(nets):
        loads.append("tried")
        return False

    monkeypatch.setattr(divert, "_load_bypass_set", load)
    monkeypatch.setattr(divert, "_supports_bypass", lambda: _true())
    monkeypatch.setattr(divert, "_matches", lambda *a, **k: _true())
    monkeypatch.setattr(divert, "_bypass_rejected", want)
    monkeypatch.setattr(divert, "_bypass_rejected_at", 1000.0)
    monkeypatch.setattr(divert, "_loaded_bypass", None)

    # Inside the retry window: no attempt, and no rebuild.
    monkeypatch.setattr(divert, "_monotonic", lambda: 1000.0 + divert._BYPASS_RETRY_S - 1)
    assert await divert.install(["eth1"], bypass_nets=list(want)) is True
    assert loads == [], "retried too eagerly — a failed probe would force a rebuild"

    # Past it: probed once, and the failure re-arms the timer rather than
    # retrying on every subsequent tick.
    monkeypatch.setattr(divert, "_monotonic", lambda: 1000.0 + divert._BYPASS_RETRY_S + 1)
    assert await divert.install(["eth1"], bypass_nets=list(want)) is True
    assert loads == ["tried"]
    assert divert._bypass_rejected_at == 1000.0 + divert._BYPASS_RETRY_S + 1


async def test_a_teardown_clears_the_loaded_set_cache(monkeypatch):
    """`_remove_locked` destroys the set, so the cache must not go on claiming
    contents the kernel no longer has."""
    monkeypatch.setattr(divert, "_loaded_bypass", ("203.0.113.0/24",))
    monkeypatch.setattr(divert, "_capture", lambda *a, **k: _empty())
    monkeypatch.setattr(divert, "_ipt", lambda *a, **k: _zero())
    monkeypatch.setattr(divert, "_ip", lambda *a, **k: _zero())
    monkeypatch.setattr(divert, "_run", lambda *a, **k: _run_ok())

    await divert._remove_locked()
    assert divert._loaded_bypass is None


async def _run_ok():
    return 0, ""


async def test_an_install_will_not_hook_after_a_forced_teardown(monkeypatch):
    """The shutdown path forces past the lock on a deadline. Without a guard,
    a wedged install completes afterwards and rebuilds the *entire* capture —
    hook included — behind the teardown, pointing the LAN at a sing-box that
    procd is about to stop. Reproduced by pass 7 on a real kernel: `remove()`
    returned a clean kernel, and the install then left it fully hooked.
    """
    monkeypatch.setattr(divert, "_matches", lambda *a, **k: _false())
    monkeypatch.setattr(divert, "_ip", lambda *a, **k: _zero())
    monkeypatch.setattr(divert, "_capture", lambda *a, **k: _empty())
    monkeypatch.setattr(divert, "_run", lambda *a, **k: _run_ok())

    hooked: list[str] = []
    wedge = asyncio.Event()

    async def ipt(args, **_kw):
        if args[:4] == ["-t", "mangle", "-A", "PREROUTING"]:
            hooked.append(" ".join(args))
        if "-N" in args:
            await wedge.wait()  # stall mid-build, like a slow ipset/iptables
        return 0

    monkeypatch.setattr(divert, "_ipt", ipt)

    install = asyncio.ensure_future(divert.install(["eth1"]))
    await asyncio.sleep(0.05)  # let it take the lock and stall

    await divert.remove(force_after_s=0.05)  # shutdown forces past the lock
    wedge.set()
    assert await install is False, "an install that lost its capture must not report success"
    assert hooked == [], "re-hooked PREROUTING after the teardown"


async def _false():
    return False


async def test_an_installs_own_teardown_does_not_block_the_rebuild(monkeypatch):
    """A rebuild tears down its own predecessor before building. The generation
    counter this replaced counted that as "someone removed the capture
    underneath me" and failed the install's own check, so every rebuild
    returned False with nothing installed — and needed a `bump=False` exemption
    at nine call sites to avoid it. A latch set only by the shutdown teardown
    has no such ambiguity.
    """
    monkeypatch.setattr(divert, "_matches", lambda *a, **k: _false())
    monkeypatch.setattr(divert, "_ip", lambda *a, **k: _zero())
    monkeypatch.setattr(divert, "_ipt", lambda *a, **k: _zero())
    monkeypatch.setattr(divert, "_run", lambda *a, **k: _run_ok())
    monkeypatch.setattr(divert, "_capture", lambda *a, **k: _empty())
    monkeypatch.setattr(
        divert, "parse_hooks", lambda _d: [["-j", divert.CHAIN], ["-j", divert.STAGING_CHAIN]]
    )

    for _ in range(3):
        assert await divert.install(["eth1"]) is True


async def test_nothing_installs_after_a_forced_teardown(monkeypatch):
    """A counter can only say "a teardown happened during my run", and "my run"
    depends on where the straggler sampled it. The shutdown teardown needs a
    one-way latch: after it, nothing may hook again, because procd stops
    sing-box right behind us and there is no daemon left to notice."""
    monkeypatch.setattr(divert, "_ipt", lambda *a, **k: _zero())
    monkeypatch.setattr(divert, "_ip", lambda *a, **k: _zero())
    monkeypatch.setattr(divert, "_run", lambda *a, **k: _run_ok())
    monkeypatch.setattr(divert, "_capture", lambda *a, **k: _empty())

    await divert.remove(force_after_s=0.05)
    assert divert._frozen is True
    assert await divert.install(["eth1"]) is False


# --- an unreadable ruleset is not a mismatch --------------------------------


async def test_matches_reports_unknown_rather_than_mismatch(monkeypatch):
    """`iptables -w 5 -S` exits 4 while another writer holds the xtables lock,
    so `_capture` returns None. Answering False there sent the caller into a
    teardown+rebuild that needs the very same lock."""
    monkeypatch.setattr(divert, "_capture", lambda *a, **k: _none())
    assert await divert._matches(["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK) is None


async def test_install_leaves_the_capture_alone_when_it_cannot_be_read(monkeypatch):
    """Measured on a 5.4 kernel before this: from a fully correct capture with
    the lock held 12 s, the rebuild left 7.9 s of unproxied LAN, and one run
    ended with hook, chain and ip rule all gone while install() returned True.
    """
    removed = []

    async def fake_remove(**kw):
        removed.append(kw)
        return True

    monkeypatch.setattr(divert, "_matches", lambda *a, **k: _none())
    monkeypatch.setattr(divert, "_remove_locked", fake_remove)
    monkeypatch.setattr(divert, "_supports_bypass", lambda: _true())
    ok = await divert.install(["eth1"], bypass_nets=[], port=divert.TPROXY_PORT)
    assert ok is False  # honest: we could not verify, and we changed nothing
    assert removed == []  # the working capture was NOT torn down


# --- a contended ipset probe is not "this kernel has no xt_set" -------------


async def test_bypass_probe_reports_unknown_when_it_cannot_run(monkeypatch):
    """`iptables -w 5` exits 4 while another writer holds the xtables lock, and
    the probe proves support by *adding a real rule*, so it takes the lock too."""

    async def contended(args, timeout=10.0):
        return 4  # iptables' resource/lock error

    monkeypatch.setattr(divert, "_bypass_supported", False)
    monkeypatch.setattr(divert, "_run", lambda *a, **k: _rc0())
    monkeypatch.setattr(divert, "_ipt", contended)
    assert await divert._supports_bypass() is None


async def test_install_does_not_drop_bypass_on_a_contended_probe(monkeypatch):
    """Reading the contended probe as "unsupported" flipped `bypass` off, which
    mismatched the live chain and rebuilt the capture WITHOUT the bypass rule.
    Measured: 15 rules / 1 --match-set became 14 / 0, 0.54 s uncaptured, and
    install() returned True — then a second teardown to put it back."""
    removed = []

    async def fake_remove(**kw):
        removed.append(kw)
        return True

    monkeypatch.setattr(divert, "_supports_bypass", lambda: _none())
    monkeypatch.setattr(divert, "_remove_locked", fake_remove)
    # A genuine mismatch, so the teardown really is reachable — otherwise this
    # test passes for the wrong reason via the unreadable-ruleset guard.
    monkeypatch.setattr(divert, "_matches", lambda *a, **k: _false())
    ok = await divert.install(["eth1"], bypass_nets=["10.0.0.0/8"], port=divert.TPROXY_PORT)
    assert ok is False
    assert removed == []  # the live capture, bypass rule and all, was untouched


async def test_install_recovers_from_a_leftover_chain(monkeypatch):
    """`-N` fails when the chain is already there, and by that point the
    teardown has run — so a chain that survived it (referenced from somewhere
    we did not parse, or an `-X` that lost the xtables lock) made every
    subsequent install fail hard and left the LAN uncaptured for good. The
    probe chain already handles this the right way. It is the staging chain
    that gets built now, so that is the one whose leftover must be survivable."""

    async def fake_remove(**kw):
        return True

    kernel = _FakeMangle([divert.CHAIN], new_rc=1)  # -N always fails: chain exists
    calls = kernel.install_into(monkeypatch)
    monkeypatch.setattr(divert, "_remove_locked", fake_remove)
    monkeypatch.setattr(divert, "_supports_bypass", lambda: _true())

    assert await divert.install(["eth1"], bypass_nets=[], port=divert.TPROXY_PORT) is True
    assert ["-t", "mangle", "-F", divert.STAGING_CHAIN] in calls  # flushed what was there
    assert kernel.hooks == [divert.CHAIN]


async def test_chain_fails_closed_on_protocols_tproxy_cannot_carry():
    """TPROXY only exists for TCP and UDP, so everything else fell off the end
    of the chain and was forwarded in the clear while the UI said the VPN was
    on. Measured with a sniffer on the WAN, capture healthy: ICMP echo, GRE
    (47), ESP (50), 6in4 (41) and SCTP (132) all reached the far side — which
    exposes the destinations, lets traceroute map the real path, and lets a
    client-run IPsec/6in4/GRE tunnel bypass the VPN entirely.
    """
    rules = divert._chain_rules(divert.TPROXY_PORT, divert.TPROXY_MARK, ["eth1"], bypass=True)
    assert rules[-1] == ["-A", divert.CHAIN, "-j", "DROP"]

    # Everything meant to escape must RETURN before it, or the DROP would eat
    # the uplink, the LAN and the bypass list along with the leak.
    drop_at = len(rules) - 1
    for i, r in enumerate(rules):
        if "RETURN" in r:
            assert i < drop_at
    assert any("--match-set" in " ".join(r) for r in rules[:drop_at])
    assert any(r[:4] == ["-A", divert.CHAIN, "-i", "eth1"] for r in rules[:drop_at])


def _dispatching_capture(prerouting="", *, ip_rule="", input_dump="", table=""):
    """A `_capture` stub that answers by command, so a test can model a kernel
    that has *some* of the capture rather than all or none of it."""

    async def capture(argv, timeout=10.0):
        joined = " ".join(argv)
        if "-S PREROUTING" in joined:
            return prerouting
        if joined.startswith("ip rule"):
            return ip_rule
        if "-S INPUT" in joined:
            return input_dump
        if "route show table" in joined:
            return table
        return ""

    return capture


def _recording_ipt(monkeypatch, rc=0):
    calls: list[list[str]] = []

    async def fake_ipt(args, timeout=10.0):
        calls.append(list(args))
        return rc

    monkeypatch.setattr(divert, "_ipt", fake_ipt)
    return calls


class _FakeMangle:
    """The PREROUTING hook list, mutated by the calls under test and read back
    through `_capture`.

    A *static* dump is not good enough here, and that is not hypothetical: with
    one, `_finish_swap` never sees the hook the code just added, so the entire
    swap reads as "nothing staged", does nothing, and the test passes for the
    wrong reason. Three tests did exactly that until the guard against a
    swap-that-is-not-in-flight exposed them.
    """

    def __init__(self, hooks=(), *, new_rc=0):
        self.hooks = list(hooks)
        self.calls: list[list[str]] = []
        self.new_rc = new_rc

    async def ipt(self, args, timeout=10.0):
        self.calls.append(list(args))
        if args[:4] == ["-t", "mangle", "-A", "PREROUTING"] and args[4] == "-j":
            self.hooks.append(args[5])
        elif args[:4] == ["-t", "mangle", "-D", "PREROUTING"] and args[-2] == "-j":
            if args[-1] in self.hooks:
                self.hooks.remove(args[-1])
        elif args[:3] == ["-t", "mangle", "-E"]:
            self.hooks = [args[4] if h == args[3] else h for h in self.hooks]
        elif args[:3] == ["-t", "mangle", "-N"]:
            return self.new_rc
        return 0

    async def capture(self, argv, timeout=10.0):
        joined = " ".join(argv)
        if "-S PREROUTING" in joined:
            return "-P PREROUTING ACCEPT\n" + "".join(f"-A PREROUTING -j {h}\n" for h in self.hooks)
        return ""

    def install_into(self, monkeypatch):
        monkeypatch.setattr(divert, "_ipt", self.ipt)
        monkeypatch.setattr(divert, "_capture", self.capture)
        monkeypatch.setattr(divert, "_ip", lambda *a, **k: _zero())
        monkeypatch.setattr(divert, "_matches", lambda *a, **k: _false())
        return self.calls

    def index_of(self, *prefix):
        return next(i for i, c in enumerate(self.calls) if c[: len(prefix)] == list(prefix))


async def test_a_rebuild_hooks_the_replacement_before_retiring_the_old_chain(monkeypatch):
    """The leak this design exists to close.

    Rebuilding in place — tear down, repopulate, re-hook — left the LAN
    unproxied for the length of ~14 iptables fork/execs. Measured on a 5.4
    kernel at 2000 pps, escapes counted in filter/FORWARD: 3070-3463 packets
    (1.54-1.73 s) per rebuild, carrying the client's own source address to the
    far end in the clear.

    The invariant that fixes it is an ordering one, so assert the order: the
    replacement must be hooked before anything touches the live chain, and the
    live chain must not be flushed or unhooked before that.
    """
    kernel = _FakeMangle([divert.CHAIN])
    calls = kernel.install_into(monkeypatch)

    assert await divert.install(["eth1"]) is True
    assert kernel.hooks == [divert.CHAIN], "must end with exactly one hook, under the usual name"

    index_of = kernel.index_of
    hooked = index_of("-t", "mangle", "-A", "PREROUTING", "-j", divert.STAGING_CHAIN)
    unhooked = index_of("-t", "mangle", "-D", "PREROUTING", "-j", divert.CHAIN)
    flushed = index_of("-t", "mangle", "-F", divert.CHAIN)

    assert hooked < unhooked, "the old hook must not go before the new one is in"
    assert hooked < flushed, "flushing the live chain first is the 1.6s leak"

    # And the replacement is fully populated by then, **in the staging chain**.
    # Asserting only the count let a real bug through: `_chain_rules` grew a
    # `chain=` parameter that its body never used, so every rule was appended
    # to the live chain instead. On a real kernel that made a fresh install
    # fail outright and a recovery hook an *empty* chain — a capture that
    # matches nothing, which is fail-open.
    body = [c for c in calls[:hooked] if c[:3] == ["-t", "mangle", "-A"]]
    assert len(body) == len(
        divert._chain_rules(divert.TPROXY_PORT, divert.TPROXY_MARK, ["eth1"], bypass=False)
    )
    assert all(c[3] == divert.STAGING_CHAIN for c in body), body


@pytest.mark.parametrize("bypass", [False, True])
def test_every_rule_lands_in_the_chain_it_was_asked_for(bypass):
    """`_chain_rules` builds the body for whichever chain the caller names, and
    a rule that ignores that lands in the live capture instead."""
    rules = divert._chain_rules(
        divert.TPROXY_PORT,
        divert.TPROXY_MARK,
        ["eth1"],
        bypass=bypass,
        chain=divert.STAGING_CHAIN,
    )
    assert rules, "no rules generated"
    for r in rules:
        assert r[0] == "-A" and r[1] == divert.STAGING_CHAIN, r


async def test_the_swap_ends_with_the_replacement_under_the_usual_name(monkeypatch):
    """`_matches`, `installed_state` and the docs all name one chain, so the
    staging chain has to give its contents that name rather than the code
    learning to accept two. `iptables -E` rewrites the PREROUTING jump along
    with the chain — verified on iptables v1.8.7 (legacy), which is what
    OpenWrt 21.02 and the target router ship."""
    kernel = _FakeMangle()  # nothing installed yet: a fresh install
    calls = kernel.install_into(monkeypatch)

    assert await divert.install(["eth1"]) is True
    assert ["-t", "mangle", "-E", divert.STAGING_CHAIN, divert.CHAIN] in calls
    assert kernel.hooks == [divert.CHAIN]


async def test_a_hooked_staging_chain_is_completed_not_flushed(monkeypatch):
    """A crash between the hook swap and the rename leaves the *live* capture
    under the staging name. Reusing the name by flushing it would put the LAN
    in the clear for the length of the rebuild that follows — reintroducing the
    very leak, in the recovery path. Finish the swap instead."""
    calls = _recording_ipt(monkeypatch)
    monkeypatch.setattr(
        divert, "_capture", _dispatching_capture(f"-A PREROUTING -j {divert.STAGING_CHAIN}\n")
    )

    assert await divert._reclaim_staging() is True
    assert ["-t", "mangle", "-F", divert.STAGING_CHAIN] not in calls
    assert ["-t", "mangle", "-E", divert.STAGING_CHAIN, divert.CHAIN] in calls


async def test_an_unreadable_ruleset_leaves_the_staging_chain_alone(monkeypatch):
    """Same reasoning as `_matches` returning None: we cannot tell whether that
    chain is live, and flushing it on a guess is the destructive answer."""
    calls = _recording_ipt(monkeypatch)
    monkeypatch.setattr(divert, "_capture", lambda *a, **k: _none())

    assert await divert._reclaim_staging() is False
    assert not calls


async def test_teardown_flushes_the_staging_chain_too(monkeypatch):
    """`remove()` reporting success over a live capture is this module's oldest
    P0, and a half-finished swap is a new way to reach it: the capture is under
    the staging name, so flushing only CHAIN neuters nothing."""
    calls = _recording_ipt(monkeypatch)
    monkeypatch.setattr(divert, "_ip", lambda *a, **k: _zero())
    monkeypatch.setattr(divert, "_run", lambda *a, **k: _rc0())
    monkeypatch.setattr(
        divert, "_capture", _dispatching_capture(f"-A PREROUTING -j {divert.STAGING_CHAIN}\n")
    )

    await divert._remove_locked()
    assert ["-t", "mangle", "-F", divert.STAGING_CHAIN] in calls
    assert ["-t", "mangle", "-D", "PREROUTING", "-j", divert.STAGING_CHAIN] in calls


def test_parse_hooks_sees_a_staging_hook():
    """Between the swap and the rename the staging chain *is* the capture, so a
    hook into it has to count — for `installed_state()` as much as for the
    teardown."""
    dump = f"-P PREROUTING ACCEPT\n-A PREROUTING -j {divert.STAGING_CHAIN}\n"
    assert divert.parse_hooks(dump) == [["-j", divert.STAGING_CHAIN]]


async def test_the_fwmark_rule_is_not_stacked_when_it_is_already_there(monkeypatch):
    """`ip rule add` is not idempotent and the rebuild no longer runs a teardown
    that deleted the previous one, so an unguarded add grows the rule list by
    one on every uplink change and every fw3 reload."""
    calls: list[list[str]] = []

    async def fake_ip(args, timeout=5.0):
        calls.append(list(args))
        return 0

    monkeypatch.setattr(divert, "_ip", fake_ip)
    monkeypatch.setattr(
        divert,
        "_capture",
        _dispatching_capture(
            ip_rule=f"5000: from all fwmark {hex(divert.TPROXY_MARK)} lookup {divert.ROUTE_TABLE}\n"
        ),
    )

    assert await divert._ensure_ip_rule(divert.TPROXY_MARK) is True
    assert calls == []


async def test_the_input_accept_is_left_alone_when_it_is_already_first(monkeypatch):
    """The common rebuild must not churn filter/INPUT: deleting and re-inserting
    exposes captured traffic to fw3's syn_flood and any zone REJECT for the
    length of the gap, for no gain."""
    calls = _recording_ipt(monkeypatch)
    monkeypatch.setattr(
        divert,
        "_capture",
        _dispatching_capture(
            input_dump=f"-A INPUT -m comment --comment {divert._INPUT_ACCEPT_COMMENT} -j ACCEPT\n"
        ),
    )

    assert await divert._ensure_input_accept(divert.TPROXY_MARK) is True
    assert calls == []


async def test_finishing_a_swap_that_is_not_in_flight_touches_nothing(monkeypatch):
    """Without the guard this function is a full teardown, not a no-op: it
    deletes the live `-j CHAIN` hook, flushes and deletes the live chain, then
    fails the rename because there is nothing to rename. Measured on a real
    kernel, one such call cost 4,180 escaped packets over 2.2 s and left the
    LAN uncaptured — and only the `_staging_hooked` bookkeeping kept it
    unreachable, i.e. one deleted line away, while the docstring promised
    idempotence."""
    calls = _recording_ipt(monkeypatch)
    monkeypatch.setattr(
        divert, "_capture", _dispatching_capture(f"-A PREROUTING -j {divert.CHAIN}\n")
    )

    assert await divert._finish_swap() is True
    assert calls == [], "a live capture must not be touched when nothing is staged"


async def test_a_staged_hook_wiped_before_the_handover_is_not_a_success(monkeypatch):
    """The P0 that lived inside the previous fix.

    The guard against "no swap in flight" asked the *kernel* whether a staging
    hook was present. That cannot tell "nothing was staged" apart from "the hook
    I installed 20 ms ago was removed under me", and it answered the second with
    success. Measured on a real kernel with an `/etc/init.d/firewall restart`
    landing in that window — median 20.7 ms wide, one fork/exec: 10,213 packets
    counted escaping in filter/FORWARD and 10,333 arriving at the far end still
    carrying the client's address, while `install()` returned True and the
    dashboard read CAPTURED. `_staging_hooked` always knew the difference.
    """
    kernel = _FakeMangle([divert.CHAIN])
    kernel.install_into(monkeypatch)

    real_ipt = kernel.ipt

    async def wiping_ipt(args, timeout=10.0):
        rc = await real_ipt(args, timeout)
        # Somebody flushes mangle/PREROUTING the moment the staging hook lands.
        if args[:4] == ["-t", "mangle", "-A", "PREROUTING"]:
            kernel.hooks = []
        return rc

    monkeypatch.setattr(divert, "_ipt", wiping_ipt)

    assert await divert.install(["eth1"]) is False, "an uncaptured LAN is not a successful install"
    assert kernel.hooks == [], "and the kernel really is left with no capture"


async def test_a_failed_teardown_keeps_the_policy_routing_half(monkeypatch):
    """`ip` does not take the xtables lock, so under sustained contention every
    iptables call can fail while these two succeed — leaving a live hook into a
    fully armed chain with nothing to route the marked packets. Measured with
    the lock held through a 60 s remove(): hook present, 16 rules, 4 TPROXY
    targets, no ip rule, table 2023 empty, 205,159 of 338,100 packets dropped,
    traceroute dead — and `installed_state()` still True, because it reads the
    hook alone. On the shutdown path nothing is left to heal it."""
    ip_calls: list[list[str]] = []

    async def fake_ip(args, timeout=5.0):
        ip_calls.append(list(args))
        return 0

    monkeypatch.setattr(divert, "_ipt", lambda *a, **k: _four())  # every iptables call: lock held
    monkeypatch.setattr(divert, "_ip", fake_ip)
    monkeypatch.setattr(divert, "_run", lambda *a, **k: _rc0())
    monkeypatch.setattr(divert, "_capture", lambda *a, **k: _none())

    assert await divert._remove_locked() is False
    assert not any(c[:2] == ["rule", "del"] for c in ip_calls), (
        "the fwmark rule must survive a teardown that could not remove the chain"
    )
    assert not any(c[:2] == ["route", "flush"] for c in ip_calls)


async def test_the_input_accept_is_never_removed_before_its_replacement_is_in(monkeypatch):
    """This rule belongs to the capture that is still live. Deleting it first
    meant a rebuild that then failed left the running capture without it, and a
    zone with the stock `input REJECT` went dark — measured, 40/40 TCP connects
    refused from a guest client while the LAN zone kept working, with nothing to
    restore it until the next successful install."""
    calls = _recording_ipt(monkeypatch)
    monkeypatch.setattr(
        divert,
        "_capture",
        _dispatching_capture(
            input_dump=(
                "-A INPUT -j syn_flood\n"
                f"-A INPUT -m comment --comment {divert._INPUT_ACCEPT_COMMENT} -j ACCEPT\n"
            )
        ),
    )

    assert await divert._ensure_input_accept(divert.TPROXY_MARK) is True
    kinds = [c[2] for c in calls if c[:2] == ["-t", "filter"]]
    assert kinds and kinds[0] == "-I", f"the insert must come first, got {kinds}"


async def test_an_unreadable_input_chain_is_not_answered_by_inserting(monkeypatch):
    """Inserting blind was measurably unbounded — one duplicate per contended
    install, forever, invisible because `_matches` only inspects the first rule
    and the teardown deletes at most four."""
    calls = _recording_ipt(monkeypatch)
    monkeypatch.setattr(divert, "_capture", lambda *a, **k: _none())

    assert await divert._ensure_input_accept(divert.TPROXY_MARK) is False
    assert calls == []


async def _four():
    return 4


def test_a_chain_missing_its_terminal_drop_is_rejected():
    """The rule count was the only thing guarding this check, and it collides: a
    16-rule chain built WITH the bypass and missing its DROP is exactly as long
    as a correct 15-rule chain built WITHOUT one. Measured through such a chain
    — `body_matches(bypass=False)` returned True and `install()` reported
    success — ICMP, GRE and ESP all reached the far side carrying the client's
    traffic, and only a daemon restart would have cleared it."""
    body = _body(("eth1",), bypass=True)[:-1]  # drop the DROP
    assert len(body) == len(_body(("eth1",), bypass=False)), "the collision this guards"
    assert not divert.body_matches(
        body, ["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False
    )


def test_a_bypass_rule_we_did_not_ask_for_is_rejected():
    """Same collision, other half: the stale `--match-set` RETURN keeps sending
    a list the user has already removed straight out to the ISP."""
    body = _body(("eth1",), bypass=True)[:-1]
    assert any("--match-set" in ln for ln in body)
    assert not divert.body_matches(
        body, ["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False
    )


def test_a_chain_that_ends_in_something_other_than_drop_is_rejected():
    """Isolates the terminal check from the rule-count one. A chain of exactly
    the right length, with no bypass rule to give it away, that simply does not
    end in DROP: every non-TCP/UDP protocol then falls off the end and is
    forwarded in the clear while the UI says the VPN is on — ICMP, GRE, ESP and
    6in4 were all measured reaching the far side that way."""
    body = _body(("eth1",), bypass=False)
    body = [*body[:-1], body[-2]]  # same length, DROP replaced by a duplicate
    assert not body[-1].endswith("-j DROP")
    assert not divert.body_matches(
        body, ["eth1"], divert.TPROXY_PORT, divert.TPROXY_MARK, bypass=False
    )
