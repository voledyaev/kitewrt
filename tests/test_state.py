import json
import logging

import pytest
from kitewrt.state import (
    DEFAULT_DOH_URL,
    SCHEMA_VERSION,
    ActiveServerRef,
    Data,
    DnsState,
    State,
    Subscription,
)
from kitewrt.vless import Server


@pytest.fixture
def state(tmp_path):
    return State(tmp_path / "state.json")


def make_server(server_id: str, **kw) -> Server:
    defaults = {
        "name": server_id,
        "country": "??",
        "host": "",
        "port": 443,
        "uuid": "",
        "params": {},
    }
    defaults.update(kw)
    return Server(id=server_id, **defaults)


async def add_sub(state: State, label: str, source: str, servers=None) -> str:
    await state.add_subscription(label, source, servers or [])
    subs = state.snapshot().subscriptions
    return subs[-1].id


async def test_defaults_when_no_file(state):
    snap = state.snapshot()
    assert snap.version == SCHEMA_VERSION
    assert snap.subscriptions == []
    assert snap.vpn_on is False
    assert snap.active_server is None
    assert snap.dns == DnsState()


async def test_add_subscription_appends_and_assigns_id(state):
    sub_id = await add_sub(state, "Foo", "https://foo.example/sub", [make_server("a:443")])
    assert sub_id
    subs = state.snapshot().subscriptions
    assert len(subs) == 1
    assert subs[0].label == "Foo"
    assert subs[0].source == "https://foo.example/sub"
    assert subs[0].fetched_at


async def test_add_subscription_allows_duplicate_source(state):
    await add_sub(state, "First", "https://foo.example/sub", [])
    await add_sub(state, "Second", "https://foo.example/sub", [])
    assert len(state.snapshot().subscriptions) == 2


async def test_persist_across_reload(tmp_path):
    path = tmp_path / "state.json"
    s1 = State(path)
    sub_id = await add_sub(s1, "Foo", "https://x", [make_server("h:443")])

    def mutate(d: Data) -> None:
        d.vpn_on = True
        d.active_server = ActiveServerRef(subscription_id=sub_id, server_id="h:443")

    await s1.update(mutate)

    s2 = State(path)
    snap = s2.snapshot()
    assert snap.vpn_on is True
    assert snap.active_server is not None
    assert snap.active_server.subscription_id == sub_id
    assert len(snap.subscriptions) == 1
    assert snap.subscriptions[0].id == sub_id


async def test_state_file_is_owner_only(tmp_path):
    # state.json holds subscription URLs + VLESS credentials → mode 0o600.
    import stat

    path = tmp_path / "state.json"
    s = State(path)
    await add_sub(s, "Foo", "https://x", [make_server("h:443")])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # No leftover temp file after the durable write.
    assert not path.with_suffix(".json.tmp").exists()


async def test_migrate_older_schema_preserves_subscriptions(tmp_path):
    # A version bump must NOT silently discard the user's subscriptions/creds and
    # boot direct — a forward-compatible older file carries them across.
    path = tmp_path / "state.json"
    srv = make_server("h:443", uuid="secret-uuid")
    older = Data(
        version=SCHEMA_VERSION - 1,
        subscriptions=[
            Subscription(id="s1", label="L", source="https://x", fetched_at="t", servers=[srv])
        ],
        active_server=ActiveServerRef(subscription_id="s1", server_id="h:443"),
        vpn_on=True,
    )
    path.write_text(older.model_dump_json())

    snap = State(path).snapshot()
    assert snap.version == SCHEMA_VERSION  # adopted
    assert len(snap.subscriptions) == 1
    assert snap.subscriptions[0].servers[0].uuid == "secret-uuid"  # creds preserved
    assert snap.vpn_on is True  # stays protected across the upgrade
    assert snap.applying is False  # transient runtime field reset


async def test_migrate_inconsistent_old_schema_resets(tmp_path):
    # The v1 symptom — vpn_on with no servers (its singular subscription_url
    # shape collapses to empty subscriptions) — can't be honored, so reset.
    path = tmp_path / "state.json"
    path.write_text(Data(version=1, vpn_on=True).model_dump_json())

    snap = State(path).snapshot()
    assert snap.vpn_on is False
    assert snap.subscriptions == []


async def test_corrupt_state_resets_to_defaults(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{ not valid json")
    snap = State(path).snapshot()
    assert snap.subscriptions == []
    assert snap.vpn_on is False


async def test_delete_subscription_clears_active_when_affected(state):
    sub_id = await add_sub(state, "Foo", "x", [make_server("h:443")])

    def mutate(d: Data) -> None:
        d.active_server = ActiveServerRef(subscription_id=sub_id, server_id="h:443")
        d.vpn_on = True

    await state.update(mutate)
    await state.delete_subscription(sub_id)
    snap = state.snapshot()
    assert snap.active_server is None
    assert snap.vpn_on is False
    assert snap.subscriptions == []


async def test_delete_subscription_keeps_active_when_unrelated(state):
    id1 = await add_sub(state, "A", "x", [make_server("h:443")])
    id2 = await add_sub(state, "B", "y", [make_server("k:443")])

    def mutate(d: Data) -> None:
        d.active_server = ActiveServerRef(subscription_id=id1, server_id="h:443")
        d.vpn_on = True

    await state.update(mutate)
    await state.delete_subscription(id2)
    snap = state.snapshot()
    assert snap.active_server is not None
    assert snap.active_server.subscription_id == id1
    assert snap.vpn_on is True


async def test_replace_subscription_servers_clears_active_when_server_gone(state):
    sub_id = await add_sub(state, "Foo", "x", [make_server("old:443")])

    def mutate(d: Data) -> None:
        d.active_server = ActiveServerRef(subscription_id=sub_id, server_id="old:443")
        d.vpn_on = True

    await state.update(mutate)
    await state.replace_subscription_servers(sub_id, [make_server("new:443")])
    snap = state.snapshot()
    assert snap.active_server is None
    assert snap.vpn_on is False


async def test_replace_subscription_servers_keeps_active_when_still_present(state):
    sub_id = await add_sub(state, "Foo", "x", [make_server("stay:443")])

    def mutate(d: Data) -> None:
        d.active_server = ActiveServerRef(subscription_id=sub_id, server_id="stay:443")
        d.vpn_on = True

    await state.update(mutate)
    await state.replace_subscription_servers(
        sub_id, [make_server("other:443"), make_server("stay:443")]
    )
    snap = state.snapshot()
    assert snap.active_server is not None
    assert snap.active_server.server_id == "stay:443"
    assert snap.vpn_on is True


async def test_rename_subscription(state):
    sub_id = await add_sub(state, "Old", "x", [])
    await state.rename_subscription(sub_id, "New")
    assert state.snapshot().subscriptions[0].label == "New"


async def test_corrupt_json_falls_back_to_defaults(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{not valid json")
    s = State(path)
    snap = s.snapshot()
    assert snap.subscriptions == []
    assert snap.version == SCHEMA_VERSION


async def test_version_mismatch_falls_back_to_defaults(tmp_path):
    # v1-style state.json with subscription_url + flat servers is rejected at
    # load. User must re-enter subscriptions through the UI.
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "subscription_url": "https://old.example/sub",
                "servers": [{"id": "x:443"}],
                "active_server_id": "x:443",
                "vpn_on": True,
            }
        )
    )
    s = State(path)
    snap = s.snapshot()
    assert snap.version == SCHEMA_VERSION
    assert snap.subscriptions == []
    assert snap.vpn_on is False


async def test_atomic_no_tmp_left_behind(state):
    await state.update(lambda d: setattr(d, "vpn_on", True))
    tmp = state._path.with_suffix(state._path.suffix + ".tmp")
    assert not tmp.exists()


async def test_active_server_resolves_to_copy(state):
    sub_id = await add_sub(
        state,
        "Foo",
        "x",
        [make_server("h:443", host="h", params={"k": "v"})],
    )

    def mutate(d: Data) -> None:
        d.active_server = ActiveServerRef(subscription_id=sub_id, server_id="h:443")

    await state.update(mutate)
    active = state.active_server()
    assert active is not None
    assert active.id == "h:443"
    assert active.host == "h"
    # The returned model is frozen — attempting to mutate raises. But the
    # underlying params dict is plain; mutating it must not affect storage.
    active.params["k"] = "mutated"
    assert state.active_server().params["k"] == "v"


async def test_active_server_nil_when_unset(state):
    assert state.active_server() is None


async def test_active_server_nil_when_subscription_missing(state):
    def mutate(d: Data) -> None:
        d.active_server = ActiveServerRef(subscription_id="ghost", server_id="h:443")

    await state.update(mutate)
    assert state.active_server() is None


async def test_snapshot_is_independent_copy(state):
    await add_sub(state, "Foo", "x", [make_server("h:443")])
    snap = state.snapshot()
    snap.subscriptions[0].servers.append(make_server("injected:443"))
    assert len(state.snapshot().subscriptions[0].servers) == 1


async def test_rules_are_raw_json(tmp_path):
    """Rules round-trip as plain dicts — kitewrt does not model sing-box's
    schema, it only checks the keys it is prepared to accept.

    The sample used to be an xray rule (`outboundTag`, `type: field`). That was
    never loadable: sing-box rejects unknown fields, so such a document broke
    the data plane anyway, and the parser has refused xray markers for a while.
    Load now re-checks stored rules, which made it visible.
    """
    s = State(tmp_path / "state.json")
    rule = {"outbound": "proxy", "domain": ["foo.com"]}
    await s.update(lambda d: d.rules.append(rule))

    reloaded = State(s._path)
    snap = reloaded.snapshot()
    assert len(snap.rules) == 1
    assert snap.rules[0]["outbound"] == "proxy"
    assert snap.rules[0]["domain"] == ["foo.com"]


async def test_has_server(state):
    sub_id = await add_sub(state, "Foo", "x", [make_server("h:443")])
    assert state.has_server(sub_id, "h:443")
    assert not state.has_server(sub_id, "ghost:443")
    assert not state.has_server("ghost-sub", "h:443")


async def test_dns_section_loads_with_defaults_on_old_v2_file(tmp_path):
    # Old v2 state.json without the new `dns` field: backwards-compatible load
    # via Pydantic default. No schema bump needed.
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "version": SCHEMA_VERSION,
                "subscriptions": [],
                "active_server": None,
                "vpn_on": False,
                "rules": [],
                "rules_warnings": [],
                "rules_skipped_count": 0,
                "last_error": "",
                "last_apply": None,
                "applying": False,
                "rules_url": "",
                "rules_fetched_at": "",
            }
        )
    )
    s = State(path)
    snap = s.snapshot()
    assert snap.dns.doh_url == DEFAULT_DOH_URL


async def test_dns_section_persists(tmp_path):
    s = State(tmp_path / "state.json")

    def mutate(d: Data) -> None:
        d.dns.doh_url = "https://9.9.9.9/dns-query"

    await s.update(mutate)

    reloaded = State(s._path)
    snap = reloaded.snapshot()
    assert snap.dns.doh_url == "https://9.9.9.9/dns-query"


async def test_a_hostname_doh_url_saved_earlier_is_repaired_on_load(tmp_path, caplog):
    """A hostname DoH URL wedges *every* apply — sing-box uses it as
    `route.default_domain_resolver`, which must be an IP literal, and refuses
    the config. The API rejects it now, but anything already in state.json
    would keep failing forever with nothing in the UI to explain it.
    """
    s = State(tmp_path / "state.json")

    def mutate(d: Data) -> None:
        object.__setattr__(d.dns, "doh_url", "https://dns.google/dns-query")

    await s.update(mutate)

    with caplog.at_level(logging.WARNING, logger="kitewrt.state"):
        reloaded = State(s._path)
    assert reloaded.snapshot().dns.doh_url == DEFAULT_DOH_URL
    assert any("hostname" in r.getMessage() for r in caplog.records)


async def test_applying_is_never_restored_from_disk(tmp_path):
    """`applying` describes a worker running *now*. Shutdown cancels the apply
    worker, so it can be left True on disk — and the next boot then reads it:
    the watchdog returns immediately every tick (no capture re-assert, no
    sing-box supervision) and the UI shows a permanent spinner."""
    s = State(tmp_path / "state.json")
    await s.update(lambda d: setattr(d, "applying", True))
    assert State(s._path).snapshot().applying is False


async def test_a_failed_write_leaves_memory_untouched(tmp_path, monkeypatch):
    """All-or-nothing, because a half-applied update wedged the whole daemon.

    `update()` used to mutate in place and save afterwards, so an OSError from
    the durable write left the mutation in memory with nothing on disk — and a
    caller that sets `applying=True` and *then* signals the apply pipeline never
    reached its signal. The flag stayed set with no apply that could clear it,
    the watchdog stands down while it is set, and the LAN sat dark for over five
    minutes with last_apply.ok true. Measured on a full filesystem.
    """
    from kitewrt import state as state_mod

    st = State(tmp_path / "s.json")
    await st.update(lambda d: setattr(d, "vpn_on", True))
    assert st.snapshot().vpn_on is True

    def boom(*_a, **_kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(state_mod, "_atomic_write_durable", boom)
    with pytest.raises(OSError):
        await st.update(lambda d: (setattr(d, "vpn_on", False), setattr(d, "applying", True)))

    snap = st.snapshot()
    assert snap.vpn_on is True, "a failed write must not change what the daemon acts on"
    assert snap.applying is False, "and must not strand the flag that retires the watchdog"


def test_a_stored_rule_the_current_validator_rejects_is_dropped_on_load(tmp_path):
    """The rules document is fetched once and persisted, so a rule accepted by
    an older build is fed to sing-box on every boot afterwards — a validator
    tightened later never sees it again. `override_address` rewrites the dial
    destination for matched domains, so a router that had already fetched a
    hostile document would have gone on honouring it through any number of
    upgrades."""
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "version": SCHEMA_VERSION,
                "rules": [
                    {"domain_suffix": ["ok.example"], "outbound": "proxy"},
                    {
                        "domain_suffix": ["victim-bank.example"],
                        "outbound": "proxy",
                        "override_address": "203.0.113.66",
                        "override_port": 8443,
                    },
                ],
            }
        )
    )
    loaded = State(path).snapshot()

    assert loaded.rules == [{"domain_suffix": ["ok.example"], "outbound": "proxy"}]
    assert loaded.rules_skipped_count == 1
    assert any("override_address" in w for w in loaded.rules_warnings)


def test_dropping_a_rule_set_also_drops_the_rules_that_reference_it(tmp_path):
    """sing-box refuses to start on a route rule naming an unknown rule-set tag,
    so dropping the definition without the references turns "less routing" into
    the boot failure the re-validation exists to avoid."""
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "version": SCHEMA_VERSION,
                "rules": [{"rule_set": ["blocked"], "outbound": "block"}],
                "rule_sets": [
                    {
                        "tag": "blocked",
                        "type": "remote",
                        "url": "http://localhost:9090/configs",
                        "format": "binary",
                    }
                ],
            }
        )
    )
    loaded = State(path).snapshot()

    assert loaded.rule_sets == []
    assert loaded.rules == []
    assert loaded.rules_skipped_count == 2


def test_a_clean_stored_document_is_left_exactly_as_it_was(tmp_path):
    """The repair must not churn a healthy document — a false positive here
    silently strips the user's routing on every boot."""
    rules = [{"domain_suffix": ["example.com"], "outbound": "proxy"}]
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"version": SCHEMA_VERSION, "rules": rules}))
    loaded = State(path).snapshot()

    assert loaded.rules == rules
    assert loaded.rules_skipped_count == 0
    assert loaded.rules_warnings == []


def test_stored_rule_warnings_cannot_grow_without_bound(tmp_path):
    """`rules_warnings` is persisted, re-appended on every boot, and shipped
    whole in every `/api/state` response and WS frame — the one field the
    bulk-to-count trim does not cover. Measured with a 20,000-rule document that
    the tightened validators reject: state.json 1.9 MB -> 2.8 MB and a
    2,749,487-byte state body, surviving reboots."""
    bad = [
        {"domain_suffix": [f"n{i}.example"], "outbound": "proxy", "override_address": "203.0.113.1"}
        for i in range(200)
    ]
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"version": SCHEMA_VERSION, "rules": bad}))

    loaded = State(path).snapshot()
    assert loaded.rules == []
    assert loaded.rules_skipped_count == 200, "the count stays honest"
    assert len(loaded.rules_warnings) <= 25, "the strings are only a sample"
