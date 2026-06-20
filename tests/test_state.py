import json

import pytest
from kitewrt.state import (
    DEFAULT_DOH_URL,
    SCHEMA_VERSION,
    ActiveServerRef,
    Data,
    DnsState,
    State,
)
from kitewrt.vless import Server


@pytest.fixture
def state(tmp_path):
    return State(tmp_path / "state.json")


def make_server(server_id: str, **kw) -> Server:
    defaults = dict(name=server_id, country="??", host="", port=443, uuid="", params={})
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
    s = State(tmp_path / "state.json")
    rule = {"outboundTag": "proxy", "domain": ["foo.com"], "type": "field"}
    await s.update(lambda d: d.rules.append(rule))

    reloaded = State(s._path)
    snap = reloaded.snapshot()
    assert len(snap.rules) == 1
    assert snap.rules[0]["outboundTag"] == "proxy"
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
        d.dns.doh_url = "https://dns.example/dns-query"

    await s.update(mutate)

    reloaded = State(s._path)
    snap = reloaded.snapshot()
    assert snap.dns.doh_url == "https://dns.example/dns-query"
