"""Router-level health metrics (kitewrt.sysmetrics).

These exist because everything else on the dashboard comes from sing-box's
Clash API, which only sees what reaches sing-box. Measured on a live GL-MT6000
during a `bypass_address` download: 512.5 MB crossed the WAN while the Clash
totals moved 1.5 MB — the "Download" chart was reporting 0.3% of the truth.
"""

from __future__ import annotations

from kitewrt import sysmetrics


def _fake_fs(
    tmp_path, monkeypatch, *, stat, netdev, meminfo=None, route=None, temp=None, hnat=None
):
    files = {"stat": stat, "netdev": netdev, "meminfo": meminfo, "route": route}
    paths = {}
    for name, content in files.items():
        if content is None:
            paths[name] = tmp_path / f"missing-{name}"
            continue
        p = tmp_path / name
        p.write_text(content)
        paths[name] = p
    monkeypatch.setattr(sysmetrics, "_PROC_STAT", paths["stat"])
    monkeypatch.setattr(sysmetrics, "_PROC_NET_DEV", paths["netdev"])
    monkeypatch.setattr(sysmetrics, "_PROC_MEMINFO", paths["meminfo"])
    monkeypatch.setattr(sysmetrics, "_PROC_ROUTE", paths["route"])

    thermal = tmp_path / "thermal"
    if temp is not None:
        (thermal / "thermal_zone0").mkdir(parents=True)
        (thermal / "thermal_zone0" / "temp").write_text(temp)
    monkeypatch.setattr(sysmetrics, "_THERMAL", thermal)

    hnat_path = tmp_path / "hnat_entry"
    if hnat is not None:
        hnat_path.write_text(hnat)
    monkeypatch.setattr(sysmetrics, "_HNAT_ENTRY", hnat_path)
    return paths


# `/proc/net/route` as the kernel writes it: iface, dest, gateway, flags...
_ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "br-lan\t0008A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
    "eth1\t00000000\t0164A8C0\t0003\t0\t0\t0\t00000000\n"
)
_MEMINFO = "MemTotal:        1013116 kB\nMemFree:  100 kB\nMemAvailable:     645724 kB\n"


def _stat(total_busy: int, idle: int) -> str:
    # user nice system idle iowait irq softirq steal
    return f"cpu  {total_busy} 0 0 {idle} 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8\n"


def _netdev(rx: int, tx: int, dev: str = "eth1") -> str:
    return (
        "Inter-|   Receive                    |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes\n"
        f"    {dev}: {rx} 1 0 0 0 0 0 0 {tx} 1 0 0 0 0 0 0\n"
    )


def test_first_sample_has_no_rates(tmp_path, monkeypatch):
    """No baseline yet. None, not 0 — a fake zero on the first tick draws a
    dip in the chart that never happened."""
    _fake_fs(tmp_path, monkeypatch, stat=_stat(100, 900), netdev=_netdev(1000, 500), route=_ROUTE)
    s = sysmetrics.SystemMetrics()
    f = s.sample(mono_now=10.0)
    assert f["cpu_percent"] is None
    assert f["wan_down_rate"] is None
    assert f["wan_up_rate"] is None
    assert f["wan_device"] == "eth1"


def test_rates_and_cpu_from_two_samples(tmp_path, monkeypatch):
    paths = _fake_fs(
        tmp_path,
        monkeypatch,
        stat=_stat(100, 900),
        netdev=_netdev(1000, 500),
        route=_ROUTE,
        meminfo=_MEMINFO,
        temp="58626\n",
    )
    s = sysmetrics.SystemMetrics()
    s.sample(mono_now=10.0)

    # +100 busy jiffies, +100 idle over the interval -> 50% busy.
    paths["stat"].write_text(_stat(200, 1000))
    paths["netdev"].write_text(_netdev(1000 + 2_000_000, 500 + 500_000))
    f = s.sample(mono_now=12.0)  # 2 seconds later

    assert f["cpu_percent"] == 50.0
    assert f["wan_down_rate"] == 1_000_000.0  # 2 MB over 2 s
    assert f["wan_up_rate"] == 250_000.0
    assert f["mem_total"] == 1013116 * 1024
    assert f["mem_available"] == 645724 * 1024
    assert f["temp_c"] == 58.626


def test_a_counter_reset_is_skipped_not_reported_as_a_spike(tmp_path, monkeypatch):
    """An interface reset makes the delta negative; reporting it as a huge or
    negative rate puts a spike in the chart that never happened."""
    paths = _fake_fs(
        tmp_path,
        monkeypatch,
        stat=_stat(100, 900),
        netdev=_netdev(9_000_000, 9_000_000),
        route=_ROUTE,
    )
    s = sysmetrics.SystemMetrics()
    s.sample(mono_now=10.0)
    paths["netdev"].write_text(_netdev(10, 10))  # counters wrapped / reset
    f = s.sample(mono_now=11.0)
    assert f["wan_down_rate"] is None
    assert f["wan_up_rate"] is None


def test_a_router_without_these_files_reports_none_and_does_not_raise(tmp_path, monkeypatch):
    """Every field is optional. A target with no thermal zone, no PPE debugfs
    and no readable /proc must still produce a frame — the dashboard degrades,
    it does not break."""
    _fake_fs(tmp_path, monkeypatch, stat=None, netdev=None, route=None)
    f = sysmetrics.SystemMetrics().sample(mono_now=1.0)
    assert f == {
        "cpu_percent": None,
        "wan_device": None,
        "wan_down_rate": None,
        "wan_up_rate": None,
        "mem_total": None,
        "mem_available": None,
        "temp_c": None,
        "offload_bound": None,
    }


def test_offload_is_read_when_the_target_has_a_ppe(tmp_path, monkeypatch):
    """Nonzero only for traffic that never reaches the proxy. It is the
    difference between forwarding at line rate for free and paying CPU per
    packet — measured 4% vs 42% on the Flint 2 for the same download."""
    _fake_fs(
        tmp_path,
        monkeypatch,
        stat=_stat(1, 1),
        netdev=_netdev(1, 1),
        route=_ROUTE,
        hnat="Total State = BIND cnt = 21\n",
    )
    assert sysmetrics.SystemMetrics().sample(mono_now=1.0)["offload_bound"] == 21


def test_the_uplink_is_re_read_every_sample(tmp_path, monkeypatch):
    """A WAN failover or PPPoE reconnect renames the uplink. Caching it means
    the throughput chart silently reads zero forever afterwards."""
    paths = _fake_fs(
        tmp_path, monkeypatch, stat=_stat(1, 1), netdev=_netdev(1, 1, dev="eth1"), route=_ROUTE
    )
    s = sysmetrics.SystemMetrics()
    assert s.sample(mono_now=1.0)["wan_device"] == "eth1"
    paths["route"].write_text(_ROUTE.replace("eth1", "wwan0"))
    assert s.sample(mono_now=2.0)["wan_device"] == "wwan0"


def test_default_route_device_requires_the_gateway_flag(tmp_path, monkeypatch):
    """Destination 00000000 alone is not enough — an on-link route to it has
    the same destination and would name the wrong interface, which reads as a
    permanently idle link."""
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\n"
        "lo\t00000000\t00000000\t0001\n"  # UP but not GATEWAY
        "eth1\t00000000\t0164A8C0\t0003\n"  # UP | GATEWAY
    )
    monkeypatch.setattr(sysmetrics, "_PROC_ROUTE", route)
    assert sysmetrics.default_route_device() == "eth1"


_ROUTE_B = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "br-lan\t0008A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
    "wan_b\t00000000\t0164A8C0\t0003\t0\t0\t0\t00000000\n"
)


def test_wan_failover_does_not_invent_a_throughput_spike(tmp_path, monkeypatch):
    """The device name and the byte counters are a pair.

    Only the name was refreshed each tick, so after a failover the new device's
    counters were deltaed against the old device's — and the `d_rx >= 0` guard
    only catches the new ones being *lower*. Measured across a wan_a → wan_b
    switch between two 1 s ticks: 899,999,000 B/s, which also lands in the
    30-sample history the dashboard reads its peak from.
    """
    paths = _fake_fs(
        tmp_path,
        monkeypatch,
        stat=_stat(100, 900),
        netdev=_netdev(1_000_000, 500, dev="eth1"),
        route=_ROUTE,
        meminfo=_MEMINFO,
    )
    s = sysmetrics.SystemMetrics()
    s.sample(mono_now=10.0)  # baseline on eth1

    # Failover: a different device carries the default route, and its counters
    # are unrelated to (here, far above) the old one's.
    paths["route"].write_text(_ROUTE_B)
    paths["netdev"].write_text(_netdev(900_000_000, 400_000_000, dev="wan_b"))
    f = s.sample(mono_now=11.0)

    assert f["wan_device"] == "wan_b"
    assert f["wan_down_rate"] is None, "no rate may be derived across two devices"
    assert f["wan_up_rate"] is None

    # ...and the next tick, both now on wan_b, is a normal reading again.
    paths["netdev"].write_text(_netdev(900_002_000, 400_000_500, dev="wan_b"))
    f2 = s.sample(mono_now=12.0)
    assert f2["wan_down_rate"] == 2000.0
