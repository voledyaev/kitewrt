"""Tests for the server-side metrics cache + rolling history
(kitewrt.metrics_store)."""

from __future__ import annotations

from kitewrt.metrics_store import HISTORY_LIMIT, MetricsStore


def _summary(down=0, up=0, conns=0, **extra):
    """Minimal `build_metrics_summary`-shaped dict for tests."""
    return {
        "available": True,
        "now": "tag",
        "download_total": down,
        "upload_total": up,
        "connections": conns,
        "proxied": 0,
        "direct": 0,
        "memory": 0,
        "top": [],
        **extra,
    }


def test_first_update_has_zero_rates():
    """No prior totals to delta against — rates must be 0, not undefined."""
    s = MetricsStore()
    frame = s.update(_summary(down=1000, up=500), mono_now=10.0)
    assert frame["down_rate"] == 0.0
    assert frame["up_rate"] == 0.0
    assert frame["history"] == [{"down_rate": 0.0, "up_rate": 0.0, "memory": 0, "connections": 0}]


def test_rate_computed_from_delta_and_dt():
    s = MetricsStore()
    s.update(_summary(down=1000, up=500), mono_now=10.0)
    f = s.update(_summary(down=11000, up=2500), mono_now=11.0)  # +10000 down / 1s, +2000 up / 1s
    assert f["down_rate"] == 10000.0
    assert f["up_rate"] == 2000.0


def test_rate_clamps_to_zero_on_counter_reset():
    """sing-box restart resets the totals; a backwards delta must not yield
    a negative rate (would make the sparkline glitch)."""
    s = MetricsStore()
    s.update(_summary(down=10_000_000, up=5_000_000), mono_now=10.0)
    f = s.update(_summary(down=0, up=0), mono_now=11.0)
    assert f["down_rate"] == 0.0
    assert f["up_rate"] == 0.0


def test_history_grows_then_caps_at_limit():
    s = MetricsStore()
    for i in range(HISTORY_LIMIT + 5):
        s.update(_summary(down=i * 1000), mono_now=float(i))
    frame = s.latest_frame()
    assert len(frame["history"]) == HISTORY_LIMIT


def test_latest_frame_none_until_first_update():
    s = MetricsStore()
    assert s.latest_frame() is None


def test_mark_unavailable_resets_prev_totals():
    """After VPN goes off and comes back on, the next available tick must
    not delta against the pre-off totals (would yield a huge bogus rate)."""
    s = MetricsStore()
    s.update(_summary(down=10_000), mono_now=10.0)
    s.mark_unavailable()
    f = s.update(_summary(down=15_000), mono_now=12.0)  # 5000 / 2s == 2500 IF delta'd
    # No prev totals after mark_unavailable → first tick after re-availability
    # is treated like a fresh start, rates are zero.
    assert f["down_rate"] == 0.0


def test_mark_unavailable_preserves_history():
    """A transient WS reconnect shouldn't blank the sparkline."""
    s = MetricsStore()
    s.update(_summary(down=1000), mono_now=10.0)
    s.update(_summary(down=2000), mono_now=11.0)
    h_before = list(s.latest_frame()["history"])
    frame = s.mark_unavailable()
    assert frame["available"] is False
    assert frame["history"] == h_before


def test_latest_frame_carries_history():
    s = MetricsStore()
    s.update(_summary(down=1000), mono_now=10.0)
    s.update(_summary(down=2500), mono_now=11.0)
    latest = s.latest_frame()
    assert latest["down_rate"] == 1500.0
    assert len(latest["history"]) == 2
