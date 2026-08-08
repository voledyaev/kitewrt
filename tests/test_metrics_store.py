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
    assert frame["history"] == [
        {
            "down_rate": 0.0,
            "up_rate": 0.0,
            "connections": 0,
            # Router-level; None until SystemMetrics has a baseline. sing-box's
            # own RSS used to live here and drove a whole chart — it never
            # moved off ~60 MB under any load, so it was dropped for the
            # numbers that do move.
            "cpu_percent": None,
            "wan_down_rate": None,
            "wan_up_rate": None,
        }
    ]


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


def test_frames_carry_the_capture_observation():
    """ "The VPN is on" and "traffic is being captured" are different facts, and
    the gap between them is where every silent leak in this project has lived.
    The watchdog is the only thing that probes it, so it rides along here rather
    than being re-probed once a second (a fork, competing for the xtables lock).
    """
    from kitewrt.metrics_store import MetricsStore

    store = MetricsStore()
    # Never observed yet reads as unknown, not as "no capture".
    assert store.mark_unavailable({})["capture"] is None

    store.set_capture(False)
    assert store.mark_unavailable({})["capture"] is False
    frame = store.update({"connections": 0, "download_total": 0, "upload_total": 0}, system={})
    assert frame["capture"] is False

    store.set_capture(True)
    assert store.mark_unavailable({})["capture"] is True


def test_capture_age_lets_the_ui_spot_a_stale_reading():
    """A reading is only worth something if you know how old it is.

    The watchdog observes it every 30 s, and the browser can keep the last
    frame long after the socket dropped — so a "captured" claim can outlive the
    thing it describes. Publishing the age is what lets the UI degrade it to
    "unverified" rather than keep a green headline alive on it.
    """
    from kitewrt.metrics_store import MetricsStore

    store = MetricsStore()
    assert store.mark_unavailable({})["capture_age_s"] is None  # never observed

    store.set_capture(True)
    age = store.mark_unavailable({})["capture_age_s"]
    assert age is not None and age < 1.0  # fresh
