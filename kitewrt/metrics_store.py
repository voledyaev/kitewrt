"""In-process metrics cache + rolling history.

Two purposes:
- Compute throughput rates **server-side** from successive Clash
  `download_total` / `upload_total` deltas, so clients don't each have to
  build up rate samples from scratch after every page reload.
- Hold a small rolling buffer of recent samples (~30 seconds) so a fresh
  WS connection can render its sparkline + throughput numbers
  immediately, without the 30-second warm-up the UI used to need.

The store is updated by `kitewrt.api._metrics_pump` on every tick (~1/s
while the VPN is on). `latest_frame()` is what the WebSocket handler
sends to newly-connected clients as a priming frame.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

# How many seconds of rate history to keep. The UI sparkline width is
# small; 30 seconds at ~1 sample/s is plenty without bloating the WS
# payload (each sample is two floats + a timestamp).
HISTORY_LIMIT = 30


class MetricsStore:
    """Latest metrics + rolling history. Single-instance per process.

    `update(raw, now_tag)` takes a Clash `/connections` payload plus the
    selector's current outbound tag, computes deltas against the previous
    totals to derive rates, appends the new sample, and returns the
    complete frame to publish (same shape the WS sends).

    Thread-safety: not needed. The pump runs in one asyncio task and the
    WS handlers only read via `latest_frame()`, which is a cheap dict
    copy.
    """

    def __init__(self) -> None:
        self._latest: dict[str, Any] | None = None
        self._history: deque[dict[str, Any]] = deque(maxlen=HISTORY_LIMIT)
        # Previous totals + monotonic timestamp, for delta calc. None on
        # first tick (we just record the totals; the first published frame
        # has zero rates).
        self._prev_total_down: int | None = None
        self._prev_total_up: int | None = None
        self._prev_mono: float | None = None

    def update(
        self, summary_no_rates: dict[str, Any], mono_now: float | None = None
    ) -> dict[str, Any]:
        """Wrap a `build_metrics_summary` output with computed rates +
        history and stash for later WS priming.

        `summary_no_rates` is the dict from `build_metrics_summary`. It
        carries totals (`download_total`, `upload_total`) which we delta
        against the previous tick. `mono_now` is `time.monotonic()` at
        sample time (parameterised so tests can drive it deterministically);
        defaults to the real monotonic clock.
        """
        mono_now = mono_now if mono_now is not None else time.monotonic()
        down_total = int(summary_no_rates.get("download_total", 0))
        up_total = int(summary_no_rates.get("upload_total", 0))

        if (
            self._prev_total_down is not None
            and self._prev_total_up is not None
            and self._prev_mono is not None
        ):
            dt = max(mono_now - self._prev_mono, 1e-3)  # guard div-by-zero
            # Counters reset (sing-box restart) → negative delta → clamp to 0.
            down_rate = max(0.0, (down_total - self._prev_total_down) / dt)
            up_rate = max(0.0, (up_total - self._prev_total_up) / dt)
        else:
            down_rate = 0.0
            up_rate = 0.0

        self._prev_total_down = down_total
        self._prev_total_up = up_total
        self._prev_mono = mono_now

        # Each sample also carries memory + connection count so the UI can
        # plot those over time (not just throughput) without a second buffer.
        sample = {
            "down_rate": down_rate,
            "up_rate": up_rate,
            "memory": int(summary_no_rates.get("memory", 0)),
            "connections": int(summary_no_rates.get("connections", 0)),
        }
        self._history.append(sample)

        frame = {
            **summary_no_rates,
            "down_rate": down_rate,
            "up_rate": up_rate,
            "history": list(self._history),
        }
        self._latest = frame
        return frame

    def mark_unavailable(self) -> dict[str, Any]:
        """Record an `available: False` frame (e.g. VPN off, Clash
        unreachable). Clears the prev-totals so the next available tick
        starts fresh (no spike from a stale baseline). History is
        preserved — the sparkline stays put rather than flashing empty."""
        self._prev_total_down = None
        self._prev_total_up = None
        self._prev_mono = None
        frame = {"available": False, "history": list(self._history)}
        self._latest = frame
        return frame

    def latest_frame(self) -> dict[str, Any] | None:
        """The most recent published frame (whatever was returned from
        `update` / `mark_unavailable`), or None if nothing has been pushed
        yet (VPN never turned on this session). Cheap to call — caller
        will wrap it in a WS message and send."""
        return self._latest
