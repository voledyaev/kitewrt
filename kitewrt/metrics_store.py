"""In-process metrics cache + rolling history.

Two purposes:
- Compute throughput rates **server-side** from successive Clash
  `download_total` / `upload_total` deltas, so clients don't each have to
  build up rate samples from scratch after every page reload.
- Hold a small rolling buffer of recent samples (~30 seconds) so a fresh
  WS connection can render its numbers immediately, without the 30-second
  warm-up the UI used to need. The dashboard no longer plots this buffer —
  the charts were removed — it reduces it to the "peak · 30s" figure under
  each current-value tile.

The store is updated by `kitewrt.api._metrics_pump` on every tick, ~1/s,
**whether or not the VPN is on**: with it off the pump calls
`mark_unavailable`, which still carries the router's own CPU/WAN/temperature
sample and still appends to history. `latest_frame()` is what the WebSocket
handler sends to newly-connected clients as a priming frame.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

# How many seconds of rate history to keep. 30 seconds at ~1 sample/s is what
# the dashboard's "peak · 30s" figures are computed over, and it is small enough
# not to bloat the WS payload: six numeric fields per sample (see `update`),
# with no timestamp — position in the deque is the only ordering there is, which
# is why a dropped tick shifts the window rather than leaving a gap.
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
        # Whether the LAN capture is actually installed: True / False / None
        # for "could not determine". Written by the watchdog, which is already
        # the only thing that probes it, so this costs no extra forks. It rides
        # in every frame because "the VPN is on" and "traffic is being
        # captured" are different facts, and the difference is the entire
        # failure class this project keeps finding: a firewall restart flushes
        # the capture and the LAN egresses in the clear while the UI says
        # Connected.
        self._capture: bool | None = None
        # When that observation was taken. Published as an age so the UI can
        # tell a fresh reading from one the watchdog took before it stopped
        # ticking — a stale "captured" is exactly the false reassurance this
        # field was added to remove.
        self._capture_at: float | None = None

    def update(
        self,
        summary_no_rates: dict[str, Any],
        mono_now: float | None = None,
        system: dict[str, Any] | None = None,
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

        # Each sample also carries the connection count and the router-level
        # numbers, so the UI can peak over all of them from one buffer.
        system = system or {}
        sample = {
            "down_rate": down_rate,
            "up_rate": up_rate,
            "connections": int(summary_no_rates.get("connections", 0)),
            # Router-level, and the reason the WAN figures are trustworthy: the
            # rates above only cover traffic that reached sing-box, which after
            # `bypass_address` can be a tiny fraction of the link.
            "cpu_percent": system.get("cpu_percent"),
            "wan_down_rate": system.get("wan_down_rate"),
            "wan_up_rate": system.get("wan_up_rate"),
        }
        self._history.append(sample)

        frame = {
            **summary_no_rates,
            **system,
            "capture": self._capture,
            "capture_age_s": self._capture_age_s(),
            "down_rate": down_rate,
            "up_rate": up_rate,
            "history": list(self._history),
        }
        self._latest = frame
        return frame

    def mark_unavailable(self, system: dict[str, Any] | None = None) -> dict[str, Any]:
        """Record an `available: False` frame (e.g. VPN off, Clash
        unreachable). Clears the prev-totals so the next available tick
        starts fresh (no spike from a stale baseline). History is
        preserved — the 30 s peaks stay put rather than flashing empty.

        `system` is still carried and still appended to history: the router's
        CPU, WAN throughput and temperature are exactly as real with the VPN
        off, and blanking them would make the health panel flicker on every
        toggle."""
        self._prev_total_down = None
        self._prev_total_up = None
        self._prev_mono = None
        system = system or {}
        if system:
            self._history.append(
                {
                    "down_rate": 0.0,
                    "up_rate": 0.0,
                    "connections": 0,
                    "cpu_percent": system.get("cpu_percent"),
                    "wan_down_rate": system.get("wan_down_rate"),
                    "wan_up_rate": system.get("wan_up_rate"),
                }
            )
        frame = {
            "available": False,
            "capture": self._capture,
            "capture_age_s": self._capture_age_s(),
            **system,
            "history": list(self._history),
        }
        self._latest = frame
        return frame

    def set_capture(self, state: bool | None) -> None:
        """Record what the watchdog last saw. Deliberately not probed here:
        the pump runs every second and the probe is a fork that takes the
        xtables lock."""
        self._capture = state
        self._capture_at = time.monotonic()

    def _capture_age_s(self) -> float | None:
        """Seconds since the observation, or None if there has never been one."""
        if self._capture_at is None:
            return None
        return max(0.0, time.monotonic() - self._capture_at)

    def latest_frame(self) -> dict[str, Any] | None:
        """The most recent published frame (whatever was returned from
        `update` / `mark_unavailable`), or None if nothing has been pushed
        yet (VPN never turned on this session). Cheap to call — caller
        will wrap it in a WS message and send."""
        return self._latest
