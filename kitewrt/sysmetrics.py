"""Router-level health: CPU, WAN throughput, memory, temperature, offload.

**Why this exists.** Everything else on the dashboard comes from sing-box's
Clash API, which by construction only sees traffic that reaches sing-box. Once
`bypass_address` returns traffic to the kernel before the capture — which is
the whole point of it, and what keeps the hardware fast path alive — that
traffic is invisible to the daemon. Measured on a live GL-MT6000 during a
bypassed download: 512.5 MB crossed the WAN, the Clash totals moved 1.5 MB. A
"Download" chart fed from Clash was reporting 0.3% of the truth.

So the honest throughput number has to come from the kernel's own interface
counters, and the metric that actually tells a user whether their routing
config is healthy is the router's CPU — a bypassed download runs at ~4%, the
same download through sing-box at ~40%.

Everything here is a plain read of `/proc` or `/sys`: no packages, no polling
daemon, and nothing that can fail loudly. Every field is optional; a router
that doesn't expose one just reports None for it rather than breaking the
frame.
"""

from __future__ import annotations

import contextlib
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PROC_STAT = Path("/proc/stat")
_PROC_NET_DEV = Path("/proc/net/dev")
_PROC_MEMINFO = Path("/proc/meminfo")
_PROC_ROUTE = Path("/proc/net/route")
# MediaTek's PPE (and the mtkhnat debugfs it exposes). Present on the Flint 2,
# absent on x86 and most other targets — hence best-effort.
_HNAT_ENTRY = Path("/sys/kernel/debug/hnat/hnat_entry")
_THERMAL = Path("/sys/class/thermal")


def _read(path: Path) -> str | None:
    """File contents, or None if it isn't there / can't be read.

    None rather than "" on purpose: an empty read and a failed read mean
    different things to every caller here, and conflating them is the bug that
    cost this project two P0s in `divert.py`.
    """
    try:
        return path.read_text()
    except OSError:
        return None


def default_route_device() -> str | None:
    """The uplink interface name, read from the kernel routing table.

    `/proc/net/route` rather than shelling out to `ip`: this runs once a
    second, and a fork per tick on an A53 is a real cost for a string we can
    read directly. Destination 00000000 with the UP+GATEWAY flags is the
    default route.
    """
    raw = _read(_PROC_ROUTE)
    if raw is None:
        return None
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) > 3 and parts[1] == "00000000":
            with contextlib.suppress(ValueError):
                if int(parts[3], 16) & 0x2:  # RTF_GATEWAY
                    return parts[0]
    return None


def _cpu_totals() -> tuple[int, int] | None:
    """(busy+idle, idle) jiffies from /proc/stat's aggregate `cpu` line."""
    raw = _read(_PROC_STAT)
    if raw is None:
        return None
    for line in raw.splitlines():
        if line.startswith("cpu "):
            try:
                f = [int(x) for x in line.split()[1:]]
            except ValueError:
                return None
            if len(f) < 5:
                return None
            idle = f[3] + f[4]  # idle + iowait
            return sum(f), idle
    return None


def _iface_bytes(dev: str) -> tuple[int, int] | None:
    """(rx, tx) byte counters for `dev` from /proc/net/dev."""
    raw = _read(_PROC_NET_DEV)
    if raw is None:
        return None
    for line in raw.splitlines():
        name, _, rest = line.partition(":")
        if name.strip() != dev:
            continue
        f = rest.split()
        if len(f) < 9:
            return None
        with contextlib.suppress(ValueError):
            return int(f[0]), int(f[8])
    return None


def _memory() -> tuple[int, int] | None:
    """(total, available) bytes."""
    raw = _read(_PROC_MEMINFO)
    if raw is None:
        return None
    vals: dict[str, int] = {}
    for line in raw.splitlines():
        key, _, rest = line.partition(":")
        if key in ("MemTotal", "MemAvailable"):
            with contextlib.suppress(ValueError, IndexError):
                vals[key] = int(rest.split()[0]) * 1024
    if "MemTotal" not in vals or "MemAvailable" not in vals:
        return None
    return vals["MemTotal"], vals["MemAvailable"]


def _temperature_c() -> float | None:
    """Hottest thermal zone in °C, or None where the target has no sensors."""
    try:
        zones = sorted(_THERMAL.glob("thermal_zone*/temp"))
    except OSError:
        return None
    best: float | None = None
    for z in zones:
        raw = _read(z)
        if raw is None:
            continue
        with contextlib.suppress(ValueError):
            # Kernel reports millidegrees; a few targets report degrees.
            v = int(raw.strip())
            c = v / 1000.0 if abs(v) > 1000 else float(v)
            if -50 < c < 150 and (best is None or c > best):
                best = c
    return best


def _offload_bound() -> int | None:
    """Flows currently bound to the hardware flow offload, or None if the
    target has no PPE (or debugfs isn't mounted).

    This is the difference between "the router is forwarding at line rate for
    free" and "every packet costs CPU". Nonzero only for traffic that never
    reaches the proxy — see `kitewrt.divert` on why anything sing-box
    terminates leaves netfilter's forward chain for good.
    """
    raw = _read(_HNAT_ENTRY)
    if raw is None:
        return None
    marker = "BIND cnt = "
    idx = raw.find(marker)
    if idx < 0:
        return None
    tail = raw[idx + len(marker) :].split()
    if not tail:
        return None
    try:
        return int(tail[0])
    except ValueError:
        return None


class SystemMetrics:
    """Samples router health. Holds the previous counters to derive rates.

    One instance per process, driven by the metrics pump. `sample()` never
    raises and never blocks on anything but a `/proc` read.
    """

    def __init__(self) -> None:
        self._prev_cpu: tuple[int, int] | None = None
        self._prev_net: tuple[int, int] | None = None
        self._prev_mono: float | None = None
        self._wan: str | None = None

    def sample(self, mono_now: float | None = None) -> dict[str, Any]:
        """One reading. Rates are None on the first call (no baseline yet) and
        whenever a counter goes backwards (interface reset)."""
        mono_now = mono_now if mono_now is not None else time.monotonic()
        dt = None if self._prev_mono is None else max(mono_now - self._prev_mono, 1e-3)

        cpu_percent = None
        cpu = _cpu_totals()
        if cpu is not None and self._prev_cpu is not None:
            d_total = cpu[0] - self._prev_cpu[0]
            d_idle = cpu[1] - self._prev_cpu[1]
            if d_total > 0:
                cpu_percent = max(0.0, min(100.0, 100.0 * (d_total - d_idle) / d_total))
        self._prev_cpu = cpu

        # Re-read the uplink every tick: it changes on a WAN failover or a
        # PPPoE reconnect, and a stale name silently reports zero forever.
        #
        # The device name and the byte counters are a pair — refreshing one
        # without the other deltas the new device's counters against the old
        # device's, and the `d_rx >= 0` guard below only catches the new
        # counters being *lower*. Measured across a wan_a → wan_b switch
        # between two 1 s ticks: 899,999,000 B/s reported as wan_down_rate,
        # which also lands in the 30-sample history the dashboard peaks off.
        wan = default_route_device()
        if wan != self._wan:
            self._prev_net = None
        self._wan = wan
        down_rate = up_rate = None
        net = _iface_bytes(self._wan) if self._wan else None
        if net is not None and self._prev_net is not None and dt is not None:
            d_rx = net[0] - self._prev_net[0]
            d_tx = net[1] - self._prev_net[1]
            if d_rx >= 0 and d_tx >= 0:  # counter reset → skip this sample
                down_rate = d_rx / dt
                up_rate = d_tx / dt
        self._prev_net = net
        self._prev_mono = mono_now

        mem = _memory()
        return {
            "cpu_percent": cpu_percent,
            "wan_device": self._wan,
            "wan_down_rate": down_rate,
            "wan_up_rate": up_rate,
            "mem_total": mem[0] if mem else None,
            "mem_available": mem[1] if mem else None,
            "temp_c": _temperature_c(),
            "offload_bound": _offload_bound(),
        }
