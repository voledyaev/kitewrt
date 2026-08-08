"""The daemon's uvicorn wiring.

Small, but this is where a missing keyword costs the whole shutdown: uvicorn
waits for in-flight requests *without a deadline* before it runs the lifespan,
and the lifespan is what removes the LAN capture.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

from kitewrt import __main__ as entry


def test_uvicorn_gets_a_graceful_shutdown_deadline(monkeypatch):
    """Without `timeout_graceful_shutdown`, uvicorn's `Server.shutdown()`
    awaits every in-flight task with `timeout=None`. One `POST
    /api/subscriptions` against an unroutable host holds a 30 s fetch — longer
    than procd's `term_timeout`, so the process is SIGKILLed with "Waiting for
    connections to close" as its last log line and the lifespan never runs at
    all. The LAN capture is then still hooked when procd stops sing-box right
    after us. Every bound inside the lifespan is downstream of this one.
    """
    monkeypatch.setenv("KITEWRT_LISTEN", "127.0.0.1:8088")
    with patch.object(entry, "uvicorn") as uv, patch.object(entry, "create_app"):
        entry.main()
    kwargs = uv.run.call_args.kwargs
    assert kwargs["timeout_graceful_shutdown"] == entry.SHUTDOWN_DRAIN_S
    assert 0 < entry.SHUTDOWN_DRAIN_S <= 5, "must leave room for the lifespan inside term_timeout"


def test_httpx_request_logging_is_quiet_enough_to_debug_over(monkeypatch):
    """httpx's per-request INFO line is emitted 1.80x/s with the VPN on (the
    metrics pump hits the Clash API twice a tick, measured over 10 s). OpenWrt's
    `logd -S 64` ring holds ~495 lines of that shape, so left at INFO it evicts
    the actual error in under five minutes — which is how a debugging session
    loses the one line that mattered.
    """
    monkeypatch.setenv("KITEWRT_LISTEN", "127.0.0.1:8088")
    logging.getLogger("httpx").setLevel(logging.NOTSET)
    with patch.object(entry, "uvicorn"), patch.object(entry, "create_app"):
        entry.main()
    # The explicit level, not `isEnabledFor`: pytest's logging plugin has
    # already put handlers on the root logger, which makes `basicConfig` a
    # no-op, so an inherited-level assertion would pass without the fix.
    assert logging.getLogger("httpx").level == logging.WARNING
    # WARNING, not ERROR/CRITICAL: a genuine httpx complaint must still land.
    # And the daemon's own loggers stay on the root's INFO — that is what
    # `logread` shows and what the router is actually debugged from.
    assert logging.getLogger("kitewrt").level == logging.NOTSET
