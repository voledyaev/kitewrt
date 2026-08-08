"""Entry point for the kitewrt daemon.

Just reads the listen address from the environment and hands off to
uvicorn. All other configuration (state dir, sing-box config path, Clash
API URL) is read by the FastAPI lifespan in `kitewrt.api`, so that test
code can build the same app without touching the environment.

Environment variables (set by the installer's init script):

    KITEWRT_BASE_DIR        absolute path for per-router data (state.json).
                           Required; refuses to guess.
    KITEWRT_LISTEN          listen address, default "0.0.0.0:8088".
    KITEWRT_SINGBOX_CONFIG  sing-box config.json path written on apply.
    KITEWRT_CLASH_API       Clash API base URL for live server switching,
                           default http://127.0.0.1:9090.
"""

from __future__ import annotations

import logging
import os

import uvicorn

from kitewrt.api import create_app

# How long uvicorn may drain in-flight requests before the lifespan teardown
# runs. The teardown then gets its own budget (see kitewrt.api), and the two
# together have to fit inside the init script's `term_timeout 20`.
SHUTDOWN_DRAIN_S = 3

# httpx logs one INFO line per request, and the daemon polls constantly: the
# metrics pump calls the Clash API twice a tick, measured at **1.80 lines/s**
# over 10 s with the VPN on. That is not a log, it is a treadmill — the router's
# ring is tiny. OpenWrt runs `logd -S 64` (64 KiB), which measured out at ~495
# lines of this shape on the lab VM, so httpx alone scrolls the whole ring in
# under five minutes and takes the error you were reading with it. It
# measurably slowed the clean-room agent's diagnosis of the `ip-full` blocker.
#
# httpx is the only one that needs this. Measured across a driven session (30
# API polls + a live WS client + pushed frames) it was the sole third-party
# logger to emit a record at all: httpcore has no INFO call site, uvicorn's
# access log is already off (`access_log=False` below), and websockets logged
# nothing. WARNING keeps httpx's real complaints.
_CHATTY_LOGGERS = ("httpx",)


def quiet_chatty_third_party_loggers() -> None:
    for name in _CHATTY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s kitewrtd %(name)s %(levelname)s %(message)s",
    )
    quiet_chatty_third_party_loggers()

    listen = os.environ.get("KITEWRT_LISTEN") or "0.0.0.0:8088"
    host, _, port_s = listen.rpartition(":")
    host = host or "0.0.0.0"
    port = int(port_s)

    logging.getLogger("kitewrt").info("listening on http://%s:%s/", host, port)

    # Lifespan in kitewrt.api handles everything else: builds State, ApplyPipeline,
    # the sing-box data plane, Watchdog, the httpx fetcher; tears them down cleanly
    # when uvicorn signals shutdown (SIGINT/SIGTERM).
    #
    # `timeout_graceful_shutdown` is load-bearing, not tidiness. Without it
    # uvicorn waits for every in-flight request *without a deadline* before it
    # runs the lifespan's shutdown — and one `POST /api/subscriptions` against
    # an unroutable host holds a 30 s fetch. Measured: procd SIGKILLed the
    # daemon at term_timeout with "Waiting for connections to close" as the
    # last log line, so the lifespan never ran at all and the LAN capture was
    # still hooked when sing-box stopped after us. Every bound inside the
    # lifespan is downstream of this one.
    uvicorn.run(
        create_app(),
        host=host,
        port=port,
        log_level="info",
        access_log=False,
        timeout_graceful_shutdown=SHUTDOWN_DRAIN_S,
    )


if __name__ == "__main__":
    main()
