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


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s kitewrtd %(name)s %(levelname)s %(message)s",
    )

    listen = os.environ.get("KITEWRT_LISTEN") or "0.0.0.0:8088"
    host, _, port_s = listen.rpartition(":")
    host = host or "0.0.0.0"
    port = int(port_s)

    logging.getLogger("kitewrt").info("listening on http://%s:%s/", host, port)

    # Lifespan in kitewrt.api handles everything else: builds State, ApplyPipeline,
    # the sing-box data plane, Watchdog, the httpx fetcher; tears them down cleanly
    # when uvicorn signals shutdown (SIGINT/SIGTERM).
    uvicorn.run(
        create_app(),
        host=host,
        port=port,
        log_level="info",
        access_log=False,
    )


if __name__ == "__main__":
    main()
