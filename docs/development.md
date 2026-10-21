# Development

```sh
git clone https://github.com/voledyaev/kitewrt.git
cd kitewrt
uv sync --extra installer            # dev group is synced by default
uv run pytest                        # a few seconds
uv run ruff check .
uv run kitewrt --probe root@192.168.8.1   # connectivity + state check, no changes
```

## The web UI

The web UI is a React + Vite SPA under `web/`. Its build output is committed to
`kitewrt/static/` so the router install needs no Node — but if you change the
UI, rebuild and commit the result (CI fails if it's stale):

```sh
cd web
npm install
npm run test           # vitest — health.ts and format.ts
npm run build          # → ../kitewrt/static/
npm run dev            # HMR dev server, proxies /api + /ws to a running daemon
```

## CI

CI runs `ruff check`, `ruff format --check` and pytest across Python 3.9–3.12
(3.9 is the floor because that's what OpenWrt 21.02 ships), validates the
generated sing-box configs against the pinned real binary, and rebuilds the SPA
to check the committed bundle hasn't drifted.

Release tags use the same locked uv environment, including the installer extra
and the dev dependency group. The wheel resource check verifies that the guard
script and all bundled UI assets ship in a non-editable installation.

## Screenshots

Published screenshots must use synthetic data: example domains, documentation
IP ranges and invented subscriptions, devices and traffic. Never capture a live
router or reuse its state as a fixture. The previous screenshot harness was
removed; there is currently no `web/mock/` directory. Before making new images,
create a local fixture harness for the required API and WebSocket responses and
verify that it makes no requests to a real router.

## Running the daemon without a router

```sh
KITEWRT_BASE_DIR=/tmp/kitewrt-dev KITEWRT_LISTEN=127.0.0.1:8088 uv run python -m kitewrt
```

It will have no sing-box to drive and no capture to install, but the UI, the
state store and the API are all exercised.

## Project layout

```
kitewrt/         # the daemon package (FastAPI, asyncio, Pydantic)
  singbox/      #   sing-box config builder, Clash API client, service control
  static/       #   built web UI (generated from web/ — do not hand-edit)
web/            # web UI source (React + Vite + Tailwind + daisyUI)
installer/     # the Mac/Linux-side installer (asyncssh)
tests/          # unit tests
docs/           # OpenWrt notes, VLESS / rules formats, measured facts
```

Design rationale lives in [ARCHITECTURE.md](../ARCHITECTURE.md); the platform
facts that keep biting are in [docs/openwrt-notes.md](./openwrt-notes.md); the
open queue is [docs/measured-facts.md](./measured-facts.md).
