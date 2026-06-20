# KiteWrt web UI

React + Vite + Tailwind/daisyUI SPA for the KiteWrt daemon.

- `npm install` — install deps
- `npm run dev` — dev server with HMR; proxies `/api` and `/ws` to the daemon at `127.0.0.1:8088`
- `npm run build` — build into `../kitewrt/static/` (the daemon serves it)
- `npm run lint` — ESLint

The build output in `kitewrt/static/` is **committed** so the OpenWrt router
install needs no Node. CI rebuilds and fails if the committed output drifts from
source — so **run `npm run build` and commit `kitewrt/static/` whenever you
change anything under `web/src/`** (CI pins Node to keep the build reproducible).
