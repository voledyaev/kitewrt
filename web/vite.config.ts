import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath } from 'node:url'

// The daemon ships no Node: we build the SPA here and commit the output into
// kitewrt/static/, which the router install copies verbatim. FastAPI serves
// `/` → static/index.html and mounts the rest, so Vite's absolute /assets/*
// paths resolve as-is.
// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: fileURLToPath(new URL('../kitewrt/static', import.meta.url)),
    emptyOutDir: true,
    // The ApexCharts chunk is ~590 KB but lazily loaded (see Dashboard); not a
    // shell-bundle concern, so don't warn on it.
    chunkSizeWarningLimit: 700,
  },
  server: {
    // `npm run dev` proxies the API + WS to a locally-running daemon so the
    // dev server (HMR) talks to real state.
    proxy: {
      '/api': { target: 'http://127.0.0.1:8088' },
      '/ws': { target: 'ws://127.0.0.1:8088', ws: true },
    },
  },
})
