import type { AppState, Connectivity, ExitIp, MetricsFrame } from './types'

// Must match kitewrt.state — pinned by
// tests/test_api.py::test_frontend_dns_defaults_match_the_backend. Both
// resolvers default to "" = automatic; AUTO_DOH_URL is what an empty DoH field
// means (shown in the hint). It is an IP literal on purpose: the router dials
// it to resolve the VPN servers' own names, so a hostname would need resolving.
export const DEFAULT_DOH_URL = ''
export const DEFAULT_DIRECT_DNS = ''
export const AUTO_DOH_URL = 'https://1.1.1.1/dns-query'

// Must match kitewrt.routes.server.UNREACHABLE_PREFIX — pinned by
// tests/test_api.py. The daemon refuses to move a working VPN onto a node that
// fails a test connection; this is how the UI recognises that refusal and
// offers to switch anyway (blocked nodes come and go).
export const UNREACHABLE_PREFIX = 'Server did not answer a test connection'

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const opts: RequestInit = { method }
  if (body !== undefined && body !== null) {
    opts.headers = { 'Content-Type': 'application/json' }
    opts.body = JSON.stringify(body)
  }
  const r = await fetch(path, opts)
  const text = await r.text()
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    data = { error: text || `HTTP ${r.status}` }
  }
  if (!r.ok) {
    const msg =
      (data as { error?: string; detail?: string }).error ||
      (data as { detail?: string }).detail ||
      `HTTP ${r.status}`
    throw new Error(msg)
  }
  return data as T
}

const enc = encodeURIComponent

// Most mutations return the full updated AppState snapshot.
export const api = {
  getState: () => req<AppState>('GET', '/api/state'),
  getMetrics: () => req<MetricsFrame>('GET', '/api/metrics'),
  getExitIp: () => req<ExitIp>('GET', '/api/exit-ip'),
  getConnectivity: () => req<Connectivity>('GET', '/api/connectivity'),

  addSubscription: (label: string, source: string) =>
    req<AppState>('POST', '/api/subscriptions', { label, source }),
  refreshSubscription: (id: string) =>
    req<AppState>('POST', `/api/subscriptions/${enc(id)}/refresh`),
  testSubscription: (id: string) => req<AppState>('POST', `/api/subscriptions/${enc(id)}/test`),
  autoSelectSubscription: (id: string) =>
    req<AppState>('POST', `/api/subscriptions/${enc(id)}/auto-select`),
  renameSubscription: (id: string, label: string) =>
    req<AppState>('PATCH', `/api/subscriptions/${enc(id)}`, { label }),
  deleteSubscription: (id: string) => req<AppState>('DELETE', `/api/subscriptions/${enc(id)}`),

  pickServer: (subscription_id: string, server_id: string, force = false) =>
    req<AppState>('POST', '/api/server', { subscription_id, server_id, force }),
  toggleVpn: (on: boolean) => req<AppState>('POST', '/api/toggle', { on }),

  setDns: (doh_url: string, direct_dns: string) =>
    req<AppState>('POST', '/api/dns/config', { doh_url, direct_dns }),

  setRulesUrl: (url: string | null) => req<AppState>('POST', '/api/rules-url', { url }),
  refreshRules: () => req<AppState>('POST', '/api/rules/refresh'),
}
