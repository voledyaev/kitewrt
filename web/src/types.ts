// Mirrors kitewrt.state.Data (the /api/state snapshot) + the metrics frame
// shape from kitewrt.metrics_store / build_metrics_summary.

// Secrets (uuid / password / method / params) are stripped server-side before
// any response or WS frame leaves the daemon, so the UI only ever sees these
// display fields. See kitewrt.state.redact_state_dict.
export interface Server {
  id: string // "host:port"
  name: string
  country: string
  type: string // "vless" | "hysteria2" | "trojan" | ...
  host: string
  port: number
}

export interface Subscription {
  id: string
  label: string
  source: string
  fetched_at: string
  servers: Server[]
}

export interface ActiveServerRef {
  subscription_id: string
  server_id: string
}

export interface ApplyResult {
  at: string
  ok: boolean
  msg: string
}

export interface DnsState {
  doh_url: string
  direct_dns: string
}

export interface PingResult {
  ms: number | null
  at: string
}

export interface AppState {
  version: number
  subscriptions: Subscription[]
  active_server: ActiveServerRef | null
  vpn_on: boolean
  rules_url: string
  rules_fetched_at: string
  rules: unknown[]
  rule_sets: unknown[]
  rules_warnings: string[]
  rules_skipped_count: number
  last_error: string
  last_apply: ApplyResult | null
  applying: boolean
  dns: DnsState
  pings: Record<string, PingResult>
}

export interface MetricsTop {
  host: string
  down: number
  up: number
  proxied: boolean
  net?: string // "tcp" | "udp"
}

export interface MetricsClient {
  ip: string
  down: number
  up: number
  conns: number
}

export interface MetricsSample {
  down_rate: number
  up_rate: number
  memory?: number
  connections?: number
}

export interface MetricsFrame {
  available: boolean
  now?: string
  down_rate?: number
  up_rate?: number
  connections?: number
  proxied?: number
  direct?: number
  memory?: number
  download_total?: number
  upload_total?: number
  top?: MetricsTop[]
  clients?: MetricsClient[]
  history?: MetricsSample[]
}

export interface ExitIp {
  available: boolean
  ip?: string
  country?: string
  vpn_on?: boolean
}

export interface ConnTarget {
  name: string
  ok: boolean
  ms: number | null
}

export interface Connectivity {
  targets: ConnTarget[]
}
