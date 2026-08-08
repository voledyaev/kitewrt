// Mirrors kitewrt.state.Data (the /api/state snapshot) + the metrics frame
// shape from kitewrt.metrics_store / build_metrics_summary.

// Secrets (uuid / password / method / params) are stripped server-side before
// any response or WS frame leaves the daemon, so the UI only ever sees these
// display fields. See kitewrt.state.redact_state_dict.
export interface Server {
  id: string; // "host:port"
  name: string;
  country: string;
  type: string; // "vless" | "hysteria2" | "trojan" | ...
  host: string;
  port: number;
}

export interface Subscription {
  id: string;
  label: string;
  source: string;
  fetched_at: string;
  servers: Server[];
}

export interface ActiveServerRef {
  subscription_id: string;
  server_id: string;
}

export interface ApplyResult {
  at: string;
  ok: boolean;
  msg: string;
}

export interface DnsState {
  doh_url: string;
  direct_dns: string;
}

export interface PingResult {
  ms: number | null;
  at: string;
}

export interface AppState {
  version: number;
  subscriptions: Subscription[];
  active_server: ActiveServerRef | null;
  vpn_on: boolean;
  rules_url: string;
  rules_fetched_at: string;
  // Counts, not the lists. A country-sized rules document put 8640 CIDRs
  // (147 KB) and its domain lists (489 KB at 20000 entries) into every poll
  // and every WS push, and counts are all the UI has ever shown of them.
  // See kitewrt.schemas.state_payload.
  rules_count: number;
  rule_sets_count: number;
  rules_bypass_count: number;
  rules_warnings: string[];
  rules_skipped_count: number;
  last_error: string;
  last_apply: ApplyResult | null;
  applying: boolean;
  dns: DnsState;
  pings: Record<string, PingResult>;
}

export interface MetricsTop {
  host: string;
  down: number;
  up: number;
  proxied: boolean;
  net?: string; // "tcp" | "udp"
}

export interface MetricsClient {
  ip: string;
  down: number;
  up: number;
  conns: number;
}

export interface MetricsSample {
  // Through the proxy only — after `bypass_address`, this can be a small
  // fraction of the link. See wan_* for the honest number.
  down_rate: number;
  up_rate: number;
  connections?: number;
  // Router-level, from /proc. null until there is a baseline to delta against.
  cpu_percent?: number | null;
  wan_down_rate?: number | null;
  wan_up_rate?: number | null;
}

export interface MetricsFrame {
  // `available` covers the sing-box-derived half only. The router-level
  // fields below are present regardless — the CPU and the WAN link are just
  // as real with the VPN off.
  available: boolean;
  // Whether the LAN capture is actually installed, as last observed by the
  // watchdog. `null` = could not determine (never checked yet, or the ruleset
  // read failed). NOT the same fact as `vpn_on`, and the gap between them is
  // where every silent leak this project has found lives.
  capture?: boolean | null;
  // Seconds since the watchdog took that reading (server-side).
  capture_age_s?: number | null;
  // Wall-clock ms when this frame reached the browser (client-side). The two
  // add up to how stale the reading really is.
  received_at?: number;
  now?: string;
  down_rate?: number;
  up_rate?: number;
  connections?: number;
  proxied?: number;
  direct?: number;
  memory?: number;
  download_total?: number;
  upload_total?: number;
  top?: MetricsTop[];
  clients?: MetricsClient[];
  history?: MetricsSample[];
  // Router health (kitewrt/sysmetrics.py). Every field optional: a target
  // without thermal zones or a PPE simply reports null.
  cpu_percent?: number | null;
  wan_device?: string | null;
  wan_down_rate?: number | null;
  wan_up_rate?: number | null;
  mem_total?: number | null;
  mem_available?: number | null;
  temp_c?: number | null;
  offload_bound?: number | null;
}

export interface ExitIp {
  available: boolean;
  ip?: string;
  country?: string;
  vpn_on?: boolean;
}

export interface ConnTarget {
  name: string;
  ok: boolean;
  ms: number | null;
}

export interface Connectivity {
  targets: ConnTarget[];
}
