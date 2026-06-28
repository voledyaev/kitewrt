import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'
import { api } from '../api'
import { useStore } from '../store'
import { flagEmoji, fmtBytes, fmtRate, fmtRelative, fmtTime } from '../format'
import type { ConnTarget, ExitIp } from '../types'
import type { AreaSeries } from './AreaChart'
import { Card } from './ui'

// ApexCharts is ~500 KB — split it into its own chunk so the shell (which must
// boot even with the VPN down) stays light. Loaded only once the dashboard
// renders with the VPN on. (The `import type` above is erased, so it doesn't
// pull the chunk eagerly.)
const AreaChart = lazy(() => import('./AreaChart').then((m) => ({ default: m.AreaChart })))

// Module-level so the chart's options memo stays stable across renders.
const fmtCount = (v: number) => String(Math.round(v))

// Best-effort public exit IP. Refetches when the VPN toggles (the exit changes)
// and every 30 s; failures just leave it null so the row hides.
function useExitIp(vpnOn: boolean): ExitIp | null {
  const [info, setInfo] = useState<ExitIp | null>(null)
  useEffect(() => {
    let alive = true
    const load = () =>
      api
        .getExitIp()
        .then((d) => alive && setInfo(d))
        .catch(() => {})
    load() // immediately on mount / vpn toggle
    // The server keys its cache on vpn_on, so this re-fetch after the tunnel
    // has settled reflects the new exit IP (not the pre-toggle one).
    const settle = setTimeout(load, 2500)
    const t = setInterval(load, 30000)
    return () => {
      alive = false
      clearTimeout(settle)
      clearInterval(t)
    }
  }, [vpnOn])
  return info
}

function activeLabel(
  state: NonNullable<ReturnType<typeof useStore>['state']>,
): { name: string; sub: string; serverId: string } | null {
  const a = state.active_server
  if (!a) return null
  for (const sub of state.subscriptions) {
    if (sub.id !== a.subscription_id) continue
    const srv = sub.servers.find((s) => s.id === a.server_id)
    if (srv) return { name: srv.name, sub: sub.label, serverId: srv.id }
  }
  return { name: a.server_id, sub: a.subscription_id, serverId: a.server_id }
}

function VpnControl() {
  const { state, run, busy, clock } = useStore()
  const exit = useExitIp(state?.vpn_on ?? false)
  if (!state) return null
  const busyOrApplying = busy || state.applying
  const active = activeLabel(state)
  const ping = active ? state.pings[active.serverId] : undefined
  return (
    <Card>
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={`inline-block size-2.5 rounded-full ${
                state.vpn_on ? 'bg-success' : 'bg-base-content/30'
              }`}
            />
            <h2 className="text-lg font-semibold">{state.vpn_on ? 'Connected' : 'Disconnected'}</h2>
          </div>
          <div className="mt-1 text-sm text-base-content/60">
            {active ? (
              <>
                via <span className="font-medium text-base-content">{active.name}</span>
                <span className="text-base-content/60"> · {active.sub}</span>
                {ping?.ms != null && <span className="tnum ml-2 text-success">{ping.ms} ms</span>}
              </>
            ) : (
              'No server selected'
            )}
          </div>
          {exit?.available && exit.ip && (
            <div className="mt-1 text-xs text-base-content/60">
              exit IP <span className="tnum text-base-content/70">{exit.ip}</span>
              {exit.country && (
                <span className="ml-1">
                  {flagEmoji(exit.country)} {exit.country}
                </span>
              )}
            </div>
          )}
        </div>
        <input
          type="checkbox"
          className="toggle toggle-success toggle-lg"
          aria-label="VPN on/off"
          checked={state.vpn_on}
          disabled={busyOrApplying || (!state.active_server && !state.vpn_on)}
          onChange={(e) => run(() => api.toggleVpn(e.target.checked))}
        />
      </div>

      {state.applying && (
        <div className="mt-3 flex items-center gap-2 text-sm text-base-content/60">
          <span className="loading loading-spinner loading-xs" /> applying changes…
        </div>
      )}
      {!state.applying && state.last_apply && !state.last_apply.ok && (
        <div className="mt-3 rounded-field border border-error/40 bg-error/10 p-3 text-sm text-error">
          <span className="font-semibold">Apply failed</span> at {fmtTime(state.last_apply.at)}:{' '}
          {state.last_apply.msg || '(no message)'}
        </div>
      )}
      {!state.applying && state.last_apply?.ok && (
        <div className="mt-3 text-xs text-base-content/60">
          last applied{' '}
          <span title={fmtTime(state.last_apply.at)}>
            {fmtRelative(state.last_apply.at, clock)}
          </span>
        </div>
      )}
    </Card>
  )
}

function Stat({
  label,
  value,
  sub,
  accent = 'text-base-content',
}: {
  label: string
  value: ReactNode
  sub?: ReactNode
  accent?: string
}) {
  return (
    <div className="rounded-box border border-base-300 bg-base-200 p-4">
      <div className="text-xs uppercase tracking-wide text-base-content/50">{label}</div>
      <div className={`tnum mt-1 text-2xl font-semibold ${accent}`}>{value}</div>
      <div className="mt-0.5 h-4 text-xs text-base-content/60">{sub}</div>
    </div>
  )
}

function StatCards() {
  const { metrics } = useStore()
  const on = metrics.available
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Stat
        label="Download"
        accent="text-accent"
        value={on ? fmtRate(metrics.down_rate) : '—'}
        sub={on ? `total ${fmtBytes(metrics.download_total)}` : undefined}
      />
      <Stat
        label="Upload"
        accent="text-success"
        value={on ? fmtRate(metrics.up_rate) : '—'}
        sub={on ? `total ${fmtBytes(metrics.upload_total)}` : undefined}
      />
      <Stat
        label="Connections"
        value={on ? metrics.connections : '—'}
        sub={on ? `${metrics.proxied} via VPN · ${metrics.direct} direct` : undefined}
      />
      <Stat
        label="sing-box memory"
        value={on ? fmtBytes(metrics.memory) : '—'}
      />
    </div>
  )
}

function Connections() {
  const { metrics } = useStore()
  const top = metrics.top ?? []
  return (
    <Card title="Active connections" subtitle="top flows by traffic">
      {/* table-fixed + explicit column widths: cells size by layout, not by
          content, so the columns don't jitter as hosts/byte values change.
          overflow-x-auto + min-width: on a phone the table scrolls sideways
          instead of crushing the Host column to nothing (the fixed numeric
          columns would otherwise eat the whole width). */}
      <div className="overflow-x-auto">
        <table className="table table-fixed table-sm w-full min-w-[27rem]">
        <thead>
          <tr className="text-base-content/50">
            <th scope="col">Host</th>
            <th scope="col" className="w-14">Type</th>
            <th scope="col" className="w-16">Route</th>
            <th scope="col" className="w-24 text-right">↓ Down</th>
            <th scope="col" className="w-24 text-right">↑ Up</th>
          </tr>
        </thead>
        <tbody>
          {!metrics.available && (
            <tr>
              <td colSpan={5} className="text-base-content/60">
                Connecting…
              </td>
            </tr>
          )}
          {metrics.available && top.length === 0 && (
            <tr>
              <td colSpan={5} className="text-base-content/60">
                No active flows
              </td>
            </tr>
          )}
          {top.map((c) => (
            <tr key={`${c.host}-${c.net ?? ''}`} className="hover:bg-base-300/30">
              <td className="truncate font-medium">{c.host}</td>
              <td className="text-xs uppercase text-base-content/60">{c.net || '—'}</td>
              <td>
                <span
                  className={`badge badge-sm ${
                    c.proxied ? 'badge-success badge-soft' : 'badge-ghost'
                  }`}
                >
                  {c.proxied ? 'VPN' : 'direct'}
                </span>
              </td>
              <td className="tnum whitespace-nowrap text-right text-base-content/70">
                {fmtBytes(c.down)}
              </td>
              <td className="tnum whitespace-nowrap text-right text-base-content/70">
                {fmtBytes(c.up)}
              </td>
            </tr>
          ))}
        </tbody>
        </table>
      </div>
    </Card>
  )
}

function Devices() {
  const { metrics } = useStore()
  const clients = metrics.clients ?? []
  return (
    <Card title="Devices" subtitle="LAN clients by traffic">
      <div className="overflow-x-auto">
        <table className="table table-fixed table-sm w-full min-w-[22rem]">
        <thead>
          <tr className="text-base-content/50">
            <th scope="col">IP</th>
            <th scope="col" className="w-16 text-right">Conns</th>
            <th scope="col" className="w-24 text-right">↓ Down</th>
            <th scope="col" className="w-24 text-right">↑ Up</th>
          </tr>
        </thead>
        <tbody>
          {!metrics.available && (
            <tr>
              <td colSpan={4} className="text-base-content/60">
                Connecting…
              </td>
            </tr>
          )}
          {metrics.available && clients.length === 0 && (
            <tr>
              <td colSpan={4} className="text-base-content/60">
                No active devices
              </td>
            </tr>
          )}
          {clients.map((c) => (
            <tr key={c.ip} className="hover:bg-base-300/30">
              <td className="tnum truncate font-medium">{c.ip}</td>
              <td className="tnum text-right text-base-content/60">{c.conns}</td>
              <td className="tnum whitespace-nowrap text-right text-base-content/70">
                {fmtBytes(c.down)}
              </td>
              <td className="tnum whitespace-nowrap text-right text-base-content/70">
                {fmtBytes(c.up)}
              </td>
            </tr>
          ))}
        </tbody>
        </table>
      </div>
    </Card>
  )
}

// Live, informative legend for the traffic chart (replaces ApexCharts' built-in
// toggle legend, which was useless — the 1/s data refresh reset the toggle).
function ChartLegend() {
  const { metrics } = useStore()
  const on = metrics.available
  const item = (color: string, label: string, val: number | undefined) => (
    <span className="flex items-center gap-1.5 text-xs">
      <span className="inline-block size-2 rounded-full" style={{ background: color }} />
      <span className="text-base-content/50">{label}</span>
      <span className="tnum text-base-content/80">{on ? fmtRate(val) : '—'}</span>
    </span>
  )
  return (
    <div className="flex gap-4">
      {item('#2dd4bf', 'Download', metrics.down_rate)}
      {item('#2ea043', 'Upload', metrics.up_rate)}
    </div>
  )
}

function ChartPanel({
  title,
  subtitle,
  right,
  series,
  height = 200,
  yFormat,
}: {
  title: string
  subtitle?: string
  right?: ReactNode
  series: AreaSeries[]
  height?: number
  yFormat: (v: number) => string
}) {
  return (
    // min-w-0: as a grid/flex item, allow shrinking below the chart's intrinsic
    // width so ApexCharts sizes to the container instead of overflowing it.
    <Card title={title} subtitle={subtitle} right={right} className="min-w-0">
      <Suspense
        fallback={
          <div
            className="flex items-center justify-center text-sm text-base-content/60"
            style={{ height }}
          >
            loading chart…
          </div>
        }
      >
        <AreaChart series={series} height={height} yFormat={yFormat} />
      </Suspense>
    </Card>
  )
}

function Connectivity() {
  const [targets, setTargets] = useState<ConnTarget[] | null>(null)
  useEffect(() => {
    let alive = true
    const load = () =>
      api
        .getConnectivity()
        .then((d) => alive && setTargets(d.targets))
        .catch(() => {})
    load()
    const t = setInterval(load, 15000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])
  const rows = targets ?? [
    { name: 'Google', ok: false, ms: null },
    { name: 'Cloudflare', ok: false, ms: null },
    { name: 'GitHub', ok: false, ms: null },
  ]
  return (
    <Card title="Connectivity" subtitle="reachability through the current path">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        {rows.map((t) => (
          <div
            key={t.name}
            className="flex items-center gap-2 rounded-box border border-base-300 bg-base-100 p-3"
          >
            <span
              className={`inline-block size-2.5 rounded-full ${
                targets ? (t.ok ? 'bg-success' : 'bg-error') : 'bg-base-content/30'
              }`}
            />
            <span className="font-medium">{t.name}</span>
            <span className="tnum ml-auto text-xs text-base-content/60">
              {!targets ? '…' : t.ok ? (t.ms != null ? `${t.ms} ms` : 'ok') : 'unreachable'}
            </span>
          </div>
        ))}
      </div>
    </Card>
  )
}

export function Dashboard() {
  const { state, metrics } = useStore()
  if (!state) return null
  const on = metrics.available
  const hist = metrics.history ?? []
  return (
    <div className="space-y-4">
      <VpnControl />
      {state.vpn_on && (
        <>
          <StatCards />
          <ChartPanel
            title="Traffic"
            subtitle="last 30s"
            right={<ChartLegend />}
            height={240}
            yFormat={fmtRate}
            series={[
              { name: 'Download', color: '#2dd4bf', data: hist.map((h) => h.down_rate) },
              { name: 'Upload', color: '#2ea043', data: hist.map((h) => h.up_rate) },
            ]}
          />
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <ChartPanel
              title="Memory"
              subtitle="sing-box RSS"
              height={180}
              yFormat={fmtBytes}
              right={
                <span className="tnum text-sm text-base-content/70">
                  {on ? fmtBytes(metrics.memory) : '—'}
                </span>
              }
              series={[{ name: 'Memory', color: '#2dd4bf', data: hist.map((h) => h.memory ?? 0) }]}
            />
            <ChartPanel
              title="Connections"
              subtitle="active over time"
              height={180}
              yFormat={fmtCount}
              right={
                <span className="tnum text-sm text-base-content/70">
                  {on ? metrics.connections : '—'}
                </span>
              }
              series={[
                { name: 'Connections', color: '#58a6ff', data: hist.map((h) => h.connections ?? 0) },
              ]}
            />
          </div>
        </>
      )}
      {/* Connectivity works on the direct path too, so it shows even with the
          VPN off; the metrics-driven widgets above need the tunnel up. */}
      <Connectivity />
      {state.vpn_on && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Connections />
          <Devices />
        </div>
      )}
    </div>
  )
}
