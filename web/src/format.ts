import type { PingResult } from './types'

export function fmtBytes(n: number | undefined): string {
  n = n || 0
  if (n < 1024) return `${Math.round(n)} B` // round: rates are fractional
  const u = ['KB', 'MB', 'GB', 'TB']
  let i = -1
  let v = n
  do {
    v /= 1024
    i++
  } while (v >= 1024 && i < u.length - 1)
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`
}

export function fmtRate(bps: number | undefined): string {
  return `${fmtBytes(bps)}/s`
}

export function fmtTime(iso: string | undefined): string {
  if (!iso) return 'never'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString()
}

// "2m ago" style. Pass a periodically-bumped clock so callers re-render.
export function fmtRelative(iso: string | undefined, _clock?: number): string {
  void _clock
  if (!iso) return 'never'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  const s = Math.round((Date.now() - d.getTime()) / 1000)
  if (s < 5) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

export type PingTone = 'fast' | 'mid' | 'slow' | 'down' | 'none'

// Cutoffs tuned for VPN-from-residential-EU: <100 great, 100-300 usable,
// 300+ noticeably laggy for interactive use.
export function pingTone(p: PingResult | undefined): PingTone {
  if (!p) return 'none'
  if (p.ms === null || p.ms === undefined) return 'down'
  if (p.ms < 100) return 'fast'
  if (p.ms < 300) return 'mid'
  return 'slow'
}

export function pingLabel(p: PingResult | undefined): string {
  if (!p) return ''
  if (p.ms === null || p.ms === undefined) return 'down'
  return `${p.ms} ms`
}

// Country code → flag emoji (regional-indicator pair). Falls back to the raw
// string when it isn't a 2-letter code.
export function flagEmoji(country: string): string {
  const cc = (country || '').trim().toUpperCase()
  if (!/^[A-Z]{2}$/.test(cc)) return ''
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}

// Mask a secret subscription source for display: host + short tail hint.
export function maskedSource(s: string): string {
  if (!s) return ''
  if (s.startsWith('vless://')) {
    const at = s.indexOf('@')
    const ends = [s.indexOf('?'), s.indexOf('#')].filter((i) => i > 0).concat([s.length])
    const hostPart = at > 0 ? s.slice(at + 1, Math.min(...ends)) : ''
    return `inline vless://…@${hostPart}`
  }
  try {
    const u = new URL(s)
    const path = u.pathname.replace(/\/+$/, '')
    const tail = path.length > 6 ? path.slice(-6) : path
    return `${u.host}/…${tail}`
  } catch {
    return s.length > 24 ? `${s.slice(0, 12)}…${s.slice(-6)}` : s
  }
}
