import type { PingResult } from './types'

/* The daemon's numbers are read off /proc on a router that may be busy, wedged
 * or (for a subscription-fed field) not ours at all, and this file is the last
 * thing between them and a sentence the user will believe. A value outside the
 * range the quantity can physically occupy is not a small or large reading, it
 * is not a reading — so it renders as the em dash, which the whole UI already
 * uses for "no answer". Rounding overshoot clamps; nonsense does not.
 *
 * "Nothing reported" stays 0 B, unchanged: an absent rate genuinely does mean
 * no traffic, and every rate on the page is a delta that starts at zero. */

export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return '0 B'
  if (!Number.isFinite(n) || n < 0) return '—' // negative bytes do not exist
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

export function fmtRate(bps: number | null | undefined): string {
  const b = fmtBytes(bps)
  // "—/s" reads as a rate of nothing; "—" reads as no rate. Only one is true.
  return b === '—' ? b : `${b}/s`
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
  // Two clocks, so a stamp can land in the future — the router's and this
  // browser's disagree, or the router booted without one. "-5s ago" is not a
  // time; "just now" is the honest floor.
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

/* The flag emoji is gone, deliberately.
 *
 * Three reasons, in order. It was the only saturated colour left on a page
 * whose one rule is that hue means the state of your traffic — 200 of them on
 * the Subscriptions tab, all of it data. It does not survive the platforms a
 * router UI is actually opened from: Windows ships no regional-indicator glyphs
 * at all, so `flagEmoji('NL')` renders there as the letters "NL" beside the
 * mono "NL" this tile already prints — the same code twice, in two faces. And
 * it is remote text: the country comes out of a subscription body, so a
 * provider chose which flag appears in the user's router UI.
 *
 * The two-letter code, set in the instrument face, says the same thing in every
 * browser and costs nothing. */

/** Country code as the tiles render it, or "" when the link carried none.
 *  A link with no country parses to "??", and showing that is worse than
 *  showing nothing: it reads as an error rather than an absence. */
export function countryCode(country: string | undefined): string {
  const cc = (country || '').trim().toUpperCase()
  if (!cc || cc === '??') return ''
  return cc
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

// CPU occupancy is 0-100 by construction. A percent or two over is multi-core
// rounding and clamps; "1000000000%" is a broken counter and says so.
export function fmtPct(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—'
  if (n < -1 || n > 101) return '—'
  return `${Math.min(100, Math.max(0, n)).toFixed(0)}%`
}

// A thermal zone that reports below dry ice or above solder is reporting its
// own failure — usually millidegrees read as degrees, or a missing sensor
// answering with a sentinel. "-273°C" beside a router's CPU load is noise
// dressed as a measurement.
export function fmtTemp(c: number | null | undefined): string {
  if (c === null || c === undefined || !Number.isFinite(c)) return '—'
  if (c < -40 || c > 150) return '—'
  return `${c.toFixed(0)}°C`
}
