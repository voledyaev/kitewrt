import { useState } from 'react'
import { api, DEFAULT_DIRECT_DNS, DEFAULT_DOH_URL } from '../api'
import { useStore } from '../store'
import { fmtRelative, fmtTime, maskedSource } from '../format'
import { Card, Field, Reveal } from './ui'

function DnsCard() {
  const { state, run, busy, clock } = useStore()
  const dns = state!.dns
  const [doh, setDoh] = useState(dns.doh_url)
  const [direct, setDirect] = useState(dns.direct_dns || '')
  void clock
  const busyOrApplying = busy || state!.applying
  const dirty = doh.trim() !== dns.doh_url || direct.trim() !== (dns.direct_dns || '')
  const isDefault = doh === DEFAULT_DOH_URL && direct === DEFAULT_DIRECT_DNS

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!doh.trim()) return
    await run(() => api.setDns(doh.trim(), direct.trim()))
  }
  const reset = async () => {
    setDoh(DEFAULT_DOH_URL)
    setDirect(DEFAULT_DIRECT_DNS)
    await run(() => api.setDns(DEFAULT_DOH_URL, DEFAULT_DIRECT_DNS))
  }

  return (
    <Card title="DNS">
      <p className="mb-4 text-sm text-base-content/60">
        Two resolvers, both default to Cloudflare. <strong>Foreign</strong> (proxy-routed) domains
        resolve over encrypted DoH through the tunnel; <strong>Direct</strong> (home/LAN) domains
        resolve via a plain resolver on the direct path. If you rely on region-specific GeoDNS, set
        Direct to a resolver in that region — it must not be the router's own resolver (that loops
        through the tunnel).
      </p>
      <form onSubmit={save} className="space-y-3">
        <Field label="Foreign DNS (DoH URL)">
          <input
            type="url"
            className="input w-full"
            value={doh}
            onChange={(e) => setDoh(e.target.value)}
            placeholder={DEFAULT_DOH_URL}
            disabled={busyOrApplying}
          />
        </Field>
        <Field label="Direct DNS (resolver IP — empty = system default)">
          <input
            type="text"
            className="input w-full"
            value={direct}
            onChange={(e) => setDirect(e.target.value)}
            placeholder={DEFAULT_DIRECT_DNS}
            disabled={busyOrApplying}
          />
        </Field>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            disabled={busyOrApplying || isDefault}
            onClick={reset}
          >
            Reset to Cloudflare
          </button>
          <button
            type="submit"
            className="btn btn-primary btn-sm"
            disabled={busyOrApplying || !doh.trim() || !dirty}
          >
            Save
          </button>
        </div>
      </form>
    </Card>
  )
}

function RulesCard() {
  const { state, run, busy, clock } = useStore()
  const [url, setUrl] = useState('')
  const busyOrApplying = busy || state!.applying
  const hasRules = !!state!.rules_url

  return (
    <Card title="Routing rules">
      {hasRules ? (
        <div className="space-y-2">
          <Reveal value={state!.rules_url} masked={maskedSource(state!.rules_url)} />
          <div className="text-xs text-base-content/60">
            last fetched{' '}
            <span title={fmtTime(state!.rules_fetched_at)}>
              {fmtRelative(state!.rules_fetched_at, clock)}
            </span>
          </div>
          <div className="flex flex-wrap gap-2 pt-1">
            <button
              className="btn btn-sm btn-outline"
              disabled={busyOrApplying}
              onClick={() => run(() => api.refreshRules())}
            >
              Refresh rules
            </button>
            <button
              className="btn btn-sm btn-outline"
              disabled={busyOrApplying}
              onClick={() => run(() => api.setRulesUrl(null))}
            >
              Reset to default
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-base-content/60">
            Without a custom URL, all traffic goes through the VPN (only private/LAN networks stay
            direct). Set a sing-box route-rules JSON URL to override.
          </p>
          <form
            className="flex flex-wrap gap-2"
            onSubmit={async (e) => {
              e.preventDefault()
              if (!url.trim()) return
              const ok = await run(() => api.setRulesUrl(url.trim()))
              if (ok) setUrl('')
            }}
          >
            <input
              type="url"
              aria-label="Routing rules JSON URL"
              className="input min-w-[16rem] flex-1"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://gist.githubusercontent.com/…/rules.json"
            />
            <button className="btn btn-primary btn-sm" disabled={busyOrApplying || !url.trim()}>
              Set rules URL
            </button>
          </form>
        </div>
      )}
    </Card>
  )
}

export function Settings() {
  return (
    <div className="space-y-4">
      <DnsCard />
      <RulesCard />
    </div>
  )
}
