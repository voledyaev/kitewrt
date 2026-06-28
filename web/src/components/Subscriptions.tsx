import { useState } from 'react'
import { api } from '../api'
import { useStore } from '../store'
import type { PingResult, Server, Subscription } from '../types'
import { flagEmoji, fmtRelative, fmtTime, maskedSource, pingLabel, pingTone } from '../format'
import { Card, Field, Reveal, useConfirm } from './ui'

const PING_TONE: Record<string, string> = {
  fast: 'text-success',
  mid: 'text-warning',
  slow: 'text-error',
  down: 'text-error line-through',
  none: 'text-base-content/60',
}

// Sort live servers by ascending ping; "down" after them; untested last.
function sortedServers(sub: Subscription, pings: Record<string, PingResult>): Server[] {
  const bucket = (id: string) => {
    const p = pings[id]
    if (!p) return 2
    if (p.ms === null || p.ms === undefined) return 1
    return 0
  }
  return sub.servers
    .map((srv, i) => ({ srv, i }))
    .sort((a, b) => {
      const ba = bucket(a.srv.id)
      const bb = bucket(b.srv.id)
      if (ba !== bb) return ba - bb
      if (ba === 0) return (pings[a.srv.id].ms ?? 0) - (pings[b.srv.id].ms ?? 0)
      return a.i - b.i
    })
    .map((x) => x.srv)
}

function ServerTile({ subId, srv }: { subId: string; srv: Server }) {
  const { state, run, busy } = useStore()
  if (!state) return null
  const busyOrApplying = busy || state.applying
  const a = state.active_server
  const active = !!a && a.subscription_id === subId && a.server_id === srv.id
  const ping = state.pings[srv.id]
  const flag = flagEmoji(srv.country)
  return (
    <button
      type="button"
      disabled={busyOrApplying}
      onClick={() => !active && run(() => api.pickServer(subId, srv.id))}
      className={`flex flex-col items-start overflow-hidden rounded-box border p-3 text-left transition disabled:opacity-60 ${
        active
          ? 'border-primary bg-primary/10'
          : 'border-base-300 bg-base-100 hover:border-secondary hover:bg-base-300/30'
      }`}
    >
      <div className="flex items-center gap-1 text-xs uppercase tracking-wide text-base-content/50">
        <span>{flag}</span>
        {srv.country}
        {srv.type === 'hysteria2' && (
          <span className="badge badge-xs badge-ghost ml-1 font-mono">HY2</span>
        )}
        {active && <span className="ml-auto text-primary">●</span>}
      </div>
      <div className="mt-0.5 w-full truncate text-sm font-medium">{srv.name}</div>
      <div className="w-full truncate text-xs text-base-content/60">{srv.host}</div>
      <div className={`tnum mt-1.5 text-xs ${PING_TONE[pingTone(ping)]}`}>
        {pingLabel(ping) || ' '}
      </div>
    </button>
  )
}

function SubscriptionCard({ sub }: { sub: Subscription }) {
  const { state, run, busy, testSubscription, testingSubId, autoSelect, autoSelectingSubId, clock } =
    useStore()
  const { confirm, element: confirmEl } = useConfirm()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(sub.label)
  if (!state) return null
  const busyOrApplying = busy || state.applying
  const testing = testingSubId === sub.id
  const autoSelecting = autoSelectingSubId === sub.id
  // Test and Fastest both delay-probe every server; keep them mutually exclusive
  // so a user can't fire two ranking storms at the same subscription at once.
  const ranking = testing || autoSelecting
  const servers = sortedServers(sub, state.pings)

  const startRename = () => {
    setDraft(sub.label)
    setEditing(true)
  }
  const cancelRename = () => setEditing(false)
  const saveRename = async () => {
    const next = draft.trim()
    if (!next || next === sub.label) {
      setEditing(false)
      return
    }
    const ok = await run(() => api.renameSubscription(sub.id, next))
    if (ok) setEditing(false)
  }

  const del = async () => {
    const a = state.active_server
    const clears = a && a.subscription_id === sub.id
    const ok = await confirm({
      title: `Delete "${sub.label}"?`,
      body: clears ? 'VPN will turn off — the active server is in this subscription.' : undefined,
      confirmLabel: 'Delete',
    })
    if (ok) run(() => api.deleteSubscription(sub.id))
  }

  const titleNode = editing ? (
    <span className="flex flex-wrap items-center gap-2">
      <input
        autoFocus
        aria-label="Subscription name"
        className="input input-sm"
        value={draft}
        maxLength={100}
        disabled={busyOrApplying}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') saveRename()
          if (e.key === 'Escape') cancelRename()
        }}
      />
      <button className="btn btn-sm btn-primary" disabled={busyOrApplying} onClick={saveRename}>
        Save
      </button>
      <button type="button" className="btn btn-sm btn-ghost" onClick={cancelRename}>
        Cancel
      </button>
    </span>
  ) : (
    sub.label
  )

  return (
    <Card
      title={titleNode}
      interactiveTitle={editing}
      subtitle={
        <>
          {sub.servers.length} server{sub.servers.length !== 1 && 's'} · last fetched{' '}
          <span title={fmtTime(sub.fetched_at)}>{fmtRelative(sub.fetched_at, clock)}</span>
          <div className="mt-1">
            <Reveal value={sub.source} masked={maskedSource(sub.source)} />
          </div>
        </>
      }
    >
      {servers.length === 0 ? (
        <p className="text-sm text-base-content/50">
          No servers in this subscription. Refresh, or delete the entry.
        </p>
      ) : (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
          {servers.map((srv) => (
            <ServerTile key={srv.id} subId={sub.id} srv={srv} />
          ))}
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        <button
          className="btn btn-sm btn-primary btn-outline"
          disabled={busyOrApplying || ranking || sub.servers.length === 0}
          title="Delay-test every server through the proxy and switch to the fastest"
          onClick={() => autoSelect(sub.id)}
        >
          {autoSelecting && <span className="loading loading-spinner loading-xs" />}
          {autoSelecting ? 'Finding…' : '⚡ Fastest'}
        </button>
        <button
          className="btn btn-sm btn-outline"
          disabled={busyOrApplying || ranking}
          onClick={() => testSubscription(sub.id)}
        >
          {testing && <span className="loading loading-spinner loading-xs" />}
          {testing ? 'Testing…' : 'Test'}
        </button>
        <button
          className="btn btn-sm btn-outline"
          disabled={busyOrApplying}
          onClick={() => run(() => api.refreshSubscription(sub.id))}
        >
          Refresh
        </button>
        <button
          className="btn btn-sm btn-outline"
          disabled={busyOrApplying || editing}
          onClick={startRename}
        >
          Rename
        </button>
        <button
          className="btn btn-sm btn-outline btn-error"
          disabled={busyOrApplying}
          onClick={del}
        >
          Delete
        </button>
      </div>
      {confirmEl}
    </Card>
  )
}

export function AddSubscriptionForm({ onDone }: { onDone?: () => void }) {
  const { run, busy, state } = useStore()
  const [label, setLabel] = useState('')
  const [source, setSource] = useState('')

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const src = source.trim()
    if (!src) return
    const ok = await run(async () => {
      const s = await api.addSubscription(label.trim(), src)
      // Convenience onboarding: auto-pick the first server if none is active.
      if (!s.active_server) {
        const added = s.subscriptions[s.subscriptions.length - 1]
        if (added && added.servers.length > 0) {
          return api.pickServer(added.id, added.servers[0].id)
        }
      }
      return s
    })
    if (ok) {
      setLabel('')
      setSource('')
      onDone?.()
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <Field label="Label" hint="optional — defaults to the source hostname">
        <input
          className="input w-full"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="A short name for this subscription"
          maxLength={100}
        />
      </Field>
      <Field label="Source">
        <input
          className="input w-full"
          value={source}
          onChange={(e) => setSource(e.target.value)}
          placeholder="https://… subscription URL, or vless://… link pasted directly"
          required
        />
      </Field>
      <div className="flex gap-2">
        <button type="submit" className="btn btn-primary btn-sm" disabled={busy || state?.applying}>
          {busy && <span className="loading loading-spinner loading-xs" />}
          Add subscription
        </button>
        {onDone && (
          <button type="button" className="btn btn-ghost btn-sm" disabled={busy} onClick={onDone}>
            Cancel
          </button>
        )}
      </div>
    </form>
  )
}

export function SubscriptionsSection() {
  const { state } = useStore()
  const [adding, setAdding] = useState(false)
  if (!state) return null
  return (
    <div className="space-y-4">
      {state.subscriptions.map((sub) => (
        <SubscriptionCard key={sub.id} sub={sub} />
      ))}
      <Card>
        {adding ? (
          <AddSubscriptionForm onDone={() => setAdding(false)} />
        ) : (
          <button className="btn btn-outline btn-sm" onClick={() => setAdding(true)}>
            + Add subscription
          </button>
        )}
      </Card>
    </div>
  )
}

export function Onboarding() {
  return (
    <div className="mx-auto max-w-xl">
      <Card title="Get started" subtitle="Add your first VLESS subscription to begin.">
        <p className="mb-4 text-sm text-base-content/60">
          The source can be an HTTP(S) URL to a subscription list, or a single{' '}
          <code className="rounded bg-base-300/60 px-1 py-0.5 font-mono text-xs">vless://</code> link
          pasted directly.
        </p>
        <AddSubscriptionForm />
      </Card>
    </div>
  )
}
