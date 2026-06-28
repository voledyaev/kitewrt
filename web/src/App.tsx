import { useEffect, useMemo, useState } from 'react'
import { useStore } from './store'
import { Dashboard } from './components/Dashboard'
import { Settings } from './components/Settings'
import { Onboarding, SubscriptionsSection } from './components/Subscriptions'

const TABS = ['dashboard', 'subscriptions', 'settings'] as const
type Tab = (typeof TABS)[number]

function readHashTab(): Tab {
  const h = location.hash.replace(/^#\/?/, '')
  return (TABS as readonly string[]).includes(h) ? (h as Tab) : 'dashboard'
}

// Tab state lives in the URL hash so a refresh (and back/forward) keeps the
// current tab. No router dependency — one hashchange listener is enough.
function useHashTab(): [Tab, (t: Tab) => void] {
  const [tab, setTab] = useState<Tab>(readHashTab)
  // Normalize the URL on load so a bare "/" shows "#dashboard" (and an invalid
  // hash snaps to the resolved tab). replaceState → no history entry, no
  // hashchange event.
  useEffect(() => {
    const t = readHashTab()
    if (location.hash.replace(/^#\/?/, '') !== t) {
      history.replaceState(null, '', `#${t}`)
    }
  }, [])
  useEffect(() => {
    const onHash = () => setTab(readHashTab())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])
  const select = (t: Tab) => {
    if (location.hash.replace(/^#\/?/, '') !== t) location.hash = t
    setTab(t)
  }
  return [tab, select]
}

function StatusPill() {
  const { state, wsConnected, metrics } = useStore()
  if (!state) return null
  const hasServers = state.subscriptions.some((s) => s.servers.length > 0)
  if (!hasServers) {
    return <span className="badge badge-warning badge-sm font-semibold">Setup needed</span>
  }
  const live = wsConnected && metrics.available
  return (
    <div className="flex items-center gap-2">
      {state.vpn_on && (
        <span
          className={`flex items-center gap-1 text-xs ${live ? 'text-success' : 'text-warning'}`}
          title={live ? 'real-time (WebSocket)' : 'polling fallback'}
        >
          <span className="inline-block size-1.5 rounded-full bg-current" />
          {live ? 'live' : 'polling'}
        </span>
      )}
      <span
        className={`badge badge-sm font-semibold ${
          state.vpn_on ? 'badge-success' : 'badge-ghost'
        }`}
      >
        {state.vpn_on ? 'VPN on' : 'VPN off'}
      </span>
    </div>
  )
}

function Toast() {
  const { error, setError } = useStore()
  if (!error) return null
  return (
    <div className="toast toast-end z-30">
      <div className="alert alert-error text-sm shadow-lg" role="alert" aria-live="assertive">
        <span>{error}</span>
        <button
          type="button"
          className="btn btn-ghost btn-xs btn-circle"
          aria-label="Dismiss error"
          onClick={() => setError('')}
        >
          ✕
        </button>
      </div>
    </div>
  )
}

export default function App() {
  const { state } = useStore()
  const [tab, setTab] = useHashTab()

  const hasSubs = useMemo(() => !!state && state.subscriptions.length > 0, [state])

  return (
    <div className="flex min-h-screen flex-col bg-base-100 text-base-content">
      <header className="sticky top-0 z-20 border-b border-base-300 bg-base-100/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
          <div className="flex items-center gap-2 text-lg font-semibold">
            <span aria-hidden>🪁</span>
            <span>
              Kite<span className="text-primary">Wrt</span>
            </span>
          </div>
          <StatusPill />
        </div>
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-6">
        {!state ? (
          <div className="flex justify-center py-20">
            <span className="loading loading-spinner loading-lg text-base-content/30" />
          </div>
        ) : !hasSubs ? (
          <Onboarding />
        ) : (
          <>
            <div role="tablist" className="tabs tabs-box mb-6 inline-flex bg-base-200">
              <button
                role="tab"
                id="tab-dashboard"
                aria-selected={tab === 'dashboard'}
                aria-controls="panel-dashboard"
                className={`tab ${tab === 'dashboard' ? 'tab-active' : ''}`}
                onClick={() => setTab('dashboard')}
              >
                Dashboard
              </button>
              <button
                role="tab"
                id="tab-subscriptions"
                aria-selected={tab === 'subscriptions'}
                aria-controls="panel-subscriptions"
                className={`tab ${tab === 'subscriptions' ? 'tab-active' : ''}`}
                onClick={() => setTab('subscriptions')}
              >
                Subscriptions
              </button>
              <button
                role="tab"
                id="tab-settings"
                aria-selected={tab === 'settings'}
                aria-controls="panel-settings"
                className={`tab ${tab === 'settings' ? 'tab-active' : ''}`}
                onClick={() => setTab('settings')}
              >
                Settings
              </button>
            </div>
            {tab === 'dashboard' && (
              <div role="tabpanel" id="panel-dashboard" aria-labelledby="tab-dashboard">
                <Dashboard />
              </div>
            )}
            {tab === 'subscriptions' && (
              <div role="tabpanel" id="panel-subscriptions" aria-labelledby="tab-subscriptions">
                <SubscriptionsSection />
              </div>
            )}
            {tab === 'settings' && (
              <div role="tabpanel" id="panel-settings" aria-labelledby="tab-settings">
                <Settings />
              </div>
            )}
          </>
        )}
      </main>

      <footer className="mx-auto w-full max-w-5xl px-4 py-6 text-center text-xs text-base-content/60">
        <a className="link link-hover" href="/api/state" target="_blank" rel="noreferrer">
          /api/state
        </a>
        {' · '}
        <a
          className="link link-hover"
          href="https://github.com/voledyaev/kitewrt"
          target="_blank"
          rel="noreferrer"
        >
          GitHub
        </a>
      </footer>

      <Toast />
    </div>
  )
}
