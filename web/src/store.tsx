// Context module: the provider component and its `useStore` hook live together
// by design, so the "only export components" fast-refresh rule doesn't apply.
/* eslint-disable react-refresh/only-export-components */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { api } from './api'
import type { AppState, MetricsFrame } from './types'

interface Store {
  state: AppState | null
  metrics: MetricsFrame
  wsConnected: boolean
  busy: boolean
  error: string
  testingSubId: string
  autoSelectingSubId: string
  clock: number
  setError: (e: string) => void
  run: (fn: () => Promise<AppState>) => Promise<boolean>
  testSubscription: (id: string) => Promise<void>
  autoSelect: (id: string) => Promise<void>
}

const emptyMetrics: MetricsFrame = { available: false, history: [] }

const Ctx = createContext<Store | null>(null)

export function useStore(): Store {
  const v = useContext(Ctx)
  if (!v) throw new Error('useStore used outside <StoreProvider>')
  return v
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AppState | null>(null)
  const [metrics, setMetrics] = useState<MetricsFrame>(emptyMetrics)
  const [wsConnected, setWsConnected] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [testingSubId, setTestingSubId] = useState('')
  const [autoSelectingSubId, setAutoSelectingSubId] = useState('')
  const [clock, setClock] = useState(0)

  // Latest values readable inside long-lived loops (timers, WS callbacks)
  // without re-subscribing them. Synced after each render so a callback that
  // fires later always sees current values.
  const stateRef = useRef<AppState | null>(state)
  const wsRef = useRef(wsConnected)
  const busyRef = useRef(busy)
  useEffect(() => {
    stateRef.current = state
    wsRef.current = wsConnected
    busyRef.current = busy
  })

  const applyMetrics = useCallback((m: MetricsFrame | null) => {
    // Keep the last history on an unavailable frame so the chart doesn't
    // flicker empty on a transient WS reconnect.
    if (!m || !m.available) {
      setMetrics((prev) => ({ ...prev, available: false }))
      return
    }
    setMetrics(m)
  }, [])

  const refresh = useCallback(async (silent: boolean) => {
    try {
      setState(await api.getState())
      if (!silent) setError('')
    } catch (e) {
      if (!silent) setError((e as Error).message)
    }
  }, [])

  // Tick a counter so relative timestamps ("2m ago") re-render on their own.
  useEffect(() => {
    const t = setInterval(() => setClock((c) => c + 1), 15000)
    return () => clearInterval(t)
  }, [])

  // WebSocket push channel: state on every change, metrics ~1/s. On drop,
  // fall back to polling and retry the socket.
  useEffect(() => {
    let sock: WebSocket | null = null
    let retry: ReturnType<typeof setTimeout> | null = null
    let closed = false

    const connect = () => {
      if (closed) return
      try {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
        sock = new WebSocket(`${proto}//${location.host}/ws`)
      } catch {
        setWsConnected(false)
        retry = setTimeout(connect, 3000)
        return
      }
      sock.onopen = () => setWsConnected(true)
      sock.onmessage = (ev) => {
        try {
          const frame = JSON.parse(ev.data)
          if (frame?.type === 'state') setState(frame.data)
          else if (frame?.type === 'metrics') applyMetrics(frame.data)
        } catch {
          /* ignore malformed frame */
        }
      }
      sock.onerror = () => sock?.close()
      sock.onclose = () => {
        setWsConnected(false)
        sock = null
        if (!busyRef.current) refresh(true)
        if (!closed) retry = setTimeout(connect, 3000)
      }
    }

    // Async load-on-mount: setState runs after the await, not synchronously,
    // so this isn't a cascading-render hazard.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refresh(false)
    connect()
    return () => {
      closed = true
      if (retry) clearTimeout(retry)
      sock?.close()
    }
  }, [applyMetrics, refresh])

  // State poll fallback — dormant while the WS is up. Faster cadence while an
  // apply is in flight so the "applying…" state clears promptly.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>
    const tick = () => {
      const delay = stateRef.current?.applying ? 500 : 10000
      timer = setTimeout(async () => {
        if (!wsRef.current && !busyRef.current) await refresh(true)
        tick()
      }, delay)
    }
    tick()
    return () => clearTimeout(timer)
  }, [refresh])

  // Metrics poll fallback — dormant while the WS pushes metrics.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>
    const tick = () => {
      timer = setTimeout(async () => {
        if (!wsRef.current) {
          if (!stateRef.current?.vpn_on) {
            applyMetrics(null)
          } else {
            try {
              applyMetrics(await api.getMetrics())
            } catch {
              applyMetrics(null)
            }
          }
        }
        tick()
      }, 2000)
    }
    tick()
    return () => clearTimeout(timer)
  }, [applyMetrics])

  const run = useCallback(async (fn: () => Promise<AppState>): Promise<boolean> => {
    setBusy(true)
    setError('')
    try {
      setState(await fn())
      return true
    } catch (e) {
      setError((e as Error).message)
      return false
    } finally {
      setBusy(false)
    }
  }, [])

  // Scoped flag (not `busy`): a TCP probe takes ~2s and shouldn't grey out
  // the whole UI — only the subscription's own Test button.
  const testSubscription = useCallback(async (id: string) => {
    setTestingSubId(id)
    setError('')
    try {
      setState(await api.testSubscription(id))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setTestingSubId('')
    }
  }, [])

  // Like testSubscription, but scoped to the auto-select action: it delay-tests
  // every server through the proxy then switches to the fastest, so it runs a
  // few seconds longer. Scoped flag keeps the rest of the UI live meanwhile.
  const autoSelect = useCallback(async (id: string) => {
    setAutoSelectingSubId(id)
    setError('')
    try {
      setState(await api.autoSelectSubscription(id))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setAutoSelectingSubId('')
    }
  }, [])

  const store: Store = {
    state,
    metrics,
    wsConnected,
    busy,
    error,
    testingSubId,
    autoSelectingSubId,
    clock,
    setError,
    run,
    testSubscription,
    autoSelect,
  }
  return <Ctx.Provider value={store}>{children}</Ctx.Provider>
}
