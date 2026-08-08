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
} from "react";
import { api } from "./api";
import { trackProxyDown, type ProxyDownEvidence } from "./health";
import type { AppState, MetricsFrame } from "./types";

interface Store {
  state: AppState | null;
  metrics: MetricsFrame;
  /** Evidence that sing-box is unreachable while the VPN is on: when it
   *  started, and how many delivered frames have said so. Both matter — see
   *  PROXY_DOWN_MIN_FRAMES. */
  proxyDown: ProxyDownEvidence | null;
  wsConnected: boolean;
  busy: boolean;
  error: string;
  testingSubId: string;
  autoSelectingSubId: string;
  clock: number;
  /** The first /api/state load has failed and none has ever succeeded. Distinct
   *  from `error`, which is transient and dismissible: until this clears there
   *  is no state at all, so the page can say nothing about the user's traffic
   *  and must not pretend the spinner is progress. */
  loadFailed: string;
  setError: (e: string) => void;
  /** Returns the outcome, not just a flag. A refresh that failed because the
   *  provider is blocked is a durable fact about that subscription, and the
   *  toast — dismissible, and re-suppressed by the silent poll — was the only
   *  place it was ever said. Callers that want to keep it need the message. */
  run: (fn: () => Promise<AppState>) => Promise<RunResult>;
  reload: () => Promise<void>;
  testSubscription: (id: string) => Promise<void>;
  autoSelect: (id: string) => Promise<void>;
}

export interface RunResult {
  ok: boolean;
  error: string;
}

const emptyMetrics: MetricsFrame = { available: false, history: [] };

const Ctx = createContext<Store | null>(null);

export function useStore(): Store {
  const v = useContext(Ctx);
  if (!v) throw new Error("useStore used outside <StoreProvider>");
  return v;
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AppState | null>(null);
  const [metrics, setMetrics] = useState<MetricsFrame>(emptyMetrics);
  const [proxyDown, setProxyDown] = useState<ProxyDownEvidence | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [testingSubId, setTestingSubId] = useState("");
  const [autoSelectingSubId, setAutoSelectingSubId] = useState("");
  const [clock, setClock] = useState(0);
  const [loadFailed, setLoadFailed] = useState("");

  // Latest values readable inside long-lived loops (timers, WS callbacks)
  // without re-subscribing them. Synced after each render so a callback that
  // fires later always sees current values.
  const stateRef = useRef<AppState | null>(state);
  const applyingSinceRef = useRef<number | null>(null);
  const wsRef = useRef(wsConnected);
  const busyRef = useRef(busy);
  useEffect(() => {
    stateRef.current = state;
    wsRef.current = wsConnected;
    busyRef.current = busy;
    if (state?.applying) {
      if (applyingSinceRef.current == null) applyingSinceRef.current = Date.now();
    } else {
      applyingSinceRef.current = null;
    }
  });

  const applyMetrics = useCallback((m: MetricsFrame | null) => {
    // Stamp arrival. Without it a dropped WebSocket leaves the last frame in
    // place and the headline keeps asserting a `capture` reading that stopped
    // arriving minutes ago — the same false certainty the field was added to
    // remove, just moved into the client.
    const now = Date.now();
    const delivered = m && { ...m, received_at: now };
    // Whether this frame is evidence of a black hole is decided in health.ts,
    // next to the constants and the reasons for them. This is the wiring.
    setProxyDown((prev) =>
      trackProxyDown(prev, {
        frame: delivered,
        vpnOn: stateRef.current?.vpn_on ?? false,
        applying: stateRef.current?.applying ?? false,
        applyingSince: applyingSinceRef.current,
        now,
      }),
    );
    // No frame at all (WS down): keep the last one, just mark it stale, so the
    // chart doesn't flicker empty on a transient reconnect.
    if (!delivered) {
      setMetrics((prev) => ({ ...prev, available: false }));
      return;
    }
    if (!delivered.available) {
      // `available` describes the sing-box half only. Router CPU, WAN
      // throughput, memory and temperature are just as real with the VPN off,
      // and so is the history — discarding the whole frame here is what left
      // the charts stuck on "gathering data…" whenever it was switched off.
      setMetrics((prev) => ({ ...prev, ...delivered, available: false }));
      return;
    }
    setMetrics(delivered);
  }, []);

  const refresh = useCallback(async (silent: boolean) => {
    try {
      setState(await api.getState());
      setLoadFailed("");
      if (!silent) setError("");
    } catch (e) {
      const msg = (e as Error).message;
      if (!silent) setError(msg);
      // Only while there is nothing to show. Once a snapshot has landed, a
      // failed poll is not a blank page — it is a stale page, and the
      // freshness of the *capture reading* is what decides whether the
      // headline may still make a claim (see health.ts). Overwriting the
      // dashboard with an error box there would throw away the one thing the
      // user still needs: the last thing we knew, with its age beside it.
      setLoadFailed((prev) => (stateRef.current ? "" : msg || prev || "failed"));
    }
  }, []);

  // Tick a counter so relative timestamps ("2m ago") re-render on their own.
  useEffect(() => {
    const t = setInterval(() => setClock((c) => c + 1), 15000);
    return () => clearInterval(t);
  }, []);

  // WebSocket push channel: state on every change, metrics ~1/s. On drop,
  // fall back to polling and retry the socket.
  useEffect(() => {
    let sock: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const connect = () => {
      if (closed) return;
      try {
        const proto = location.protocol === "https:" ? "wss:" : "ws:";
        sock = new WebSocket(`${proto}//${location.host}/ws`);
      } catch {
        setWsConnected(false);
        retry = setTimeout(connect, 3000);
        return;
      }
      sock.onopen = () => setWsConnected(true);
      sock.onmessage = (ev) => {
        try {
          const frame = JSON.parse(ev.data);
          if (frame?.type === "state") {
            setState(frame.data);
            // The socket delivers a snapshot on connect, so it can be the
            // thing that ends a run of failed /api/state polls.
            setLoadFailed("");
          } else if (frame?.type === "metrics") applyMetrics(frame.data);
        } catch {
          /* ignore malformed frame */
        }
      };
      sock.onerror = () => sock?.close();
      sock.onclose = () => {
        setWsConnected(false);
        sock = null;
        if (!busyRef.current) refresh(true);
        if (!closed) retry = setTimeout(connect, 3000);
      };
    };

    // Async load-on-mount: setState runs after the await, not synchronously,
    // so this isn't a cascading-render hazard.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refresh(false);
    connect();
    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      sock?.close();
    };
  }, [applyMetrics, refresh]);

  // State poll fallback — dormant while the WS is up. Faster cadence while an
  // apply is in flight so the "applying…" state clears promptly.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const tick = () => {
      const delay = stateRef.current?.applying ? 500 : 10000;
      timer = setTimeout(async () => {
        if (!wsRef.current && !busyRef.current) await refresh(true);
        tick();
      }, delay);
    };
    tick();
    return () => clearTimeout(timer);
  }, [refresh]);

  // Metrics poll fallback — dormant while the WS pushes metrics.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const tick = () => {
      timer = setTimeout(async () => {
        if (!wsRef.current) {
          // Polled regardless of vpn_on: the frame carries router health even
          // when the proxy half is unavailable.
          try {
            applyMetrics(await api.getMetrics());
          } catch {
            applyMetrics(null);
          }
        }
        tick();
      }, 2000);
    };
    tick();
    return () => clearTimeout(timer);
  }, [applyMetrics]);

  const run = useCallback(
    async (fn: () => Promise<AppState>): Promise<RunResult> => {
      setBusy(true);
      setError("");
      try {
        setState(await fn());
        setLoadFailed("");
        return { ok: true, error: "" };
      } catch (e) {
        const error = (e as Error).message;
        setError(error);
        return { ok: false, error };
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  // Manual retry for the "never loaded" screen. The poll behind it keeps
  // trying anyway; this is so the button does something the moment it is
  // pressed rather than up to ten seconds later. Returns the promise so the
  // button can show that it is trying — a retry that looks inert is a retry
  // people press four times.
  const reload = useCallback(() => refresh(false), [refresh]);

  // Scoped flag (not `busy`): a TCP probe takes ~2s and shouldn't grey out
  // the whole UI — only the subscription's own Test button.
  const testSubscription = useCallback(async (id: string) => {
    setTestingSubId(id);
    setError("");
    try {
      setState(await api.testSubscription(id));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setTestingSubId("");
    }
  }, []);

  // Like testSubscription, but scoped to the auto-select action: it delay-tests
  // every server through the proxy then switches to the fastest, so it runs a
  // few seconds longer. Scoped flag keeps the rest of the UI live meanwhile.
  const autoSelect = useCallback(async (id: string) => {
    setAutoSelectingSubId(id);
    setError("");
    try {
      setState(await api.autoSelectSubscription(id));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAutoSelectingSubId("");
    }
  }, []);

  const store: Store = {
    state,
    metrics,
    proxyDown,
    wsConnected,
    busy,
    error,
    testingSubId,
    autoSelectingSubId,
    clock,
    loadFailed,
    setError,
    run,
    reload,
    testSubscription,
    autoSelect,
  };
  return <Ctx.Provider value={store}>{children}</Ctx.Provider>;
}
