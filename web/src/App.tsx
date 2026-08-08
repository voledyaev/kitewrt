import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import { useStore } from "./store";
import {
  applyChoice,
  readChoice,
  saveChoice,
  watchSystem,
  type ThemeChoice,
} from "./theme";
import { mayShowOnboarding } from "./health";
import { useHealth } from "./useHealth";
import { Dashboard } from "./components/Dashboard";
import { Wordmark } from "./components/icons";
import { ActionButton, HeaderStatus, Spinner } from "./components/parts";
import { Settings } from "./components/Settings";
import { Onboarding, SubscriptionsSection } from "./components/Subscriptions";

const TABS = ["dashboard", "subscriptions", "settings"] as const;
type Tab = (typeof TABS)[number];

function readHashTab(): Tab {
  const h = location.hash.replace(/^#\/?/, "");
  return (TABS as readonly string[]).includes(h) ? (h as Tab) : "dashboard";
}

// Tab state lives in the URL hash so a refresh (and back/forward) keeps the
// current tab. No router dependency — one hashchange listener is enough.
function useHashTab(): [Tab, (t: Tab) => void] {
  const [tab, setTab] = useState<Tab>(readHashTab);
  // Normalize the URL on load so a bare "/" shows "#dashboard" (and an invalid
  // hash snaps to the resolved tab). replaceState → no history entry, no
  // hashchange event.
  useEffect(() => {
    const t = readHashTab();
    if (location.hash.replace(/^#\/?/, "") !== t) {
      history.replaceState(null, "", `#${t}`);
    }
  }, []);
  useEffect(() => {
    const onHash = () => setTab(readHashTab());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const select = (t: Tab) => {
    if (location.hash.replace(/^#\/?/, "") !== t) location.hash = t;
    setTab(t);
  };
  return [tab, select];
}

function ThemeToggle() {
  const [choice, setChoice] = useState<ThemeChoice>(readChoice);

  // Follow the OS live while set to system: the phone flips at sunset and the
  // page should not need a reload to notice.
  useEffect(() => watchSystem(() => applyChoice("system")), []);

  const cycle = () => {
    const next: ThemeChoice =
      choice === "system" ? "light" : choice === "light" ? "dark" : "system";
    setChoice(next);
    saveChoice(next);
    applyChoice(next);
  };
  const label = choice === "system" ? "Theme: system" : `Theme: ${choice}`;
  return (
    <button
      type="button"
      onClick={cycle}
      title={`${label} — click to change`}
      aria-label={label}
      className="inline-flex size-8 items-center justify-center rounded-field txt-muted transition hover:bg-base-content/10 hover:text-base-content"
    >
      {choice === "system" ? (
        // A half-filled disc: neither light nor dark, which is the point.
        <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden>
          <circle
            cx="8"
            cy="8"
            r="6.25"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
          />
          <path d="M8 1.75a6.25 6.25 0 0 0 0 12.5z" fill="currentColor" />
        </svg>
      ) : choice === "light" ? (
        <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden>
          <circle cx="8" cy="8" r="3.25" fill="currentColor" />
          <g stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
            <path d="M8 .8v1.9M8 13.3v1.9M.8 8h1.9M13.3 8h1.9" />
            <path d="M2.9 2.9l1.35 1.35M11.75 11.75l1.35 1.35M13.1 2.9l-1.35 1.35M4.25 11.75L2.9 13.1" />
          </g>
        </svg>
      ) : (
        <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden>
          <path
            d="M13.5 9.6A5.9 5.9 0 0 1 6.4 2.5a5.9 5.9 0 1 0 7.1 7.1z"
            fill="currentColor"
          />
        </svg>
      )}
    </button>
  );
}

/** One vocabulary. The header shows the same code the status card shows — it
 *  used to say "VPN on" while the dashboard said "Connected", two words for two
 *  different facts, 60px apart, and the cheerier one won. */
function StatusPill() {
  const { state, wsConnected, metrics } = useStore();
  const { h } = useHealth();
  if (!state) return null;
  // "setup needed" may only pre-empt the health code when health has nothing to
  // say — i.e. the VPN is off and nothing is captured. A subscription whose
  // refresh came back with zero servers (a blocked or rotated provider; the
  // daemon re-fetches every 6 h) otherwise put amber "setup needed" in the
  // header ~90px above teal CAPTURED in the card: two vocabularies for one
  // fact, which is the exact thing this component exists to prevent. The
  // disagreement was pessimistic rather than dangerous, but the invariant has
  // to hold by construction or it is not an invariant.
  const hasServers = state.subscriptions.some((s) => s.servers.length > 0);
  if (!hasServers && h.level === "off") {
    // Monochrome: "you have not finished configuring this" is a fact about the
    // config, not about the traffic, and amber is the colour this palette
    // reserves for a LAN diverted into a tunnel that is not answering. Spending
    // it here is what made the two indistinguishable at a glance in the header.
    return (
      <span className="lbl rounded-field border border-base-content/25 px-2 py-1 txt-muted">
        setup needed
      </span>
    );
  }
  // `metrics.available` covers the sing-box half only. Router CPU, WAN
  // throughput and temperature keep streaming with the VPN off, so gating the
  // indicator on the VPN hid it exactly when the dashboard was showing live
  // numbers and the user had no way to tell they were live.
  const hasLiveNumbers = metrics.available || metrics.cpu_percent != null;
  return <HeaderStatus h={h} live={wsConnected && hasLiveNumbers} />;
}

/** "That request failed" — not a state hue.
 *
 *  It was `alert-error`, which is the same red as `--color-alarm`, i.e. the
 *  colour this app uses for "your LAN is on the open internet right now". A
 *  mistyped subscription URL and an exposed household then arrived in the same
 *  colour, and the toast is the one that appears several times a session. The
 *  inverted fill is the heaviest thing this palette has that is not a state
 *  hue — the same treatment the VPN switch uses for its selected segment. */
function Toast() {
  const { error, setError, state, loadFailed } = useStore();
  // The "cannot reach the router" screen already carries this exact string, in
  // context and with a retry. Two copies of one failure, one of them
  // dismissible, is the sort of thing that teaches people to dismiss.
  if (!error || (!state && loadFailed)) return null;
  return (
    <div className="fixed inset-x-3 bottom-3 z-30 flex justify-end sm:inset-x-auto sm:right-4 sm:bottom-4">
      <div
        className="flex max-w-[36rem] items-start gap-3 rounded-field bg-base-content px-3.5 py-2.5 text-base-100 shadow-lg"
        role="alert"
        aria-live="assertive"
      >
        <span className="lbl mt-px shrink-0 opacity-70">failed</span>
        {/* Server text, so it is isolated: an error carrying an RTL hostname
            reorders the sentence around it. */}
        <span className="min-w-0 flex-1 text-body break-words">
          <bdi>{error}</bdi>
        </span>
        <button
          type="button"
          className="lbl shrink-0 opacity-70 hover:opacity-100"
          aria-label="Dismiss error"
          onClick={() => setError("")}
        >
          dismiss
        </button>
      </div>
    </div>
  );
}

/** No state has ever arrived.
 *
 *  This used to be a spinner with no timeout: with the daemon down (crashed,
 *  mid-reboot, or simply the wrong SSID) the page span forever behind a
 *  dismissible red toast, and once that was dismissed the silent poll never
 *  raised it again. A router UI that cannot reach its router has exactly one
 *  honest thing to say, and it is the same thing `unknown` says on the
 *  dashboard: we cannot see, so treat yourself as unprotected. */
function CannotReach({ why }: { why: string }) {
  const { reload } = useStore();
  const [trying, setTrying] = useState(false);
  const retry = async () => {
    setTrying(true);
    try {
      await reload();
    } finally {
      setTrying(false);
    }
  };
  return (
    <div className="mx-auto max-w-2xl py-6">
      <section
        role="alert"
        className="rounded-box border border-dashed border-unknown/60 bg-unknown/[0.05] dotted-unknown p-5 sm:p-7"
      >
        <div className="lbl font-semibold text-unknown">no answer</div>
        <h1 className="mt-2 text-read font-semibold leading-[1.25] tracking-[-0.01em]">
          This page cannot reach the router.
        </h1>
        <p className="mt-2.5 max-w-[58ch] text-body leading-relaxed txt-muted">
          Nothing here can tell you whether your traffic is protected — not that
          it is, and not that it isn&apos;t. The daemon may be restarting, or
          this device may no longer be on its network. Retrying every few
          seconds.
        </p>
        <p className="mt-3 font-mono text-micro txt-faint">
          <bdi>{why}</bdi>
        </p>
        <div className="mt-4">
          <ActionButton tone="unknown" busy={trying} onClick={retry}>
            retry now
          </ActionButton>
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const { state, loadFailed } = useStore();
  const { h } = useHealth();
  const [tab, setTab] = useHashTab();
  const tabRefs = useRef<Partial<Record<Tab, HTMLButtonElement | null>>>({});

  const hasSubs = useMemo(
    () => !!state && state.subscriptions.length > 0,
    [state],
  );

  // Whether the onboarding screen is allowed to speak for the router is decided
  // in health.ts, next to every other rule about what this UI may assert — and
  // pinned there by a test, because the screen hides the verdict, the tabs and
  // the VPN switch behind its own claim.
  const showOnboarding = !!state && mayShowOnboarding(hasSubs, h.level);
  const showTabs = !!state && !showOnboarding;

  // A tablist is one tab stop with arrow keys inside it, not three tab stops.
  // Without this every tab sat in the sequence, so reaching the page content
  // from the header cost three Tab presses and the widget announced as a
  // tablist while behaving like a row of buttons.
  const onTabKey = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    const i = TABS.indexOf(tab);
    let next: number;
    switch (e.key) {
      case "ArrowRight":
        next = (i + 1) % TABS.length;
        break;
      case "ArrowLeft":
        next = (i - 1 + TABS.length) % TABS.length;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = TABS.length - 1;
        break;
      default:
        return;
    }
    e.preventDefault();
    setTab(TABS[next]);
    tabRefs.current[TABS[next]]?.focus();
  };

  return (
    <div className="flex min-h-screen flex-col bg-base-100 text-base-content">
      <header className="sticky top-0 z-20 border-b border-base-300 bg-base-100/85 backdrop-blur">
        <div className="mx-auto flex h-13 max-w-5xl items-center justify-between gap-3 px-4 py-2.5">
          <Wordmark />
          <div className="flex items-center gap-2">
            {showTabs && <StatusPill />}
            <ThemeToggle />
          </div>
        </div>
        {showTabs && (
          <div className="mx-auto max-w-5xl px-4">
            {/* Underline nav rather than daisyUI's pill tabs: the pills read as
                three buttons of equal weight, and the dashboard is not one of
                three things — it is the page, and the other two are where you
                go to change it. */}
            <div role="tablist" onKeyDown={onTabKey} className="-mb-px flex gap-5">
              {TABS.map((t) => (
                <button
                  key={t}
                  ref={(el) => {
                    tabRefs.current[t] = el;
                  }}
                  role="tab"
                  id={`tab-${t}`}
                  aria-selected={tab === t}
                  aria-controls={`panel-${t}`}
                  tabIndex={tab === t ? 0 : -1}
                  className={`lbl border-b-2 pb-2 pt-0.5 transition ${
                    tab === t
                      ? "border-base-content text-base-content"
                      : "border-transparent txt-faint hover:text-base-content"
                  }`}
                  onClick={() => setTab(t)}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
        )}
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-5">
        {!state ? (
          loadFailed ? (
            <CannotReach why={loadFailed} />
          ) : (
            <div className="flex justify-center py-20">
              <Spinner size={28} />
              <span className="sr-only">Loading router state…</span>
            </div>
          )
        ) : showOnboarding ? (
          <Onboarding />
        ) : (
          <>
            {tab === "dashboard" && (
              <div
                role="tabpanel"
                id="panel-dashboard"
                aria-labelledby="tab-dashboard"
              >
                <Dashboard />
              </div>
            )}
            {tab === "subscriptions" && (
              <div
                role="tabpanel"
                id="panel-subscriptions"
                aria-labelledby="tab-subscriptions"
              >
                <SubscriptionsSection />
              </div>
            )}
            {tab === "settings" && (
              <div
                role="tabpanel"
                id="panel-settings"
                aria-labelledby="tab-settings"
              >
                <Settings />
              </div>
            )}
          </>
        )}
      </main>

      <footer className="mx-auto w-full max-w-5xl px-4 py-5">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-base-300 pt-4">
          <a
            className="lbl txt-faint hover:text-base-content"
            href="/api/state"
            target="_blank"
            rel="noreferrer"
          >
            /api/state
          </a>
          <span aria-hidden className="text-base-content/20">
            ·
          </span>
          <a
            className="lbl txt-faint hover:text-base-content"
            href="https://github.com/voledyaev/kitewrt"
            target="_blank"
            rel="noreferrer"
          >
            github
          </a>
        </div>
      </footer>

      <Toast />
    </div>
  );
}
