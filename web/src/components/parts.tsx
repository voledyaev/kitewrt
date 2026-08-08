/* The instrument kit: panels, stat cards, the switch, banners.
 *
 * These are the pieces the status component sits on top of. None of them
 * decides anything about the user's traffic — that lives in health.ts and
 * arrives here as a `Health`. */
import {
  useRef,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
} from "react";
import { IconAlert, IconArrowDown, IconArrowUp, IconRefresh } from "./icons";
import { LEVEL, type Health, type Level } from "../health";

/* --- panel ---------------------------------------------------------------- */

/** The one surface. `label` is the instrument voice — a mono machine word, the
 *  same register as "top flows" and "reachability" on the dashboard.
 *
 *  `title` exists for the one thing that is not a machine word: a subscription
 *  is an object the user named, and uppercasing remote text is both wrong
 *  (`text-transform` mangles "מנוי ישראלי") and a lie about who wrote it. It
 *  sits on the declared type scale — `text-title`, not Tailwind's off-scale
 *  `text-base`, which is what the retired `Card` used and is why Subscriptions
 *  and Settings read a half-step away from the dashboard.
 *
 *  `right` is pinned to the top of the panel deliberately: with 200 server
 *  tiles a per-subscription action row rendered underneath them sat 6,400px
 *  below the fold, so the buttons that act on the card could only be reached by
 *  scrolling past everything they act on. */
export function Panel({
  label,
  title,
  meta,
  right,
  children,
  className = "",
}: {
  label?: ReactNode;
  title?: ReactNode;
  meta?: ReactNode;
  right?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  const head = label || title || meta || right;
  return (
    <section
      className={`rounded-box border border-base-300 bg-base-200 p-4 sm:p-5 ${className}`}
    >
      {head && (
        <div
          className={`flex flex-wrap items-start justify-between gap-x-4 gap-y-3 ${
            children ? "mb-3" : ""
          }`}
        >
          <div className="min-w-0 flex-1">
            {label &&
              (title ? (
                <div className="lbl txt-faint">{label}</div>
              ) : (
                <h2 className="lbl txt-faint">{label}</h2>
              ))}
            {title && (
              <h2 className="text-title font-semibold leading-snug tracking-[-0.01em]">
                {title}
              </h2>
            )}
            {meta && <div className="mt-1">{meta}</div>}
          </div>
          {right && (
            // `max-w-full` next to `shrink-0`: shrink-0 is what keeps the
            // dashboard's short right-hand labels ("84 open") on the panel
            // label's line, and it also pinned the subscription action row to
            // its ~420px max-content width — which at 375px pushed Delete off
            // the right edge of the screen and gave the page a horizontal
            // scrollbar. The cap lets the row wrap inside itself instead.
            <div className="flex max-w-full shrink-0 flex-wrap items-center gap-2 text-meta">
              {right}
            </div>
          )}
        </div>
      )}
      {children}
    </section>
  );
}

/* --- numbers -------------------------------------------------------------- */

/** Split "842 KB/s" into value and unit so they can be typeset differently. A
 *  28px unit competes with the number for the eye; at 0.5x and 45% opacity it
 *  stops being read at all, which is correct — you read the digits and glance
 *  at the unit. */
function splitNum(s: string): [string, string] {
  const m = s.match(/^([\d.,]+|—)\s*(.*)$/);
  return m ? [m[1], m[2]] : [s, ""];
}

/** now-vs-peak rail.
 *
 *  This is what the removed charts were for, done in 3px of height and zero
 *  dependencies: the fill is now, the tick is the 30 s peak, and the distance
 *  between them is the whole story a sparkline was telling.
 *
 *  Scale: absolute when the maximum is knowable (CPU 0-100, memory 0-total),
 *  peak-relative otherwise, because a router does not know its own link speed
 *  and inventing one would be a lie of exactly the kind this UI is against. */
function Rail({
  now,
  peak,
  max,
}: {
  now: number | null;
  peak: number | null;
  max?: number | null;
}) {
  const top = max ?? Math.max(peak ?? 0, now ?? 0);
  const pctOf = (v: number | null) =>
    v == null || !top ? 0 : Math.max(0, Math.min(100, (v / top) * 100));
  const nowPct = pctOf(now);
  const peakPct = pctOf(peak);
  const idle = (peak ?? 0) <= 0 && (now ?? 0) <= 0;
  return (
    <div
      className="relative mt-2.5 h-[3px] w-full rounded-full bg-base-content/10"
      aria-hidden
    >
      {!idle && (
        <>
          <div
            className="absolute inset-y-0 left-0 rounded-full bg-current opacity-45"
            style={{ width: `${nowPct}%` }}
          />
          {peakPct > 1.5 && (
            <div
              className="absolute inset-y-[-2px] w-[2px] rounded-full bg-current"
              style={{ left: `calc(${peakPct}% - 1px)` }}
            />
          )}
        </>
      )}
    </div>
  );
}

/** A metric. Deliberately monochrome, including CPU.
 *
 *  The previous card tinted CPU amber at 60% and red at 85%. On this router
 *  60% is what *healthy* proxied traffic costs (measured: the same download is
 *  ~4% offloaded and ~40% through sing-box, and the pre-tproxy config sat at
 *  39-43% at idle load), so the threshold fired during normal use — and an
 *  amber card that means "busy" standing next to an amber card that means
 *  "your LAN is diverted into nothing" is how a palette stops meaning
 *  anything. The absolute rail already shows saturation as a nearly-full bar,
 *  which is the same information in a channel that isn't hue. */
export function Stat({
  label,
  value,
  now,
  peak,
  max,
  foot,
  dir,
}: {
  label: string;
  value: string;
  now: number | null;
  peak: number | null;
  max?: number | null;
  foot?: ReactNode;
  dir?: "down" | "up";
}) {
  const [v, u] = splitNum(value);
  return (
    <div className="rounded-box border border-base-300 bg-base-200 p-3.5">
      <div className="flex items-center gap-1.5 txt-faint">
        {dir === "down" && <IconArrowDown size={11} />}
        {dir === "up" && <IconArrowUp size={11} />}
        <span className="lbl">{label}</span>
      </div>
      <div className="tnum mt-1.5 font-mono leading-none">
        <span className="text-[1.625rem] font-medium tracking-[-0.02em]">
          {v}
        </span>
        <span className="ml-1 text-meta font-normal txt-faint">
          {u}
        </span>
      </div>
      <Rail now={now} peak={peak} max={max} />
      <div className="tnum mt-1.5 h-4 text-micro txt-faint">
        {foot}
      </div>
    </div>
  );
}

/* --- the control ---------------------------------------------------------- */

/** VPN switch.
 *
 *  Deliberately shows INTENT ONLY — what you asked the router to do — and is
 *  never tinted with a state colour. The old `toggle-success` was filled with
 *  the same green the dashboard used for "healthy", so flipping it on painted
 *  a green switch next to a green dot and the two reinforced each other into a
 *  claim neither of them had checked. Intent lives here; truth lives in the
 *  status component, and when they disagree the status says so.
 *
 *  Segmented rather than a slider: on a phone a bare switch has no legible
 *  off/on affordance, and 44px is the smallest thing worth aiming at
 *  one-handed.
 *
 *  A segmented control is a radio group, and it now announces as one. It used
 *  to be `role="group"` around two `aria-pressed` buttons, which says "two
 *  independent toggles" — so a screen-reader user was told the VPN could be
 *  both on and off, given two tab stops for one either/or choice, and got no
 *  arrow-key navigation. Worse, the visible label was an unassociated sibling
 *  and `aria-label="VPN"` was announced in its place, which threw away the
 *  whole point of the wording: this control shows what you *asked* for, not
 *  what is true, and "vpn — requested" is where that is said. */
export function VpnSwitch({
  on,
  applying,
  disabled,
  onChange,
}: {
  on: boolean;
  applying?: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);

  // Selection follows focus, as it does in a native radio group: arrowing moves
  // to the next option and picks it, wrapping — which with two options makes
  // every arrow key a toggle. Home/End address the ends absolutely.
  const onKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    let next: boolean;
    switch (e.key) {
      case "ArrowRight":
      case "ArrowDown":
      case "ArrowLeft":
      case "ArrowUp":
        next = !on;
        break;
      case "Home":
        next = false;
        break;
      case "End":
        next = true;
        break;
      default:
        return;
    }
    e.preventDefault();
    if (disabled) return;
    refs.current[next ? 1 : 0]?.focus();
    if (next !== on) onChange(next);
  };

  if (applying) {
    return (
      <div className="w-full shrink-0 sm:w-[8.5rem]">
        <div className="lbl mb-1.5 txt-faint sm:text-right">vpn</div>
        <div
          className="flex h-11 items-center justify-center overflow-hidden rounded-field border border-base-300"
          role="status"
          aria-live="polite"
          style={{
            backgroundImage:
              "repeating-linear-gradient(-45deg, color-mix(in oklab, currentColor 7%, transparent) 0 8px, transparent 8px 16px)",
          }}
        >
          <span className="lbl text-base-content/70">applying…</span>
        </div>
      </div>
    );
  }
  return (
    // Full width on a phone: a 44px-tall control spanning the card is the
    // easiest thing on this page to hit one-handed.
    <div className="w-full shrink-0 sm:w-[8.5rem]">
      <div id="kw-vpn-label" className="lbl mb-1.5 txt-faint sm:text-right">
        vpn — requested
      </div>
      <div
        role="radiogroup"
        aria-labelledby="kw-vpn-label"
        onKeyDown={onKeyDown}
        className="grid h-11 grid-cols-2 gap-1 rounded-field border border-base-300 bg-base-300/50 p-1"
      >
        {([false, true] as const).map((v, i) => (
          <button
            key={String(v)}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={on === v}
            // Roving: one tab stop for the whole control. Two stops for one
            // either/or choice is how it read as two separate switches.
            tabIndex={on === v ? 0 : -1}
            // `aria-disabled`, not the native attribute. Toggling sets `busy`,
            // which disabled the button the user had just moved to — and the
            // browser blurs a natively-disabled element, so arrowing onto "off"
            // dropped focus to the document root and the keyboard path this
            // control was just given led nowhere. Announced as unavailable,
            // still focusable, handlers guarded.
            aria-disabled={disabled || undefined}
            onClick={() => !disabled && on !== v && onChange(v)}
            className={`lbl rounded-[0.3rem] transition ${
              disabled ? "opacity-40" : ""
            } ${
              on === v
                ? "bg-base-content/90 font-semibold text-base-100"
                : "txt-faint hover:text-base-content"
            }`}
          >
            {v ? "on" : "off"}
          </button>
        ))}
      </div>
    </div>
  );
}

/* --- banners -------------------------------------------------------------- */

/** Persistent condition, not a toast.
 *
 *  "LAN capture was lost and could not be restored" used to be rendered by
 *  `<Toast>` — bottom-right, dismissible, and on a phone it sat over the
 *  content and then went away. A disclosure of every site the household
 *  visited is not a transient notification. It stays until the daemon clears
 *  it, it says when, and it carries the one button that fixes it. */
export function Banner({
  level,
  title,
  body,
  at,
  actions,
}: {
  level: Extract<Level, "alarm" | "caution" | "unknown">;
  title: string;
  body?: ReactNode;
  at?: string;
  actions?: ReactNode;
}) {
  const L = LEVEL[level];
  return (
    <div role="alert" className={`rounded-box border ${L.edge} ${L.fill} p-4`}>
      <div className="flex items-start gap-3">
        <IconAlert size={17} className={`mt-0.5 shrink-0 ${L.tone}`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className={`text-body font-semibold ${L.tone}`}>{title}</span>
            {at && <span className="tnum lbl txt-faint">{at}</span>}
          </div>
          {body && <p className="mt-1 text-body text-base-content/70">{body}</p>}
          {actions && (
            <div className="mt-3 flex flex-wrap items-center gap-2">
              {actions}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** A capture gap that healed itself.
 *
 *  The daemon writes this with ok=True, so it used to render as "last applied
 *  2m ago" with a tick — a measured window of plaintext TCP and cleartext DNS,
 *  filed as a success. It gets its own object.
 *
 *  What it deliberately does NOT show is a duration. The study headlined the
 *  seconds, because 4 s and 21 s are different amounts of browsing history —
 *  but `last_apply` carries only `{at, ok, msg}` and the daemon never puts the
 *  window length on the wire. Inventing one, or deriving it from the 30 s tick,
 *  would be the same class of confident-but-unchecked claim this whole
 *  redesign exists to remove. */
export function GapRecord({ at }: { at: ReactNode }) {
  return (
    <div className="rounded-box border border-caution/50 bg-caution/[0.06] p-4">
      <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
        <span className="lbl font-semibold text-caution">capture gap</span>
        <span className="tnum lbl txt-faint">{at}</span>
      </div>
      <p className="mt-1.5 text-body leading-relaxed text-base-content/70">
        The LAN capture was lost and put back. For as long as it was gone this
        network forwarded plaintext TCP and sent DNS queries to your ISP&apos;s
        resolver. The capture is back, but that traffic is already out.
      </p>
    </div>
  );
}

/* --- small bits ----------------------------------------------------------- */

export function KeyRow({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline gap-3 py-[3px]">
      <span className="lbl w-[4.5rem] shrink-0 txt-faint">{k}</span>
      <span className="min-w-0 flex-1 text-body text-base-content/80">
        {children}
      </span>
    </div>
  );
}

/** Every button in the app, so they all speak the same register.
 *
 *  The three state tones are for the status card's own actions and are the only
 *  ones that spend a state hue. Everything else is `neutral` or `primary`,
 *  because of what the Subscriptions tab used to look like: a `btn-error`
 *  Delete on every card, `text-alarm` on every server that failed a probe, and
 *  an `alert-error` toast — three separate uses of the exact red that means
 *  "your LAN is on the open internet right now", none of them saying anything
 *  about the user's traffic. A palette that shouts on a routine tab cannot
 *  shout about a leak.
 *
 *  `primary` is blue, which this theme defines as the *interactive* colour and
 *  deliberately not a state hue (see index.css) — so the one recommended action
 *  in a form may carry it. Destructive weight lives in the confirm dialog. */
export function ActionButton({
  children,
  tone = "neutral",
  type = "button",
  disabled,
  busy,
  title,
  onClick,
}: {
  children: ReactNode;
  tone?: "neutral" | "primary" | "alarm" | "caution" | "unknown";
  type?: "button" | "submit";
  disabled?: boolean;
  busy?: boolean;
  title?: string;
  onClick?: () => void;
}) {
  const map = {
    // /25 rather than base-300: a neutral button sitting on a hatched alarm
    // surface has to stay visible, and base-300 disappears into it.
    neutral:
      "border-base-content/25 text-base-content/80 hover:bg-base-content/10",
    primary:
      "border-primary bg-primary text-primary-content hover:border-primary/80 hover:bg-primary/85",
    alarm: "border-alarm/60 text-alarm hover:bg-alarm/10",
    caution: "border-caution/60 text-caution hover:bg-caution/10",
    unknown: "border-unknown/60 text-unknown hover:bg-unknown/10",
  };
  // A disabled `primary` drops to the neutral outline rather than fading the
  // fill. Faded-blue still reads as the page's call to action, and Save spends
  // most of its life disabled (nothing typed yet) — so the Settings tab's most
  // saturated element was a button that does nothing.
  const off = disabled || busy;
  const tint = off && tone === "primary" ? map.neutral : map[tone];
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={off}
      title={title}
      aria-busy={busy || undefined}
      className={`lbl inline-flex min-h-9 items-center gap-1.5 rounded-field border px-3 transition disabled:opacity-40 ${tint}`}
    >
      {busy && <Spinner />}
      {children}
    </button>
  );
}

/** In-button progress. Not daisyUI's `loading` (which drags in a component this
 *  app otherwise never uses); a 10px ring on `currentColor`, so it inherits
 *  whatever tone the button is wearing. */
export function Spinner({ size = 11 }: { size?: number }) {
  return (
    <span
      aria-hidden
      className="inline-block shrink-0 animate-spin rounded-full border-[1.5px] border-current border-t-transparent"
      style={{ width: size, height: size }}
    />
  );
}

/** "checked 3s ago" — the age of the evidence, always next to the claim.
 *  Without it the headline asserts a fact from a frame that may have stopped
 *  arriving minutes ago (store.applyMetrics keeps the last frame on a
 *  WebSocket drop and only flips `available`). */
export function Freshness({
  ageMs,
  stale,
}: {
  ageMs: number | null;
  stale?: boolean;
}) {
  if (ageMs == null) {
    return (
      <span className="lbl inline-flex items-center gap-1 txt-faint">
        <IconRefresh size={10} />
        never checked
      </span>
    );
  }
  const s = Math.round(ageMs / 1000);
  return (
    <span
      className={`tnum lbl inline-flex items-center gap-1 ${
        stale ? "text-unknown" : "txt-faint"
      }`}
      title="age of the last capture check"
    >
      <IconRefresh size={10} />
      {stale ? `stale · ${s}s` : `checked ${s}s ago`}
    </span>
  );
}

/** The one-line summary in the app header. Mirrors the dashboard verdict
 *  exactly — the header used to say "VPN on" while the dashboard said
 *  "Connected": two vocabularies for one fact, 60px apart. */
export function HeaderStatus({ h, live }: { h: Health; live: boolean }) {
  const L = LEVEL[h.level];
  return (
    <div className="flex items-center gap-2.5">
      {/* Monochrome. Which transport the numbers arrived over is not a claim
          about the user's traffic, and `text-caution` here put amber "polling"
          two centimetres from whatever the state palette was saying — a second
          vocabulary, in the state palette's own colours, for a fact about a
          WebSocket. It still needs to be *noticed*, so it steps up the mono
          ladder and swaps the filled dot for the dashed ring this UI already
          uses to mean "not observed" (see StatusPath's Marker). */}
      <span
        className={`lbl hidden items-center gap-1 sm:inline-flex ${
          live ? "txt-faint" : "txt-muted"
        }`}
        title={
          live
            ? "real-time (WebSocket)"
            : "polling fallback — the push channel is down"
        }
      >
        {live ? (
          <span className="inline-block size-1.5 rounded-full bg-current" />
        ) : (
          <span className="inline-block size-2 rounded-full border border-dashed border-current" />
        )}
        {live ? "live" : "polling"}
      </span>
      <span
        className={`lbl inline-flex items-center gap-1.5 rounded-field border px-2 py-1 ${L.edge} ${L.fill} ${L.tone}`}
      >
        {h.code}
      </span>
    </div>
  );
}
