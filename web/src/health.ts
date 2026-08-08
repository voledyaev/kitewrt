// The one place that turns raw daemon facts into a claim about the user's
// traffic. No component may read `vpn_on` and decide for itself.
//
// Inputs, all already on the wire:
//   state.vpn_on          — the user asked for the VPN
//   metrics.capture       — true | false | null, from the watchdog's ruleset read
//   age of that reading   — `capture_age_s` (since the watchdog looked) plus
//                           the client-side age of the frame it rode in on.
//                           Either alone under-counts: the daemon can stop
//                           ticking while the socket stays up, and the socket
//                           can drop while the daemon keeps ticking — and
//                           store.applyMetrics keeps the LAST frame when the
//                           WebSocket drops (only `available` flips), so the
//                           capture value can be minutes stale while the
//                           headline still asserts it.
//   metrics.available     — the sing-box half of the frame. See `proxyDown`.
//
// `null` is NOT "probably fine". It is its own state with its own colour, its
// own glyph and its own texture, because a UI that renders unknown as healthy
// is this product's core failure mode.

import type { MetricsFrame } from "./types";

export type Capture = boolean | null | undefined;

export type Level =
  | "secure" // verified: everything leaving the LAN is captured and tunnelled
  | "alarm" // verified bad: traffic is on the open internet right now
  | "caution" // diverted into a proxy that is not answering — the LAN goes dark
  | "unknown" // we cannot see enough to make a claim
  | "off"; // deliberately not protecting anything

/** Actions the daemon can actually perform. There is deliberately no
 *  "re-check": nothing in the API triggers a fresh capture read — the watchdog
 *  owns that on its own 30 s tick — so a button offering one would be a lie.
 *  `reassert` re-runs the whole apply, which calls `ensure_capture()` and
 *  therefore both fixes and re-answers the question. */
export type ActionKind = "reassert" | "stop" | "start";

export interface Health {
  level: Level;
  /** Machine word. Mono, uppercase, small — never the biggest thing on screen. */
  code: string;
  /** The claim, in plain language. This gets the display type size. */
  claim: string;
  /** One sentence of mechanism for whoever wants to know why. */
  detail: string;
  /** Positively verified that the LAN is covered. Only ever true for 'secure'. */
  covered: boolean;
  /** Does this state deserve to take space and interrupt? */
  loud: boolean;
  action?: { label: string; kind: ActionKind };
}

/** A capture reading older than this is not evidence any more. The watchdog
 *  observes it every 30 s, so ~95 s is three missed ticks — long enough not to
 *  flicker, short enough that a wedged daemon or a dead WebSocket cannot keep
 *  a green headline alive on an old reading. */
export const STALE_AFTER_MS = 95_000;

/** How long the sing-box half of the metrics frame must stay unavailable
 *  before the UI will call a captured LAN black-holed.
 *
 *  The frame is published ~1/s, and `available: false` is also what a single
 *  Clash hiccup and the tail of a restart look like — the watchdog re-runs
 *  `ensure_capture()` within ~15 s and heals most of them. Escalating on the
 *  first missing frame would paint a full-width amber card every time the
 *  control port stutters, which is the crying-wolf failure this palette exists
 *  to avoid. Ten seconds is past any single stutter and well inside the
 *  watchdog's own repair window. */
export const PROXY_DOWN_AFTER_MS = 10_000;

/** …and at least this many delivered frames must have said so.
 *
 *  Time alone was not enough. `PROXY_DOWN_AFTER_MS` is a subtraction between
 *  two arrival stamps, which the comment above it described as counting
 *  *delivered evidence* — it does not. One `available: false`, then a silent
 *  socket for 25 s (a wedged daemon, a suspended tab, a slept laptop, a forward
 *  clock jump), then one more, and the dwell elapsed on two frames with no
 *  evidence in between. That is the crying-wolf case the dwell exists to
 *  prevent, so require the frames as well as the seconds. */
export const PROXY_DOWN_MIN_FRAMES = 5;

/** An apply may suppress the black-hole alarm for this long, and no longer.
 *
 *  `applying` clearing the timer is right for a restart and catastrophic
 *  without a ceiling: a state write failing on a full disk has already left
 *  `applying` stuck true once, and the LAN then sat dark — capture up, nothing
 *  listening — for as long as anyone watched, with the dashboard green. The
 *  daemon learned this the same way and answered with `_MAX_DEFERRALS = 10`, a
 *  bound on how long a stuck flag may retire supervision. This is that bound,
 *  on the UI side. An apply that fetches rules, rewrites the config, restarts
 *  sing-box and waits out `ensure_capture` takes tens of seconds; past 90 s the
 *  flag is telling us about the daemon, not about the traffic. */
export const APPLY_SUPPRESSES_ALARM_MS = 90_000;

/** Age of the capture reading in ms, or null when there has never been one. */
export function captureAgeMs(m: MetricsFrame, now = Date.now()): number | null {
  if (m.capture === undefined) return null;
  const serverMs = (m.capture_age_s ?? 0) * 1000;
  const clientMs = m.received_at ? now - m.received_at : 0;
  // Floored at zero. The two halves are measured against two different clocks
  // — `capture_age_s` against the router's, `received_at` against this
  // laptop's — so a skew between them rendered "checked -5s ago" beside the
  // headline claim. A reading from the future is not a fresher reading; it is
  // a clock disagreement, and "just now" is the honest floor.
  return Math.max(0, serverMs + clientMs);
}

/* ---------------------------------------------------------------------------
   The black-hole dwell.

   Both halves of it live here rather than in the store, next to the constants
   whose reasons they implement: they are the rule that decides whether the
   dashboard is allowed to accuse the router, and that rule is not a rendering
   detail. Pure functions of their inputs, so the boundaries above can be
   tested at the second rather than inferred from a running browser.
   ------------------------------------------------------------------------ */

/** Evidence that sing-box is unreachable while the VPN is on: when the streak
 *  started, and how many delivered frames have said so. Both matter — see
 *  PROXY_DOWN_MIN_FRAMES. */
export interface ProxyDownEvidence {
  since: number;
  frames: number;
}

/** One metrics frame, weighed against the state it arrived in. */
export interface FrameEvidence {
  /** The delivered frame, or `null` when none arrived at all (the WebSocket
   *  dropped). Those are not the same fact — see `trackProxyDown`. */
  frame: { available: boolean; received_at?: number } | null;
  vpnOn: boolean;
  applying: boolean;
  /** When `applying` last went true, or null while it is clear. */
  applyingSince: number | null;
  now: number;
}

/** Fold one frame into the standing evidence. */
export function trackProxyDown(
  prev: ProxyDownEvidence | null,
  { frame, vpnOn, applying, applyingSince, now }: FrameEvidence,
): ProxyDownEvidence | null {
  // No frame at all is not evidence about sing-box — it says the browser
  // cannot reach the *daemon*. Counting it would let a dropped WebSocket on
  // the client's side accuse the router of black-holing the LAN.
  if (!frame) return null;
  // A delivered `available: false` DOES say something — but only while the VPN
  // is on. The daemon publishes it unconditionally when `vpn_on` is false,
  // without ever asking sing-box (see the metrics pump), which would otherwise
  // leave a stale start-time behind that fires the instant the VPN comes back.
  if (!vpnOn || frame.available) return null;
  // An apply legitimately has a gap while sing-box restarts — but the
  // suppression is bounded, because an `applying` flag that never clears has
  // stranded this dashboard green over a dark LAN before (a state write
  // failing on a full disk; the daemon answered with `_MAX_DEFERRALS`). Past
  // the bound the flag is evidence about the daemon, not about the traffic.
  if (
    applying &&
    applyingSince != null &&
    now - applyingSince < APPLY_SUPPRESSES_ALARM_MS
  ) {
    return null;
  }
  // Count the frames, not just the seconds — see PROXY_DOWN_MIN_FRAMES.
  return prev
    ? { since: prev.since, frames: prev.frames + 1 }
    : { since: frame.received_at ?? now, frames: 1 };
}

/** Has the dwell elapsed — both halves?
 *
 *  `latestFrameAt` is the arrival stamp of the newest delivered frame, not the
 *  wall clock: measuring between deliveries is what keeps a browser that lost
 *  the daemon from aging its way into an accusation. */
export function proxyDownDwellElapsed(
  ev: ProxyDownEvidence | null,
  latestFrameAt: number,
): boolean {
  return (
    ev != null &&
    latestFrameAt - ev.since >= PROXY_DOWN_AFTER_MS &&
    ev.frames >= PROXY_DOWN_MIN_FRAMES
  );
}

export interface Facts {
  vpnOn: boolean;
  capture: Capture;
  /** From `captureAgeMs`. */
  ageMs: number;
  /** The tunnel was asked for, but sing-box's control plane has not answered
   *  for `PROXY_DOWN_AFTER_MS`. Only meaningful while `vpnOn` — the daemon
   *  publishes `available: false` unconditionally when the VPN is off, without
   *  ever asking sing-box, so with the VPN off this fact does not exist. */
  proxyDown: boolean;
}

export function health({ vpnOn, capture, ageMs, proxyDown }: Facts): Health {
  // Fold staleness into the tri-state before anything else, so every consumer
  // gets it for free and no one can forget.
  const stale = capture != null && ageMs > STALE_AFTER_MS;
  const cap: boolean | null = stale ? null : (capture ?? null);

  const staleNote = stale
    ? ` The last reading is ${Math.round(ageMs / 1000)}s old — nothing has looked since, so this is memory, not observation.`
    : "";

  if (vpnOn && cap === true && proxyDown) {
    // Diverted into a listener that is not there. TPROXY hands the packet to a
    // socket that no longer exists and the kernel drops it: TCP hangs and the
    // LAN stops resolving names, while ICMP keeps working, so "the internet is
    // down but ping works" is the symptom. Saying CAPTURED here would be
    // literally true and completely useless.
    return {
      level: "caution",
      code: "NO LISTENER",
      claim: "Your LAN is being diverted into a tunnel that is not answering.",
      detail:
        "The capture is installed but sing-box has stopped answering on its control port, so diverted connections have nowhere to land — TCP hangs and DNS goes quiet while ping keeps working. The watchdog restarts it on its own; turning the VPN off is what lets it give up and remove the capture instead.",
      covered: false,
      loud: true,
      action: { label: "Turn VPN off", kind: "stop" },
    };
  }

  if (vpnOn && cap === true) {
    return {
      level: "secure",
      code: "CAPTURED",
      claim: "Everything leaving this LAN goes through the tunnel.",
      detail:
        "TCP, UDP and DNS are diverted into sing-box before they can reach the uplink, and anything else is dropped rather than forwarded.",
      covered: true,
      loud: false,
    };
  }

  if (vpnOn && cap === false) {
    return {
      level: "alarm",
      code: "LEAKING",
      claim: "Your LAN is on the open internet right now.",
      detail:
        "The tunnel is up but nothing is being diverted into it. Every device on this network is reaching the internet through your ISP in the clear, DNS queries included.",
      covered: false,
      loud: true,
      action: { label: "Restore capture", kind: "reassert" },
    };
  }

  if (vpnOn) {
    return {
      level: "unknown",
      code: "UNVERIFIED",
      claim: "The tunnel is up. Whether your LAN is captured is unknown.",
      detail:
        "The capture check returned no answer, so this dashboard cannot tell you whether your traffic is protected. Treat it as unprotected until it can. The watchdog re-reads the ruleset every 30 seconds." +
        staleNote,
      covered: false,
      loud: true,
      action: { label: "Re-assert capture", kind: "reassert" },
    };
  }

  // VPN off. Deliberately ONE state, not two.
  //
  // The study modelled `!vpn_on && capture === true` as a fault ("capture rules
  // installed while sing-box is down"). On this daemon it is the designed
  // behaviour: turning the VPN off points sing-box's selector at `direct` and
  // leaves both the process and the capture in place, so the fake IPs handed
  // out during the last session keep resolving. Traffic still goes straight
  // out; sing-box just dials it itself. Rendering that as amber would fire an
  // alarm on every single off.
  //
  // A capture with a *dead* sing-box behind it really does black-hole the LAN
  // with the VPN off — but the daemon publishes `available: false` without ever
  // asking sing-box once `vpn_on` is false, so the UI has no evidence either
  // way and must not pretend otherwise. The watchdog is the only thing that can
  // see it, and it has a give-up-and-uncapture path for exactly this.
  return {
    level: "off",
    code: "DIRECT",
    claim: "Traffic goes straight out. Nothing is protected.",
    detail:
      cap === true
        ? "The capture is still installed — sing-box is dialling those connections out directly instead of through a proxy server, which is what keeps names handed out during the last session resolving."
        : cap === false
          ? "No capture rules are installed and no traffic is being proxied — a plain router."
          : "Whether capture rules are still installed could not be read. With the VPN off nothing is being proxied either way." +
            staleNote,
    covered: false,
    loud: false,
    action: { label: "Turn VPN on", kind: "start" },
  };
}

/** May the app show the onboarding screen instead of the dashboard?
 *
 *  The screen exists for a router with nothing configured, and it says so in
 *  words — "no tunnel configured", "Nothing is protected yet" — while hiding the
 *  status pill, the tabs, the dashboard and the VPN switch behind it. That made
 *  it the second place in the app that decides what to tell the user about
 *  their traffic, and it decided from `subscriptions.length === 0`, which is a
 *  question about configuration, not about packets.
 *
 *  The two come apart. `POST /api/server` with no ids clears `active_server`
 *  without touching `vpn_on`, and a restored or hand-edited state.json can
 *  carry either combination — so a router with a live capture, or with a
 *  capture standing in front of a dead sing-box (which black-holes the entire
 *  LAN, symptom: "the internet is down but ping works"), rendered as a welcome
 *  page offering a subscription form, with no way to see the verdict or turn
 *  anything off.
 *
 *  `off` is the only level whose claim matches what the screen says. Anything
 *  else, and the dashboard is the correct screen even with nothing configured:
 *  the Subscriptions tab still has the form.
 *
 *  Lives here rather than in App because it is a rule about what the UI is
 *  allowed to assert, and this file is where those live. */
export function mayShowOnboarding(
  hasSubscriptions: boolean,
  level: Level,
): boolean {
  return !hasSubscriptions && level === "off";
}

/** Per-level presentation.
 *
 *  Colour is one channel of four. Glyph, edge treatment and screen prominence
 *  carry the same information, so the page still parses under `filter:
 *  grayscale(1)` and under deuteranopia. Verify both before shipping. */
export const LEVEL: Record<
  Level,
  {
    tone: string; // state colour token (index.css @theme)
    fill: string; // surface + texture
    edge: string; // border treatment: solid / hatched / dashed / flat
    glyph: string; // see icons.tsx — distinct silhouettes, not coloured dots
  }
> = {
  secure: {
    tone: "text-secure",
    fill: "bg-secure/[0.06]",
    edge: "border-secure/35",
    glyph: "linked",
  },
  alarm: {
    tone: "text-alarm",
    fill: "bg-alarm/10 hatch-alarm",
    edge: "border-alarm",
    glyph: "broken",
  },
  caution: {
    tone: "text-caution",
    fill: "bg-caution/[0.08] hatch-caution",
    edge: "border-caution/70",
    glyph: "blocked",
  },
  unknown: {
    tone: "text-unknown",
    fill: "bg-unknown/[0.05] dotted-unknown",
    edge: "border-unknown/60 border-dashed",
    glyph: "query",
  },
  off: {
    tone: "text-inert",
    fill: "bg-base-200",
    edge: "border-base-300",
    glyph: "flat",
  },
};

/* ---------------------------------------------------------------------------
   Capture gaps.

   The daemon reports three distinct events on one channel (`last_apply`):
   lost-and-unhealed (ok=False), restored, and lost-and-self-healed — which it
   writes with **ok=True**, so a measured 4-21 s window in which the LAN
   egressed plaintext TCP and cleartext DNS otherwise renders as the grey line
   "last applied 2m ago" with a tick beside it.

   A browsing-history disclosure has to leave a mark even when it self-heals,
   so it is matched out of the stream by its exact message and given its own
   object. Matching on a string across the API boundary is fragile, which is
   why it is pinned from the Python side — see
   tests/test_api.py::test_frontend_capture_messages_match_the_backend, the
   same guard DEFAULT_DOH_URL has.
   ------------------------------------------------------------------------ */

/** Must match kitewrt.dataplane._CAPTURE_GAP_MSG. */
export const CAPTURE_GAP_MSG =
  "LAN capture was lost and restored — traffic was briefly unproxied";

/** Must match kitewrt.dataplane._CAPTURE_LOST_MSG. */
export const CAPTURE_LOST_MSG =
  "LAN capture was lost and could not be restored (traffic is NOT being proxied)";
