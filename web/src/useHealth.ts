// The single subscription point for "what is happening to my traffic".
//
// Every component that wants to say something about the user's safety reads
// this — the header pill, the status card, the footer. They cannot disagree,
// which is how the old UI ended up saying "VPN on" in the header and
// "Connected" in the card, 60px apart, over a LAN egressing in the clear.

import {
  STALE_AFTER_MS,
  captureAgeMs,
  health,
  proxyDownDwellElapsed,
  type Capture,
  type Health,
} from "./health";
import { useStore } from "./store";

export interface HealthView {
  h: Health;
  /** Age of the capture reading, or null when there has never been one. */
  ageMs: number | null;
  /** The reading exists but has expired. Rendered next to the claim. */
  stale: boolean;
  /** What the reading is worth *after* staleness — this, not `metrics.capture`,
   *  is what the path drawing must use. */
  capture: Capture;
}

export function useHealth(): HealthView {
  const { state, metrics, proxyDown: evidence } = useStore();
  const vpnOn = state?.vpn_on ?? false;
  // Re-render is externally driven: a frame arrives ~1/s over the WebSocket
  // (2 s polling), and the store's 15 s clock covers the case where they stop.
  const ageMs = captureAgeMs(metrics);
  const stale = metrics.capture != null && (ageMs ?? 0) > STALE_AFTER_MS;
  // Both the seconds AND the frames — see proxyDownDwellElapsed.
  const proxyDown = proxyDownDwellElapsed(evidence, metrics.received_at ?? 0);
  return {
    h: health({ vpnOn, capture: metrics.capture, ageMs: ageMs ?? 0, proxyDown }),
    ageMs,
    stale,
    capture: stale ? null : metrics.capture,
  };
}
