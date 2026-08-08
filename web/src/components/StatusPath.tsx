/* SIGNAL PATH — the status component.
 *
 * Bet: the user cannot judge a claim they do not understand the shape of. Draw
 * the path a packet takes — LAN → capture → tunnel → exit — and let the failure
 * be a picture of a broken path rather than an adjective. The leak state gets a
 * second, wrong path drawn underneath, going straight out to the WAN, because
 * that is literally what is happening and no sentence lands as hard as seeing
 * the line bypass the box.
 */
import { GLYPHS } from "./icons";
import {
  LEVEL,
  type ActionKind,
  type Capture,
  type Health,
  type Level,
} from "../health";
import { ActionButton, Freshness, KeyRow, VpnSwitch } from "./parts";

type NodeState = "on" | "off" | "bad" | "unknown" | "idle";

// currentColor throughout, never a named state hue: the chain sits inside a
// wrapper tinted with the level's tone, so a "bad" node is red in a leak and
// amber in a black-hole. Hard-coding alarm here put a red marker inside an
// amber card, which is two states claiming one node.
const DOT: Record<NodeState, string> = {
  on: "bg-current",
  idle: "bg-current opacity-30",
  off: "bg-base-content/20",
  bad: "bg-current",
  unknown: "bg-current",
};

function Marker({ s }: { s: NodeState }) {
  // Shape carries the state as well as fill: a dashed ring for unknown, a
  // slashed diamond for bad, a plain dot otherwise. Readable with hue removed.
  if (s === "unknown") {
    return (
      <span className="relative inline-flex size-3 items-center justify-center">
        <span className="absolute inset-0 rounded-full border border-dashed border-current" />
      </span>
    );
  }
  if (s === "bad") {
    return (
      <span className="relative inline-flex size-3 items-center justify-center">
        <span className="absolute inset-[1px] rotate-45 border-[1.5px] border-current" />
        <span className="absolute h-[1.5px] w-3.5 rotate-45 bg-current" />
      </span>
    );
  }
  return (
    <span className="inline-flex size-3 items-center justify-center">
      <span className={`size-2 rounded-full ${DOT[s]}`} />
    </span>
  );
}

type LinkKind = "solid" | "dashed" | "cut" | "dead";

function Link({ kind }: { kind: LinkKind }) {
  if (kind === "cut") {
    return (
      <div className="relative flex h-3 items-center">
        <div className="h-px flex-1 bg-current opacity-50" />
        <span className="px-1">
          <svg width="9" height="9" viewBox="0 0 10 10" aria-hidden>
            <path d="M1 1l8 8M9 1 1 9" stroke="currentColor" strokeWidth="1.6" />
          </svg>
        </span>
        <div className="h-px flex-1 bg-current opacity-50" />
      </div>
    );
  }
  if (kind === "dead") {
    // A rule that runs into a stop and goes no further: traffic arrives at the
    // tunnel and is dropped there.
    return (
      <div className="relative flex h-3 items-center">
        <div className="h-px flex-1 bg-current opacity-60" />
        <span className="h-3 w-[3px] rounded-sm bg-current" />
      </div>
    );
  }
  return (
    <div className="flex h-3 items-center">
      <div
        className={`h-px w-full ${
          kind === "dashed"
            ? "border-t border-dashed border-current opacity-60"
            : "bg-current opacity-40"
        }`}
      />
    </div>
  );
}

/** The chain. Four markers on a shared baseline, labels centred beneath them,
 *  and — in the leak state only — the bypass elbow that says where the traffic
 *  is really going. Pure CSS grid: no SVG viewBox to scale, so it stays sharp
 *  and legible from 320px up. */
export function PathChain({
  level,
  capture,
}: {
  level: Level;
  capture: Capture;
}) {
  const L = LEVEL[level];

  // Off: there is no four-stop path to draw. Showing the tunnel and exit greyed
  // out implies they are part of a route that merely isn't lit; the truth is
  // simpler and worth saying plainly — LAN straight to the uplink. This holds
  // whether or not the capture is still installed, because with the VPN off
  // sing-box dials those connections out directly anyway.
  if (level === "off") {
    return (
      <div className="max-w-[26rem] text-inert">
        <div className="grid grid-cols-[auto_1fr_auto] items-center">
          <Marker s="on" />
          <Link kind="solid" />
          <Marker s="on" />
        </div>
        <div className="grid grid-cols-[auto_1fr_auto]">
          {["lan", "direct", "wan"].map((t, i) => (
            <div key={t} className="relative h-4">
              <span
                className={`lbl absolute left-1/2 top-1 -translate-x-1/2 ${
                  i === 1 ? "txt-faint" : ""
                }`}
              >
                {t}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const unk = level === "unknown";
  const leaking = level === "alarm";
  const dead = level === "caution";

  const nodes: { key: string; label: string; s: NodeState }[] = [
    { key: "lan", label: "LAN", s: "on" },
    {
      key: "cap",
      label: "capture",
      s: unk ? "unknown" : capture ? "on" : "bad",
    },
    { key: "tun", label: "tunnel", s: dead ? "bad" : leaking ? "idle" : "on" },
    {
      key: "exit",
      label: "exit",
      s: leaking || dead ? "off" : unk ? "idle" : "on",
    },
  ];

  const links: LinkKind[] = unk
    ? ["dashed", "dashed", "dashed"]
    : leaking
      ? ["cut", "solid", "solid"]
      : dead
        ? ["solid", "dead", "solid"]
        : ["solid", "solid", "solid"];

  return (
    // Capped width: stretched to a 5xl panel the chain reads as a ruler with
    // four ticks rather than a route with four stops. ~26rem keeps the nodes
    // close enough to be seen as one object, and it is also the width it has on
    // a phone, so the shape does not change between devices.
    <div className={`max-w-[26rem] ${L.tone}`}>
      <div className="grid grid-cols-[auto_1fr_auto_1fr_auto_1fr_auto] items-center">
        {nodes.map((n, i) => (
          <div key={n.key} className="contents">
            <Marker s={n.s} />
            {i < 3 && <Link kind={links[i]} />}
          </div>
        ))}
      </div>
      <div className="grid grid-cols-[auto_1fr_auto_1fr_auto_1fr_auto]">
        {nodes.map((n, i) => (
          <div key={n.key} className="contents">
            <div className="relative h-4">
              <span
                className={`lbl absolute left-1/2 top-1 -translate-x-1/2 whitespace-nowrap ${
                  n.s === "off"
                    ? "txt-faint"
                    : n.s === "idle"
                      ? "txt-faint"
                      : ""
                }`}
              >
                {n.label}
              </span>
            </div>
            {i < 3 && <div />}
          </div>
        ))}
      </div>

      {/* The wrong path — the branch that leaves the LAN without ever touching
          the tunnel. Only drawn when it is real. This is the whole direction in
          one element: you do not read that traffic is bypassing the capture,
          you see the line go around it. */}
      {leaking && (
        <>
          <div className="mt-1 flex h-4 items-stretch">
            <div className="ml-[5px] w-24 rounded-bl-[5px] border-b-[1.5px] border-l-[1.5px] border-current" />
            <div className="flex flex-1 items-end">
              <div className="mb-[-1.5px] h-[1.5px] flex-1 bg-current" />
              <svg
                width="7"
                height="9"
                viewBox="0 0 7 9"
                className="mb-[-5px]"
                aria-hidden
              >
                <path d="M0 0l7 4.5L0 9z" fill="currentColor" />
              </svg>
            </div>
          </div>
          <div className="mt-1 text-right">
            <span className="lbl text-alarm">wan · in the clear</span>
          </div>
        </>
      )}
      {dead && (
        <div className="mt-2 text-center">
          <span className="lbl text-caution">
            diverted · dropped · nothing reaches the uplink
          </span>
        </div>
      )}
    </div>
  );
}

export interface StatusPathProps {
  h: Health;
  capture: Capture;
  ageMs: number | null;
  stale: boolean;
  /** Intent — the switch is the only thing on this page allowed to read it. */
  vpnOn: boolean;
  applying: boolean;
  /** Server selection — what the user picked, not a claim that it carries anything. */
  server: { name: string; sub: string; type: string; ms: number | null } | null;
  exit: { ip: string; country?: string } | null;
  busy: boolean;
  onToggle: (v: boolean) => void;
  onAction: (kind: ActionKind) => void;
}

export function StatusPath({
  h,
  capture,
  ageMs,
  stale,
  vpnOn,
  applying,
  server,
  exit,
  busy,
  onToggle,
  onAction,
}: StatusPathProps) {
  const L = LEVEL[h.level];
  const Glyph = GLYPHS[L.glyph];

  return (
    // The whole point of this card is a claim about the user's traffic, and it
    // was announced to nobody: a screen reader got no notification when the LAN
    // started leaking, because the claim is an <h1> whose text is swapped in
    // place inside an unnamed <section>. The restart chip *was* announced,
    // which made the omission exact — the transient was spoken and the leak was
    // silent. `assertive` rather than `polite` for the loud levels only: an
    // exposed LAN interrupts, a settled one does not.
    <section
      aria-labelledby="kw-claim"
      role={h.loud ? "alert" : "status"}
      aria-live={h.loud ? "assertive" : "polite"}
      className={`overflow-hidden rounded-box border ${L.edge} ${L.fill}`}
    >
      <div
        className={`h-[3px] w-full ${h.level === "off" ? "bg-base-300" : "bg-current"} ${L.tone}`}
      />
      <div className="p-4 sm:p-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
              <span className={`inline-flex items-center gap-1.5 ${L.tone}`}>
                <Glyph size={15} />
                <span className="lbl font-semibold">{h.code}</span>
              </span>
              <Freshness ageMs={ageMs} stale={stale} />
            </div>
            {/* The claim gets the display size. Not the word "Connected" — the
                sentence, because the sentence is the thing that can be wrong. */}
            <h1
              id="kw-claim"
              className="mt-2 max-w-[36ch] text-read font-semibold leading-[1.25] tracking-[-0.01em] sm:text-display"
            >
              {h.claim}
            </h1>
            <p className="mt-2 max-w-[62ch] text-body leading-relaxed txt-muted">
              {h.detail}
            </p>
          </div>
          <VpnSwitch
            on={vpnOn}
            applying={applying}
            disabled={busy || (!server && !vpnOn)}
            onChange={onToggle}
          />
        </div>

        <div className="mt-5 grid items-start gap-x-8 gap-y-5 border-t border-base-content/10 pt-4 sm:grid-cols-[minmax(0,25rem)_1fr]">
          <div className="px-2 sm:px-4">
            <PathChain level={h.level} capture={capture} />
          </div>

          <div className="sm:pt-1">
            <KeyRow k="server">
              {server ? (
                // `<bdi>` around every remote string. This row concatenates
                // three of them with " · " and a protocol name, and an RTL
                // server name swallowed the separator and the label after it
                // into one right-to-left run — so "name · subscription VLESS"
                // rendered in an order that says something else.
                <>
                  <span className="font-medium">
                    <bdi>{server.name}</bdi>
                  </span>
                  <span className="txt-faint">
                    {" · "}
                    <bdi>{server.sub}</bdi>
                  </span>
                  <span className="lbl ml-2 txt-faint">
                    <bdi>{server.type}</bdi>
                  </span>
                  {server.ms != null && (
                    <span className="tnum ml-2 txt-muted">
                      {server.ms} ms
                    </span>
                  )}
                </>
              ) : (
                <span className="txt-faint">none selected</span>
              )}
            </KeyRow>
            <KeyRow k="exit">
              {exit ? (
                // Monochrome, always. The study flagged an exit IP equal to the
                // user's own ISP address in alarm red, but nothing on the wire
                // says whose address it is: /api/exit-ip returns {ip, country}
                // from a trace endpoint and the daemon never records the WAN
                // address to compare it against. The path drawing above is
                // already making the claim, from evidence that exists.
                <span className="tnum">
                  {exit.ip}
                  {exit.country && (
                    <span className="ml-2 txt-faint">
                      {exit.country}
                    </span>
                  )}
                </span>
              ) : (
                <span className="txt-faint">—</span>
              )}
            </KeyRow>
          </div>
        </div>

        {h.action && !applying && (
          <div className="mt-4 flex flex-wrap gap-2">
            <ActionButton
              tone={
                h.level === "secure" || h.level === "off"
                  ? "neutral"
                  : (h.level as "alarm" | "caution" | "unknown")
              }
              disabled={busy}
              onClick={() => onAction(h.action!.kind)}
            >
              {h.action.label}
            </ActionButton>
            {h.level === "alarm" && (
              <ActionButton disabled={busy} onClick={() => onToggle(false)}>
                turn vpn off
              </ActionButton>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
