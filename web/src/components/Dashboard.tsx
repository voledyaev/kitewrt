import { useEffect, useState } from "react";
import { api } from "../api";
import { useStore } from "../store";
import { useHealth } from "../useHealth";
import {
  CAPTURE_GAP_MSG,
  CAPTURE_LOST_MSG,
  type ActionKind,
} from "../health";
import { fmtBytes, fmtPct, fmtRate, fmtRelative, fmtTemp } from "../format";
import type {
  AppState,
  ConnTarget,
  ExitIp,
  MetricsSample,
  PingResult,
} from "../types";
import { IconCheck, IconCross, IconDash } from "./icons";
import { ActionButton, Banner, GapRecord, Panel, Stat } from "./parts";
import { StatusPath } from "./StatusPath";

// Best-effort public exit IP. Refetches when the VPN toggles (the exit changes)
// and every 30 s; failures just leave it null so the row shows a dash.
function useExitIp(vpnOn: boolean): ExitIp | null {
  const [info, setInfo] = useState<ExitIp | null>(null);
  useEffect(() => {
    let alive = true;
    const timers: ReturnType<typeof setTimeout>[] = [];
    // Clear on failure rather than keeping the last answer. This is the one row
    // on the card that reads as ground truth about egress, and it was the only
    // fact with no freshness beside it — so with the endpoint failing it went on
    // showing the tunnel's exit next to "Your LAN is on the open internet right
    // now". Showing nothing is the honest answer; `received_at` was added to
    // `capture` for exactly this reason.
    const load = () =>
      api
        .getExitIp()
        .then((d) => alive && setInfo(d))
        .catch(() => alive && setInfo(null));
    load(); // immediately on mount / vpn toggle
    // A toggle restarts sing-box and then has to complete a Reality handshake,
    // which does not finish in the couple of seconds a single retry allowed —
    // so the pre-toggle exit stayed on screen for up to the full 30 s poll.
    // Re-check on a short ramp instead. The server keys its cache on vpn_on,
    // so each of these reflects the new tunnel as soon as it is up.
    for (const ms of [1500, 3000, 5000, 8000, 12000, 18000]) {
      timers.push(setTimeout(load, ms));
    }
    const t = setInterval(load, 30000);
    return () => {
      alive = false;
      timers.forEach(clearTimeout);
      clearInterval(t);
    };
  }, [vpnOn]);
  return info;
}

function activeServer(
  state: AppState,
  pings: Record<string, PingResult>,
): { name: string; sub: string; type: string; ms: number | null } | null {
  const a = state.active_server;
  if (!a) return null;
  for (const sub of state.subscriptions) {
    if (sub.id !== a.subscription_id) continue;
    const srv = sub.servers.find((s) => s.id === a.server_id);
    if (srv) {
      return {
        name: srv.name,
        sub: sub.label,
        type: srv.type,
        ms: pings[srv.id]?.ms ?? null,
      };
    }
  }
  // The selection outlived the subscription refresh that removed it. Show the
  // ids rather than "none selected" — the VPN is pointed at this thing.
  return {
    name: a.server_id,
    sub: a.subscription_id,
    type: "",
    ms: pings[a.server_id]?.ms ?? null,
  };
}

/** Highest value in the window, ignoring gaps. This is what the charts were
 *  for: a single instantaneous number cannot tell "steady at 40%" from "idle,
 *  but it just spiked to 90%", and that distinction is the whole reason this
 *  dashboard exists. */
function peakOf(
  hist: MetricsSample[],
  pick: (h: MetricsSample) => number | null | undefined,
) {
  let best: number | null = null;
  for (const h of hist) {
    const v = pick(h);
    if (v != null && Number.isFinite(v) && (best == null || v > best)) best = v;
  }
  return best;
}

function StatRow() {
  const { metrics } = useStore();
  const hist = metrics.history ?? [];
  // `available > total` is not a small memory reading, it is a broken pair —
  // /proc/meminfo scraped mid-write, a target where the two lines mean
  // different things, a hostile daemon. Subtracting them anyway rendered
  // "-400000000 B used of 477 MB", a number that cannot exist. Nothing is the
  // honest answer; the card already knows how to draw a dash.
  const memUsed =
    metrics.mem_total != null &&
    metrics.mem_available != null &&
    metrics.mem_available <= metrics.mem_total
      ? metrics.mem_total - metrics.mem_available
      : null;
  const peakDown = peakOf(hist, (h) => h.wan_down_rate);
  const peakUp = peakOf(hist, (h) => h.wan_up_rate);
  const peakCpu = peakOf(hist, (h) => h.cpu_percent);
  return (
    <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-4">
      {/* WAN, not the sing-box counters. Those only count traffic that reaches
          the proxy — measured on a live router during a bypassed download, 512
          MB crossed the WAN while they moved 1.5 MB. The honest number is the
          one the link actually carried. */}
      <Stat
        label="wan down"
        dir="down"
        value={fmtRate(metrics.wan_down_rate ?? undefined)}
        now={metrics.wan_down_rate ?? null}
        peak={peakDown}
        foot={`peak ${fmtRate(peakDown ?? undefined)} · 30s`}
      />
      <Stat
        label="wan up"
        dir="up"
        value={fmtRate(metrics.wan_up_rate ?? undefined)}
        now={metrics.wan_up_rate ?? null}
        peak={peakUp}
        foot={`peak ${fmtRate(peakUp ?? undefined)} · 30s`}
      />
      <Stat
        label="router cpu"
        value={fmtPct(metrics.cpu_percent)}
        now={metrics.cpu_percent ?? null}
        peak={peakCpu}
        max={100}
        foot={
          <>
            peak {fmtPct(peakCpu)}
            {metrics.temp_c != null && ` · ${fmtTemp(metrics.temp_c)}`}
          </>
        }
      />
      <Stat
        label="memory"
        value={memUsed != null ? fmtBytes(memUsed) : "—"}
        now={memUsed}
        peak={memUsed}
        max={metrics.mem_total ?? null}
        foot={
          metrics.mem_total != null ? `of ${fmtBytes(metrics.mem_total)}` : null
        }
      />
    </div>
  );
}

/** Below the floor the proxied/WAN ratio is meaningless — at a few hundred
 *  bytes a second of background chatter it swings between 0 and 100 on
 *  rounding alone — so it reports nothing rather than noise. */
function tunnelShare(
  proxied: number,
  wan: number,
  vpnOn: boolean,
): number | null {
  if (!vpnOn) return null;
  const FLOOR = 32 * 1024; // bytes/s
  if (wan < FLOOR) return null;
  return Math.round(Math.max(0, Math.min(100, (proxied / wan) * 100)));
}

/** Where traffic goes and how it is handled — all three are properties of the
 *  path, not of a device, so they read as one line rather than as cards. */
function RouteLine() {
  const { state, metrics } = useStore();
  const bound = metrics.offload_bound;
  const vpnOn = state?.vpn_on ?? false;
  const share = metrics.available
    ? tunnelShare(
        (metrics.down_rate ?? 0) + (metrics.up_rate ?? 0),
        (metrics.wan_down_rate ?? 0) + (metrics.wan_up_rate ?? 0),
        vpnOn,
      )
    : null;
  if (bound == null && !metrics.wan_device && share == null) return null;
  // A share claim is a claim about where traffic is going, so it is allowed a
  // hue — but only while the VPN is supposed to be carrying it, and not with an
  // apply in flight: sing-box is restarting, 0% is expected, and an alarm
  // colour there is the boy who cried wolf.
  //
  // And not when the user's own rules document says traffic should be leaving
  // the tunnel. `bypass_address` returns whole networks to normal forwarding
  // before the capture sees them; the owner's document declares 8,640 of them,
  // and a country-sized bypass list is the ordinary configuration for this
  // tool. Under it a share below half is not an anomaly, it is the setting
  // working — so this painted a permanent `text-alarm` on a correctly
  // functioning router, in the one colour reserved for a verified leak. With no
  // bypass networks declared, everything is supposed to be captured and a low
  // share really is worth the hue.
  //
  // Zero is the exception to the exception. A bypass list carves networks out
  // of the capture; it never carves out all of them, so above the measurement
  // floor a flat 0% means nothing whatsoever reached the tunnel, and that is
  // anomalous no matter what the rules document says.
  const bypassing = (state?.rules_bypass_count ?? 0) > 0;
  const anomalous = share === 0 || (share != null && share < 50 && !bypassing);
  const shareTone =
    share != null && anomalous && !state?.applying
      ? "text-alarm"
      : "text-base-content/70";
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1 px-1">
      {metrics.wan_device && (
        <span className="lbl txt-faint">
          uplink{" "}
          <span className="txt-muted">{metrics.wan_device}</span>
        </span>
      )}
      {bound != null && (
        <span
          className="lbl txt-faint"
          title="Flows the router forwards in hardware. Only traffic that never reaches the proxy can be offloaded — anything sing-box terminates is handled in software, at a real CPU cost."
        >
          hw offload{" "}
          <span className="txt-muted">
            {bound > 0 ? `${bound} flow${bound === 1 ? "" : "s"}` : "idle"}
          </span>
        </span>
      )}
      {share != null && (
        <span
          className="lbl txt-faint"
          title={
            bypassing
              ? `Share of the WAN traffic that goes through the tunnel. Your routing rules deliberately keep ${state?.rules_bypass_count} networks out of it, so this is expected to sit below 100%.`
              : "Share of the WAN traffic that goes through the tunnel. Your routing rules bypass no networks, so anything well under 100% is traffic escaping the capture."
          }
        >
          through the tunnel <span className={shareTone}>{share}%</span>
        </span>
      )}
    </div>
  );
}

/** Monochrome, deliberately.
 *
 *  A reachable target is not a claim about the user's traffic. During a leak
 *  every one of these is reachable, fast and ticked — because the internet is
 *  working perfectly, through the ISP — so three `text-secure` ticks could sit
 *  directly under a red LEAKING card, which is the exact misreading the panel's
 *  own right-hand label exists to head off. A state hue here was arguing with
 *  that label in the palette's loudest channel.
 *
 *  The three silhouettes already differ (tick / cross / dash), and prominence
 *  carries the rest: a failed probe is the one worth noticing, so it gets full
 *  contrast, a pass sits a step back, and "not told yet" a step further. */
function ReachMark({ ok }: { ok: boolean | null }) {
  if (ok === true) return <IconCheck size={12} className="txt-muted" />;
  if (ok === false) return <IconCross size={12} className="text-base-content" />;
  return <IconDash size={12} className="txt-faint" />;
}

function Reachability({ leaking }: { leaking: boolean }) {
  const [targets, setTargets] = useState<ConnTarget[] | null>(null);
  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .getConnectivity()
        .then((d) => alive && setTargets(d.targets))
        .catch(() => {});
    load();
    const t = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  // The probe result itself is a strict boolean server-side; the third state
  // here is "we have not been told yet", which is a real thing to say and not
  // the same as "unreachable".
  const rows: { name: string; ok: boolean | null; ms: number | null }[] =
    targets ?? [
      { name: "Google", ok: null, ms: null },
      { name: "Cloudflare", ok: null, ms: null },
      { name: "GitHub", ok: null, ms: null },
    ];
  return (
    <Panel
      label="reachability"
      right={
        // The single most misleading panel on the page during a leak: every
        // target is reachable, fast, and ticked, because the internet is
        // working perfectly — through the ISP. Say so here, where someone
        // reading three ticks would otherwise take them as reassurance.
        <span className={`lbl ${leaking ? "text-alarm" : "txt-faint"}`}>
          {leaking ? "reachable ≠ protected" : "via current path"}
        </span>
      }
    >
      <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-3">
        {rows.map((t) => (
          <div
            key={t.name}
            className="flex items-center gap-2 rounded-field border border-base-300 bg-base-100 px-3 py-2.5"
          >
            <ReachMark ok={t.ok} />
            <span className="text-body">{t.name}</span>
            <span className="tnum lbl ml-auto txt-faint">
              {t.ok == null
                ? "—"
                : t.ok
                  ? t.ms != null
                    ? `${t.ms} ms`
                    : "ok"
                  : "unreachable"}
            </span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function Flows({ leaking }: { leaking: boolean }) {
  const { state, metrics } = useStore();
  const top = metrics.top ?? [];
  const vpnOn = state?.vpn_on ?? false;
  return (
    <Panel
      label="top flows"
      right={
        metrics.connections != null && (
          <span className="tnum lbl txt-faint">
            {metrics.connections} open
          </span>
        )
      }
    >
      {top.length === 0 ? (
        // An empty table is not the same fact in every state, and rendering one
        // "No active flows" for all of them throws away the most damning
        // evidence the dashboard has: an idle proxy underneath a busy uplink.
        leaking ? (
          <p className="py-1 text-body leading-relaxed text-alarm">
            sing-box has no connections at all — while the uplink is moving{" "}
            <span className="tnum font-mono">
              {fmtRate(metrics.wan_down_rate ?? undefined)}
            </span>
            . None of that traffic is reaching the tunnel.
          </p>
        ) : !vpnOn ? (
          <p className="py-1 text-body txt-faint">
            vpn is off — nothing to count
          </p>
        ) : !metrics.available ? (
          <p className="py-1 text-body txt-faint">connecting…</p>
        ) : (
          <p className="py-1 text-body txt-faint">no active flows</p>
        )
      ) : (
        <ul className="space-y-1">
          {top.map((f) => (
            <li
              key={`${f.host}-${f.net ?? ""}`}
              className="flex items-baseline gap-2 py-[3px]"
            >
              <span className="lbl w-8 shrink-0 txt-faint">
                {f.net || ""}
              </span>
              {/* Isolated: a hostname is remote text and an RTL one reorders
                  the row's neighbours around it. */}
              <span className="min-w-0 flex-1 truncate text-body">
                <bdi>{f.host}</bdi>
              </span>
              <span
                className={`lbl shrink-0 rounded-[3px] border px-1.5 py-px ${
                  f.proxied
                    ? "border-secure/40 text-secure"
                    : leaking
                      ? "border-alarm text-alarm"
                      : "border-base-300 txt-faint"
                }`}
              >
                {f.proxied ? "tunnel" : "direct"}
              </span>
              <span className="tnum w-16 shrink-0 text-right font-mono text-meta txt-muted">
                {fmtBytes(f.down)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function Devices({ leaking }: { leaking: boolean }) {
  const { metrics } = useStore();
  const clients = metrics.clients ?? [];
  return (
    <Panel
      label="lan devices"
      right={<span className="lbl txt-faint">proxied only</span>}
    >
      {clients.length === 0 ? (
        leaking ? (
          <p className="py-1 text-body leading-relaxed text-alarm">
            no device is reaching the proxy. Every host on this LAN is talking to
            the internet directly.
          </p>
        ) : (
          <p className="py-1 text-body txt-faint">
            no active devices
          </p>
        )
      ) : (
        <ul className="space-y-1">
          {clients.map((c) => (
            <li key={c.ip} className="flex items-baseline gap-2 py-[3px]">
              <span className="tnum min-w-0 flex-1 truncate font-mono text-body">
                {c.ip}
              </span>
              <span className="tnum w-12 shrink-0 text-right font-mono text-meta txt-faint">
                {c.conns}
              </span>
              <span className="tnum w-16 shrink-0 text-right font-mono text-meta txt-muted">
                {fmtBytes(c.down)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function Dashboard() {
  const { state, metrics, busy, clock, run } = useStore();
  const { h, ageMs, stale, capture } = useHealth();
  const exit = useExitIp(state?.vpn_on ?? false);
  if (!state) return null;

  const leaking = h.level === "alarm";
  const last = state.last_apply;

  // Both watchdog capture events ride on `last_apply`, and only one of them is
  // an apply. Split them back out: the unhealed one is a standing alarm, the
  // self-healed one is a record of a window that already leaked, and a genuine
  // apply failure is neither.
  const lostBanner = state.last_error === CAPTURE_LOST_MSG;
  const healedGap = !!last?.ok && last.msg === CAPTURE_GAP_MSG;
  const applyFailed = !!last && !last.ok && !lostBanner && !state.applying;

  const act = (kind: ActionKind) => {
    // Every one of these is a real apply. `toggleVpn(true)` while already on
    // re-runs the pipeline, which calls `ensure_capture()` unconditionally —
    // that is what "restore" and "re-assert" actually do, and it is why there
    // is no "re-check" button: nothing in the API triggers a read on its own.
    if (kind === "stop") return run(() => api.toggleVpn(false));
    return run(() => api.toggleVpn(true));
  };

  return (
    <div className="space-y-3.5">
      {lostBanner && (
        <Banner
          level="alarm"
          title={CAPTURE_LOST_MSG}
          at={last ? fmtRelative(last.at, clock) : undefined}
          body="The watchdog re-asserted the capture and it did not hold. Until it does, every device on this LAN is reaching the internet through your ISP."
          actions={
            <>
              <ActionButton
                tone="alarm"
                disabled={busy || state.applying}
                onClick={() => act("reassert")}
              >
                Retry now
              </ActionButton>
              <ActionButton
                disabled={busy || state.applying}
                onClick={() => act("stop")}
              >
                Turn VPN off
              </ActionButton>
            </>
          }
        />
      )}
      {healedGap && <GapRecord at={fmtRelative(last!.at, clock)} />}
      {applyFailed && (
        <Banner
          level="caution"
          title="Apply failed"
          at={fmtRelative(last!.at, clock)}
          body={<bdi>{last!.msg || "(no message)"}</bdi>}
        />
      )}

      <StatusPath
        h={h}
        capture={capture}
        ageMs={ageMs}
        stale={stale}
        vpnOn={state.vpn_on}
        applying={state.applying}
        server={activeServer(state, state.pings)}
        exit={exit?.available && exit.ip ? { ip: exit.ip, country: exit.country } : null}
        busy={busy}
        onToggle={(v) => run(() => api.toggleVpn(v))}
        onAction={act}
      />

      {/* Router health is shown whether or not the VPN is on: the CPU and the
          WAN link are just as real either way, and hiding them made the panel
          blank exactly when someone is debugging why they turned it off. */}
      <StatRow />
      <RouteLine />
      <Reachability leaking={leaking} />
      {(state.vpn_on || (metrics.top ?? []).length > 0) && (
        <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-2">
          <Flows leaking={leaking} />
          <Devices leaking={leaking} />
        </div>
      )}
    </div>
  );
}
