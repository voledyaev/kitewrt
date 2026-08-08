import { useMemo, useState } from "react";
import { api } from "../api";
import { useStore } from "../store";
import { useHealth } from "../useHealth";
import type { PingResult, Server, Subscription } from "../types";
import {
  countryCode,
  fmtRelative,
  fmtTime,
  maskedSource,
  pingLabel,
  pingTone,
} from "../format";
import { PathChain } from "./StatusPath";
import { ActionButton, Panel } from "./parts";
import { ActionSep, Actions, Field, Reveal, TextInput, useConfirm } from "./ui";

// Latency is data, and hue is reserved for state — a "fast" server painted the
// same teal as "your traffic is verified captured" makes the palette unable to
// say either thing. The tiles are already sorted by ping, so the ranking is in
// the layout; the number itself is enough.
//
// `down` used to keep `text-alarm`, on the argument that a server which did not
// answer is a state rather than a measurement. It is — but not a state of the
// user's traffic, which is the only thing this palette's one rule lets a hue
// talk about. A subscription where half the nodes are blocked (the ordinary
// case this tool exists for) rendered as a screen of the exact red that means
// "your LAN is on the open internet right now". It now takes the treatment
// `ReachMark` already uses for a failed probe: full contrast, because the
// failure is the row worth noticing, plus the strikethrough it always had.
const PING_TONE: Record<string, string> = {
  fast: "text-base-content/75",
  mid: "txt-muted",
  slow: "txt-faint",
  down: "text-base-content line-through decoration-from-font",
  none: "txt-muted",
};

/** How many tiles a card shows before it asks. A real subscription is 20-200
 *  nodes; at 200 the grid measured 6,453px tall on a laptop and roughly 11,000
 *  on a phone, which put every button on the card — including Delete and the
 *  filter — below all of it, and cost a keyboard user 200 tab stops to reach
 *  the next subscription. */
const COLLAPSED = 24;

/** Long enough that scanning stops working and filtering starts. */
const FILTER_FROM = 12;

// Sort live servers by ascending ping; "down" after them; untested last.
function sortedServers(
  sub: Subscription,
  pings: Record<string, PingResult>,
): Server[] {
  const bucket = (id: string) => {
    const p = pings[id];
    if (!p) return 2;
    if (p.ms === null || p.ms === undefined) return 1;
    return 0;
  };
  return sub.servers
    .map((srv, i) => ({ srv, i }))
    .sort((a, b) => {
      const ba = bucket(a.srv.id);
      const bb = bucket(b.srv.id);
      if (ba !== bb) return ba - bb;
      if (ba === 0) return (pings[a.srv.id].ms ?? 0) - (pings[b.srv.id].ms ?? 0);
      return a.i - b.i;
    })
    .map((x) => x.srv);
}

function matches(srv: Server, q: string): boolean {
  if (!q) return true;
  const n = q.toLowerCase();
  return (
    srv.name.toLowerCase().includes(n) ||
    srv.host.toLowerCase().includes(n) ||
    (srv.country || "").toLowerCase().includes(n) ||
    srv.type.toLowerCase().includes(n)
  );
}

/** Protocol, in the instrument face. Every tile carries one — it used to be a
 *  `HY2` badge on hysteria2 nodes and nothing at all on the rest, so the
 *  presence of the chip encoded the protocol and its absence encoded a
 *  different one, which only reads if you already know the list. */
function protoLabel(type: string): string {
  const t = (type || "").toLowerCase();
  if (t === "hysteria2") return "hy2";
  // Remote-derived: the parser emits a fixed set, but nothing on the wire
  // guarantees it, and this string is rendered inside a fixed-width chip.
  return t.slice(0, 9);
}

function ServerTile({
  subId,
  srv,
  active,
}: {
  subId: string;
  srv: Server;
  active: boolean;
}) {
  const { state, run, busy } = useStore();
  if (!state) return null;
  const busyOrApplying = busy || state.applying;
  const ping = state.pings[srv.id];
  const cc = countryCode(srv.country);
  return (
    <button
      type="button"
      // A radio-like choice: exactly one server in the whole app is active, and
      // the only thing that said so was a coloured dot. A screen reader was
      // read the name, the host and the latency of the server carrying the
      // user's traffic with nothing to distinguish it from the other 199.
      aria-pressed={active}
      disabled={busyOrApplying}
      onClick={() => !active && run(() => api.pickServer(subId, srv.id))}
      className={`flex flex-col items-start overflow-hidden rounded-field border p-3 text-left transition disabled:opacity-60 ${
        active
          ? "border-primary bg-primary/10"
          : "border-base-300 bg-base-100 hover:border-primary/50 hover:bg-base-300/30"
      }`}
    >
      {/* `txt-muted`, not `txt-faint`. The faint step is tuned against the card
          surface; a tile carries its own lighter fill when it is the active one
          (`bg-primary/10`), and measured there the country code came out at
          4.48 — just under AA, on the tile that matters most. */}
      <div className="flex w-full items-center gap-1.5">
        <span className="lbl txt-muted">{cc || "··"}</span>
        <span className="lbl rounded-[3px] border border-base-300 px-1 py-px txt-muted">
          {protoLabel(srv.type)}
        </span>
        {active && (
          // Text, not only the dot: this is the one tile that says where the
          // user's traffic is going, and it has to survive greyscale.
          //
          // Filled rather than `text-primary`: the tile it sits on carries a
          // `bg-primary/10` wash, and blue-on-that measured 4.25 in the light
          // theme — under AA, on the one marker that has to be unambiguous.
          // The filled pair is the theme's own primary/primary-content, the
          // same combination the Fastest button uses.
          <span className="lbl ml-auto rounded-[3px] bg-primary px-1 py-px font-semibold text-primary-content">
            active
          </span>
        )}
      </div>
      {/* Both come straight out of a subscription body — the name from a
          `#fragment` the provider controls. Isolated so an RTL one cannot
          reorder the tile around it. */}
      <div className="mt-1.5 w-full truncate text-body font-medium">
        <bdi>{srv.name}</bdi>
      </div>
      <div className="w-full truncate text-meta txt-muted">
        <bdi>{srv.host}</bdi>
      </div>
      <div className={`tnum mt-1.5 text-meta ${PING_TONE[pingTone(ping)]}`}>
        {pingLabel(ping) || " "}
      </div>
    </button>
  );
}

function SubscriptionCard({ sub }: { sub: Subscription }) {
  const {
    state,
    run,
    busy,
    testSubscription,
    testingSubId,
    autoSelect,
    autoSelectingSubId,
    clock,
  } = useStore();
  const { confirm, element: confirmEl } = useConfirm();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(sub.label);
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState(false);
  // A failed refresh is a durable fact about this subscription — the provider
  // is blocked, the URL rotated, the token expired — and its only channel was
  // a toast that the user can dismiss and that the silent 10 s poll never
  // repeats. The list on screen then goes on looking like an answer. Kept in
  // component state on purpose: it is a record of something that happened in
  // *this* session, and inventing a persisted field for it would be claiming
  // the daemon told us something it did not.
  //
  // Stamped with the `fetched_at` it was recorded against, so the daemon's own
  // 6-hourly re-fetch retires it: once newer servers have landed the note is
  // describing a list that is no longer on screen.
  const [failed, setFailed] = useState<{ since: string; msg: string } | null>(
    null,
  );

  const servers = useMemo(
    () => (state ? sortedServers(sub, state.pings) : []),
    [sub, state],
  );
  const shown = useMemo(
    () => servers.filter((s) => matches(s, query.trim())),
    [servers, query],
  );
  if (!state) return null;

  const busyOrApplying = busy || state.applying;
  const testing = testingSubId === sub.id;
  const autoSelecting = autoSelectingSubId === sub.id;
  // Test and Fastest both delay-probe every server; keep them mutually
  // exclusive so a user can't fire two ranking storms at one subscription.
  const ranking = testing || autoSelecting;
  const empty = sub.servers.length === 0;
  const a = state.active_server;
  const activeId = a && a.subscription_id === sub.id ? a.server_id : null;
  const activeServer = activeId
    ? sub.servers.find((s) => s.id === activeId)
    : undefined;
  const visible = expanded ? shown : shown.slice(0, COLLAPSED);
  const hidden = shown.length - visible.length;

  const startRename = () => {
    setDraft(sub.label);
    setEditing(true);
  };
  const cancelRename = () => setEditing(false);
  const saveRename = async () => {
    const next = draft.trim();
    if (!next || next === sub.label) {
      setEditing(false);
      return;
    }
    const { ok } = await run(() => api.renameSubscription(sub.id, next));
    if (ok) setEditing(false);
  };

  const refresh = async () => {
    const { ok, error } = await run(() => api.refreshSubscription(sub.id));
    setFailed(ok ? null : { since: sub.fetched_at, msg: error });
  };

  const del = async () => {
    const clears = !!activeId;
    const ok = await confirm({
      // FSI/PDI: the string form of <bdi>, because this label is embedded in a
      // sentence rather than rendered on its own. Without it an RTL label drags
      // the quote and the question mark to the wrong end.
      title: `Delete "⁨${sub.label}⁩"?`,
      body: clears
        ? "The active server is in this subscription, so the VPN will be turned off and traffic will go straight out until you pick another one."
        : undefined,
      confirmLabel: "Delete",
    });
    if (ok) run(() => api.deleteSubscription(sub.id));
  };

  return (
    <Panel
      title={
        editing ? (
          <span className="flex flex-wrap items-center gap-2">
            <TextInput
              autoFocus
              aria-label="Subscription name"
              className="input-sm max-w-xs"
              value={draft}
              maxLength={100}
              disabled={busyOrApplying}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") saveRename();
                if (e.key === "Escape") cancelRename();
              }}
            />
            <ActionButton
              tone="primary"
              disabled={busyOrApplying}
              onClick={saveRename}
            >
              save
            </ActionButton>
            <ActionButton onClick={cancelRename}>cancel</ActionButton>
          </span>
        ) : (
          <bdi>{sub.label}</bdi>
        )
      }
      meta={
        <div className="space-y-1.5">
          <div className="lbl flex flex-wrap items-center gap-x-2 gap-y-1 txt-faint">
            <span className="tnum">
              {sub.servers.length} server{sub.servers.length !== 1 && "s"}
            </span>
            <span aria-hidden>·</span>
            <span title={fmtTime(sub.fetched_at)}>
              fetched {fmtRelative(sub.fetched_at, clock)}
            </span>
            {/* Which server this subscription is feeding the tunnel, said in
                one place that no filter or collapse can hide. */}
            {activeId && (
              <>
                <span aria-hidden>·</span>
                <span className="text-primary">
                  active{" "}
                  <span className="font-semibold normal-case tracking-normal">
                    <bdi>{activeServer?.name ?? activeId}</bdi>
                  </span>
                </span>
              </>
            )}
          </div>
          <Reveal
            what="subscription source"
            value={sub.source}
            masked={maskedSource(sub.source)}
          />
        </div>
      }
      right={
        <Actions>
          <ActionButton
            tone="primary"
            disabled={busyOrApplying || ranking || empty}
            busy={autoSelecting}
            title="Delay-test every server through the proxy and switch to the fastest"
            onClick={() => autoSelect(sub.id)}
          >
            {autoSelecting ? "finding…" : "fastest"}
          </ActionButton>
          <ActionButton
            // Was enabled with no servers, where the daemon answers 400
            // "subscription has no servers" — a button whose only outcome is
            // an error toast.
            disabled={busyOrApplying || ranking || empty}
            busy={testing}
            onClick={() => testSubscription(sub.id)}
          >
            {testing ? "testing…" : "test"}
          </ActionButton>
          <ActionButton disabled={busyOrApplying} onClick={refresh}>
            refresh
          </ActionButton>
          <ActionButton
            disabled={busyOrApplying || editing}
            onClick={startRename}
          >
            rename
          </ActionButton>
          <ActionSep />
          <ActionButton disabled={busyOrApplying} onClick={del}>
            delete
          </ActionButton>
        </Actions>
      }
    >
      {failed && failed.since === sub.fetched_at && (
        <p className="mb-3 rounded-field border border-base-content/25 px-3 py-2 text-body txt-muted">
          <span className="lbl mr-2 text-base-content">refresh failed</span>
          <bdi>{failed.msg}</bdi> — the {sub.servers.length} server
          {sub.servers.length !== 1 && "s"} below are from{" "}
          {fmtRelative(sub.fetched_at, clock)}, not from now.
        </p>
      )}

      {empty ? (
        <p className="text-body txt-muted">
          This subscription has no servers. Nothing in it can carry traffic —
          refresh it, or delete the entry.
        </p>
      ) : (
        <>
          {servers.length > FILTER_FROM && (
            <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-2">
              <TextInput
                type="search"
                aria-label={`Filter the ${servers.length} servers in ${sub.label}`}
                placeholder="filter by name, country, host…"
                className="input-sm max-w-xs"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <span className="lbl tnum txt-faint" aria-live="polite">
                {shown.length} of {servers.length}
              </span>
            </div>
          )}
          {shown.length === 0 ? (
            <p className="text-body txt-muted">
              No server here matches <bdi>{query.trim()}</bdi>.
            </p>
          ) : (
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
              {visible.map((srv) => (
                <ServerTile
                  key={srv.id}
                  subId={sub.id}
                  srv={srv}
                  active={srv.id === activeId}
                />
              ))}
            </div>
          )}
          {hidden > 0 && (
            <button
              type="button"
              className="lbl mt-3 txt-muted hover:text-base-content"
              onClick={() => setExpanded(true)}
            >
              show {hidden} more →
            </button>
          )}
          {expanded && shown.length > COLLAPSED && (
            <button
              type="button"
              className="lbl mt-3 txt-muted hover:text-base-content"
              onClick={() => setExpanded(false)}
            >
              ← show fewer
            </button>
          )}
        </>
      )}
      {confirmEl}
    </Panel>
  );
}

export function AddSubscriptionForm({ onDone }: { onDone?: () => void }) {
  const { run, busy, state } = useStore();
  const [label, setLabel] = useState("");
  const [source, setSource] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const src = source.trim();
    if (!src) return;
    const { ok } = await run(async () => {
      const s = await api.addSubscription(label.trim(), src);
      // Convenience onboarding: auto-pick the first server if none is active.
      // It does NOT turn the VPN on — the dashboard the user lands on says
      // plainly that nothing is protected yet and offers the switch.
      if (!s.active_server) {
        const added = s.subscriptions[s.subscriptions.length - 1];
        if (added && added.servers.length > 0) {
          return api.pickServer(added.id, added.servers[0].id);
        }
      }
      return s;
    });
    if (ok) {
      setLabel("");
      setSource("");
      onDone?.();
    }
  };

  return (
    <form onSubmit={submit} className="space-y-3.5">
      <Field label="source" hint="Stored on this router. It never leaves it.">
        <TextInput
          mono
          value={source}
          onChange={(e) => setSource(e.target.value)}
          placeholder="https://… subscription URL, or a vless:// link pasted directly"
          required
        />
      </Field>
      <Field label="label" hint="Optional — defaults to the source hostname.">
        <TextInput
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="A short name for this subscription"
          maxLength={100}
        />
      </Field>
      <Actions>
        <ActionButton
          type="submit"
          tone="primary"
          busy={busy}
          disabled={state?.applying || !source.trim()}
        >
          add subscription
        </ActionButton>
        {onDone && (
          <ActionButton disabled={busy} onClick={onDone}>
            cancel
          </ActionButton>
        )}
      </Actions>
    </form>
  );
}

export function SubscriptionsSection() {
  const { state } = useStore();
  const [adding, setAdding] = useState(false);
  if (!state) return null;
  return (
    <div className="space-y-3.5">
      {state.subscriptions.map((sub) => (
        <SubscriptionCard key={sub.id} sub={sub} />
      ))}
      <Panel label={adding ? "new subscription" : undefined}>
        {adding ? (
          <AddSubscriptionForm onDone={() => setAdding(false)} />
        ) : (
          <ActionButton onClick={() => setAdding(true)}>
            + add subscription
          </ActionButton>
        )}
      </Panel>
    </div>
  );
}

/** The empty state is the only screen where this product gets to say what it
 *  is, and the previous one ("Get started · Add your first VLESS subscription
 *  to begin.") spent it on an instruction. It should spend it on the claim —
 *  and, being honest, on the fact that nothing is protected yet.
 *
 *  It is also the one screen that used to make that claim on its own authority.
 *  App renders it whenever there are no subscriptions, and it hardcoded "no
 *  tunnel configured / Nothing is protected yet" plus the `off` chain — so a
 *  router reporting `vpn_on: true` with a live capture was told the exact
 *  opposite of what health.ts had concluded, with the status pill, the tabs,
 *  the dashboard and the VPN switch all hidden behind it. App now refuses to
 *  route here unless health agrees (see `showOnboarding`), and this component
 *  refuses to draw the chain from anything but the real verdict, so neither
 *  half can drift on its own. */
export function Onboarding() {
  const { h, capture } = useHealth();
  return (
    <div className="mx-auto max-w-2xl">
      <section className="rounded-box border border-base-300 bg-base-200 p-5 sm:p-7">
        <div className="lbl text-inert">no tunnel configured</div>
        <h1 className="mt-2 text-read font-semibold leading-[1.25] tracking-[-0.01em] sm:text-display">
          Nothing is protected yet.
        </h1>
        <p className="mt-2.5 max-w-[58ch] text-body leading-relaxed txt-muted">
          KiteWrt diverts every packet leaving this LAN into a tunnel you
          choose, and tells you plainly when it stops doing that. Right now it
          is forwarding your traffic the way any router would — in the clear.
        </p>

        <div className="mt-5 rounded-field border border-base-300 bg-base-100/60 p-4">
          <PathChain level={h.level} capture={capture} />
        </div>

        <p className="mt-5 text-body txt-muted">
          The source can be an HTTP(S) URL to a subscription list, or a single{" "}
          <code className="rounded bg-base-300/60 px-1 py-0.5 font-mono text-micro">
            vless://
          </code>{" "}
          link pasted directly.
        </p>
        <div className="mt-4">
          <AddSubscriptionForm />
        </div>
      </section>
    </div>
  );
}
