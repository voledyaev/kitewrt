import { useEffect, useRef, useState } from "react";
import { api, DEFAULT_DIRECT_DNS, DEFAULT_DOH_URL } from "../api";
import { useStore } from "../store";
import { fmtRelative, fmtTime, maskedSource } from "../format";
import { ActionButton, Panel } from "./parts";
import { Actions, Field, Reveal, TextInput, useConfirm } from "./ui";

function DnsCard() {
  const { state, run, busy } = useStore();
  const dns = state!.dns;
  const [doh, setDoh] = useState(dns.doh_url);
  const [direct, setDirect] = useState(dns.direct_dns || "");
  const busyOrApplying = busy || state!.applying;
  const dirty =
    doh.trim() !== dns.doh_url || direct.trim() !== (dns.direct_dns || "");
  // From what is *saved*, not from what is typed. It read the drafts, so typing
  // the defaults into the two boxes greyed out "Reset to Cloudflare" while the
  // router was still configured with something else — the button reported the
  // contents of the form as though it were the state of the daemon.
  const isDefault =
    dns.doh_url === DEFAULT_DOH_URL &&
    (dns.direct_dns || "") === DEFAULT_DIRECT_DNS;

  // Adopt a change that came from somewhere else — another browser on the LAN,
  // a second tab, the daemon's own defaults after a reset — but only into boxes
  // the user has not touched. The inputs used to be seeded once at mount and
  // never again, so a change underneath left the form holding the old value,
  // `dirty` went true on its own, and Save wrote the stale value back over the
  // new one. `seen` is what the daemon last told us, so "untouched" is a
  // comparison against that rather than against the value we are adopting.
  const seen = useRef({ doh: dns.doh_url, direct: dns.direct_dns || "" });
  useEffect(() => {
    const next = { doh: dns.doh_url, direct: dns.direct_dns || "" };
    const prev = seen.current;
    if (next.doh === prev.doh && next.direct === prev.direct) return;
    seen.current = next;
    setDoh((cur) => (cur === prev.doh ? next.doh : cur));
    setDirect((cur) => (cur === prev.direct ? next.direct : cur));
  }, [dns.doh_url, dns.direct_dns]);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!doh.trim()) return;
    await run(() => api.setDns(doh.trim(), direct.trim()));
  };
  const reset = async () => {
    setDoh(DEFAULT_DOH_URL);
    setDirect(DEFAULT_DIRECT_DNS);
    await run(() => api.setDns(DEFAULT_DOH_URL, DEFAULT_DIRECT_DNS));
  };

  return (
    <Panel label="dns">
      <p className="mb-4 max-w-[70ch] text-body leading-relaxed txt-muted">
        Two resolvers, both defaulting to Cloudflare.{" "}
        <span className="text-base-content/80">Foreign</span> (proxy-routed)
        names resolve over encrypted DoH inside the tunnel;{" "}
        <span className="text-base-content/80">direct</span> (home/LAN) names
        resolve through a plain resolver on the direct path. If you rely on
        region-specific GeoDNS, point direct at a resolver in that region — it
        must not be this router's own resolver, which loops back through the
        tunnel.
      </p>
      <form onSubmit={save} className="max-w-xl space-y-3.5">
        <Field
          label="foreign dns"
          hint="A DoH URL. It must be an IP literal, not a hostname — the router dials this to resolve the proxy servers' own names, so a hostname here would itself need resolving."
        >
          <TextInput
            mono
            type="url"
            value={doh}
            onChange={(e) => setDoh(e.target.value)}
            placeholder={DEFAULT_DOH_URL}
            disabled={busyOrApplying}
          />
        </Field>
        <Field
          label="direct dns"
          hint="A resolver IP. Empty falls back to the system default."
        >
          <TextInput
            mono
            type="text"
            inputMode="numeric"
            value={direct}
            onChange={(e) => setDirect(e.target.value)}
            placeholder={DEFAULT_DIRECT_DNS}
            disabled={busyOrApplying}
          />
        </Field>
        <Actions>
          <ActionButton
            type="submit"
            tone="primary"
            busy={busy}
            disabled={busyOrApplying || !doh.trim() || !dirty}
          >
            save
          </ActionButton>
          <ActionButton
            disabled={busyOrApplying || isDefault}
            onClick={reset}
            title={
              isDefault ? "Already the default" : "Write both Cloudflare defaults"
            }
          >
            reset to cloudflare
          </ActionButton>
        </Actions>
      </form>
    </Panel>
  );
}

/** What the rules document became.
 *
 *  Two of these numbers are claims about where traffic goes, and neither was
 *  saying so. `bypass_address` is the count of networks that deliberately do
 *  NOT enter the tunnel, and it was captioned with a tooltip about the hardware
 *  fast path — true, and the wrong half of the sentence for a page about
 *  whether your traffic is protected. `rules_skipped_count` is the number of
 *  rules the validator threw away, rendered as a bare amber "37 skipped" with
 *  no way to find out which; the daemon keeps a 25-entry sample in
 *  `rules_warnings` and shipped it in every state frame for nobody. */
function RuleCount({
  n,
  one,
  many,
  title,
}: {
  n: number;
  one: string;
  many: string;
  title?: string;
}) {
  return (
    <span className="lbl txt-faint" title={title}>
      <span className="tnum text-base-content/80">{n}</span>{" "}
      {n === 1 ? one : many}
    </span>
  );
}

function RulesCard() {
  const { state, run, busy, clock } = useStore();
  const { confirm, element: confirmEl } = useConfirm();
  const [url, setUrl] = useState("");
  const [showWarnings, setShowWarnings] = useState(false);
  const busyOrApplying = busy || state!.applying;
  const hasRules = !!state!.rules_url;
  const warnings = state!.rules_warnings ?? [];
  const skipped = state!.rules_skipped_count;

  const resetToDefault = async () => {
    const ok = await confirm({
      title: "Drop this rules document?",
      body: (
        <>
          Everything goes back through the tunnel — including the{" "}
          <span className="tnum">{state!.rules_bypass_count}</span> network
          {state!.rules_bypass_count === 1 ? "" : "s"} currently kept out of it.
          That is more traffic protected and, on this hardware, noticeably less
          of it offloaded.
        </>
      ),
      confirmLabel: "Reset to default",
      danger: false,
    });
    if (ok) run(() => api.setRulesUrl(null));
  };

  return (
    <Panel label="routing rules">
      {hasRules ? (
        <div className="space-y-3">
          <Reveal
            what="rules URL"
            value={state!.rules_url}
            masked={maskedSource(state!.rules_url)}
          />
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
            <span className="lbl txt-faint" title={fmtTime(state!.rules_fetched_at)}>
              fetched {fmtRelative(state!.rules_fetched_at, clock)}
            </span>
            <RuleCount n={state!.rules_count} one="rule" many="rules" />
            {state!.rule_sets_count > 0 && (
              <RuleCount
                n={state!.rule_sets_count}
                one="rule-set"
                many="rule-sets"
              />
            )}
          </div>

          {/* Given its own line and its own sentence, because it is the one
              setting on this page that decides what is not protected. */}
          {state!.rules_bypass_count > 0 && (
            <p className="max-w-[70ch] rounded-field border border-base-300 bg-base-100/60 px-3 py-2 text-body txt-muted">
              <span className="tnum font-semibold text-base-content/80">
                {state!.rules_bypass_count}
              </span>{" "}
              network{state!.rules_bypass_count === 1 ? "" : "s"} bypass the
              tunnel. Traffic to them leaves through your ISP in the clear and
              stays on the router's hardware fast path — which is the point, but
              it is also the part of your traffic the dashboard's{" "}
              <span className="lbl">through the tunnel</span> figure is
              measuring against.
            </p>
          )}

          {skipped > 0 && (
            <div className="rounded-field border border-base-300 bg-base-100/60 px-3 py-2">
              <p className="max-w-[70ch] text-body txt-muted">
                <span className="lbl mr-2 text-base-content">
                  {skipped} rule{skipped === 1 ? "" : "s"} skipped
                </span>
                They failed validation and were dropped, so this router is
                routing by the rest. Whatever they were meant to do is not
                happening.
              </p>
              {warnings.length > 0 && (
                <>
                  <button
                    type="button"
                    className="lbl mt-1.5 txt-muted hover:text-base-content"
                    aria-expanded={showWarnings}
                    onClick={() => setShowWarnings((s) => !s)}
                  >
                    {showWarnings ? "hide" : "show"}{" "}
                    {warnings.length === skipped
                      ? "what was dropped"
                      : `a sample of ${warnings.length}`}
                  </button>
                  {showWarnings && (
                    // Scrolls rather than growing: the daemon keeps up to 25 and
                    // they are one long line each, which pushed the buttons on
                    // this card off the bottom of a phone.
                    <ul className="mt-2 max-h-56 space-y-1 overflow-y-auto rounded border border-base-300 bg-base-200 p-2">
                      {warnings.map((w, i) => (
                        <li
                          key={i}
                          className="break-words font-mono text-micro txt-muted"
                        >
                          {/* Remote text, straight out of a rules document. */}
                          <bdi>{w}</bdi>
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              )}
            </div>
          )}

          <Actions>
            <ActionButton disabled={busyOrApplying} onClick={() => run(() => api.refreshRules())}>
              refresh rules
            </ActionButton>
            <ActionButton disabled={busyOrApplying} onClick={resetToDefault}>
              reset to default
            </ActionButton>
          </Actions>
        </div>
      ) : (
        <div className="space-y-3.5">
          <p className="max-w-[70ch] text-body leading-relaxed txt-muted">
            No document is loaded, so everything goes through the VPN and only
            private/LAN networks stay direct. Point this at a sing-box
            route-rules JSON document to decide otherwise — including which
            networks bypass the tunnel entirely.
          </p>
          <form
            className="flex max-w-xl flex-wrap items-end gap-2"
            onSubmit={async (e) => {
              e.preventDefault();
              if (!url.trim()) return;
              const { ok } = await run(() => api.setRulesUrl(url.trim()));
              if (ok) setUrl("");
            }}
          >
            <Field label="rules url" className="min-w-[16rem] flex-1">
              <TextInput
                mono
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://…/rules.json"
              />
            </Field>
            <ActionButton
              type="submit"
              tone="primary"
              busy={busy}
              disabled={busyOrApplying || !url.trim()}
            >
              set rules url
            </ActionButton>
          </form>
        </div>
      )}
      {confirmEl}
    </Panel>
  );
}

export function Settings() {
  return (
    <div className="space-y-3.5">
      <DnsCard />
      <RulesCard />
    </div>
  );
}
