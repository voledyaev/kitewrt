// Form primitives + the `useConfirm` hook live together here; the
// "only export components" fast-refresh rule doesn't apply to this kit module.
/* eslint-disable react-refresh/only-export-components */
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ActionButton } from "./parts";

// There is no `Card` any more. It was a second surface with a sans `text-base`
// heading — a size that is not on the declared type scale — and it was the only
// thing Subscriptions and Settings used, which is exactly why those two tabs
// read a half-step behind the dashboard. `Panel` in parts.tsx is the surface.

/** One field. The label is the instrument voice — a short mono machine word,
 *  the same register as the dashboard's panel labels — and anything that needs
 *  a sentence goes in `hint`, underneath, in prose. They used to be one string,
 *  so "Foreign DNS (DoH URL — must be an IP, not a hostname)" was set as a
 *  label: a caveat typeset as a name. */
export function Field({
  label,
  hint,
  children,
  className = "",
}: {
  label: ReactNode;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={`flex flex-col gap-1.5 ${className}`}>
      <span className="lbl txt-faint">{label}</span>
      {children}
      {hint && <span className="text-meta txt-muted">{hint}</span>}
    </label>
  );
}

/** Text input. daisyUI's `input` with the addresses set in mono: every value
 *  typed into one of these is a URL or an IP, and a proportional face turns
 *  `1.1.1.1` into something you have to read twice. */
export function TextInput({
  mono = false,
  className = "",
  ...rest
}: React.InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }) {
  return (
    <input
      {...rest}
      className={`input w-full ${mono ? "tnum font-mono text-body" : ""} ${className}`}
    />
  );
}

// Unified reveal for secret strings — one wording everywhere ("show"/"hide").
// `what` names the thing for a screen reader: the visible word is "show", which
// on its own is an instruction with no object, and the Settings page has two of
// them.
export function Reveal({
  value,
  masked,
  what = "value",
  className = "",
}: {
  value: string;
  masked: string;
  what?: string;
  className?: string;
}) {
  const [shown, setShown] = useState(false);
  return (
    // flex (block-level) + min-w-0 so the revealed value wraps within the
    // container instead of pushing the layout off-screen; masked stays on one
    // truncated line.
    <span className={`flex min-w-0 items-start gap-2 ${className}`}>
      <code
        className={`min-w-0 rounded bg-base-300/60 px-1.5 py-0.5 font-mono text-micro ${
          shown ? "break-all" : "truncate"
        }`}
      >
        {/* Remote text: a subscription source can carry an RTL fragment. */}
        <bdi>{shown ? value : masked}</bdi>
      </code>
      <button
        type="button"
        className="lbl shrink-0 txt-faint hover:text-base-content"
        aria-expanded={shown}
        aria-label={`${shown ? "Hide" : "Show"} the full ${what}`}
        onClick={() => setShown((s) => !s)}
      >
        {shown ? "hide" : "show"}
      </button>
    </span>
  );
}

interface ConfirmOpts {
  title: string;
  body?: ReactNode;
  confirmLabel?: string;
  danger?: boolean; // default true (destructive)
}

// Native <dialog> via showModal() so we get focus trap, focus restore on close,
// and Escape-to-cancel for free. `onResolve` is called exactly once (the Promise
// + setReq are idempotent, but we route everything through the `close` event so
// focus is always restored to the trigger).
function ConfirmDialog({
  title,
  body,
  confirmLabel,
  danger,
  onResolve,
}: ConfirmOpts & { onResolve: (ok: boolean) => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const result = useRef(false);
  const cb = useRef(onResolve);
  useEffect(() => {
    cb.current = onResolve;
  });
  useEffect(() => {
    const dlg = ref.current;
    if (!dlg) return;
    dlg.showModal(); // focuses the autofocus element (Cancel), traps focus
    // Fires for any close path (button .close(), Escape, backdrop) — resolve
    // with whatever the chosen result was (default false = cancel).
    const onClose = () => cb.current(result.current);
    dlg.addEventListener("close", onClose);
    return () => dlg.removeEventListener("close", onClose);
  }, []);

  const close = (ok: boolean) => {
    result.current = ok;
    ref.current?.close(); // → 'close' event → onResolve + focus restore
  };

  return (
    <dialog ref={ref} className="modal">
      <div className="modal-box border border-base-300 bg-base-200">
        <h3 className="text-title font-semibold">{title}</h3>
        {body && <div className="mt-2 text-body txt-muted">{body}</div>}
        <div className="modal-action">
          <button
            type="button"
            autoFocus
            className="lbl inline-flex min-h-9 items-center rounded-field px-3 txt-muted hover:text-base-content"
            onClick={() => close(false)}
          >
            Cancel
          </button>
          {/* Inverted, not `btn-error`. A destructive confirm needs to be the
              heaviest thing in the dialog, but red in this app means "your LAN
              is on the open internet right now" — and it was being spent here,
              and on the Delete button behind this dialog, on every card. The
              inverted fill is the same treatment the VPN switch uses for the
              selected segment, so it is already in the vocabulary and costs no
              state hue. */}
          <button
            type="button"
            className={`lbl inline-flex min-h-9 items-center rounded-field border px-3 transition ${
              danger === false
                ? "border-primary bg-primary text-primary-content hover:bg-primary/85"
                : "border-base-content bg-base-content text-base-100 hover:bg-base-content/85"
            }`}
            onClick={() => close(true)}
          >
            {confirmLabel ?? "Confirm"}
          </button>
        </div>
      </div>
      {/* daisyUI backdrop: clicking it submits method=dialog → closes (cancel) */}
      <form method="dialog" className="modal-backdrop">
        <button aria-label="Cancel">close</button>
      </form>
    </dialog>
  );
}

// In-app replacement for window.confirm: `await confirm({...})` resolves to a
// boolean; render `element` once in the component. One modal at a time.
export function useConfirm(): {
  confirm: (opts: ConfirmOpts) => Promise<boolean>;
  element: ReactNode;
} {
  const [req, setReq] = useState<
    (ConfirmOpts & { resolve: (ok: boolean) => void }) | null
  >(null);

  const confirm = useCallback(
    (opts: ConfirmOpts) =>
      new Promise<boolean>((resolve) => setReq({ ...opts, resolve })),
    [],
  );

  const element = req ? (
    <ConfirmDialog
      title={req.title}
      body={req.body}
      confirmLabel={req.confirmLabel}
      danger={req.danger}
      onResolve={(ok) => {
        req.resolve(ok);
        setReq(null);
      }}
    />
  ) : null;

  return { confirm, element };
}

/** A row of buttons that all act on the same object. Wraps on a phone and
 *  keeps a 44px hit target. */
export function Actions({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-2">{children}</div>;
}

/** Separates the routine actions from the destructive one. This is the job the
 *  red `btn-error` was doing, done in a channel the state palette does not
 *  need: a rule and a gap, so Delete is not one more button in a row of five
 *  and the alarm hue stays available for an actual alarm. */
export function ActionSep() {
  return (
    <span
      aria-hidden
      className="mx-0.5 hidden h-5 w-px self-center bg-base-300 sm:block"
    />
  );
}

// Re-exported so a form can use the shared button without importing from two
// places; `Actions` + `ActionButton` are one vocabulary.
export { ActionButton };
