// Shared UI primitives + the `useConfirm` hook live together here; the
// "only export components" fast-refresh rule doesn't apply to this kit module.
/* eslint-disable react-refresh/only-export-components */
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

// One card surface used everywhere — fixes the old per-card spacing drift.
export function Card({
  title,
  subtitle,
  right,
  children,
  className = '',
  // When the title slot holds interactive controls (e.g. an inline rename
  // form), render it in a plain <div> so we don't nest form controls inside an
  // <h2> heading. Visual styling stays identical.
  interactiveTitle = false,
}: {
  title?: ReactNode
  subtitle?: ReactNode
  right?: ReactNode
  children?: ReactNode
  className?: string
  interactiveTitle?: boolean
}) {
  return (
    <section
      className={`rounded-box border border-base-300 bg-base-200 p-5 ${className}`}
    >
      {(title || right) && (
        <div className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title &&
              (interactiveTitle ? (
                <div className="text-base font-semibold">{title}</div>
              ) : (
                <h2 className="text-base font-semibold">{title}</h2>
              ))}
            {subtitle && <div className="mt-0.5 text-sm text-base-content/60">{subtitle}</div>}
          </div>
          {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
        </div>
      )}
      {children}
    </section>
  )
}

// One field component — replaces the two divergent label/input layouts.
export function Field({
  label,
  hint,
  children,
  className = '',
}: {
  label: ReactNode
  hint?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <label className={`flex flex-col gap-1 ${className}`}>
      <span className="text-xs font-medium text-base-content/60">{label}</span>
      {children}
      {hint && <span className="text-xs text-base-content/60">{hint}</span>}
    </label>
  )
}

// Unified reveal for secret strings — one wording everywhere ("show"/"hide").
export function Reveal({
  value,
  masked,
  className = '',
}: {
  value: string
  masked: string
  className?: string
}) {
  const [shown, setShown] = useState(false)
  return (
    // flex (block-level) + min-w-0 so the revealed value wraps within the
    // container instead of pushing the layout off-screen; masked stays on one
    // truncated line.
    <span className={`flex min-w-0 items-start gap-2 ${className}`}>
      <code
        className={`min-w-0 rounded bg-base-300/60 px-1.5 py-0.5 font-mono text-xs ${
          shown ? 'break-all' : 'truncate'
        }`}
      >
        {shown ? value : masked}
      </code>
      <button
        type="button"
        className="link link-secondary shrink-0 text-xs no-underline hover:underline"
        onClick={() => setShown((s) => !s)}
      >
        {shown ? 'hide' : 'show'}
      </button>
    </span>
  )
}

interface ConfirmOpts {
  title: string
  body?: ReactNode
  confirmLabel?: string
  danger?: boolean // default true (destructive)
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
  const ref = useRef<HTMLDialogElement>(null)
  const result = useRef(false)
  const cb = useRef(onResolve)
  useEffect(() => {
    cb.current = onResolve
  })
  useEffect(() => {
    const dlg = ref.current
    if (!dlg) return
    dlg.showModal() // focuses the autofocus element (Cancel), traps focus
    // Fires for any close path (button .close(), Escape, backdrop) — resolve
    // with whatever the chosen result was (default false = cancel).
    const onClose = () => cb.current(result.current)
    dlg.addEventListener('close', onClose)
    return () => dlg.removeEventListener('close', onClose)
  }, [])

  const close = (ok: boolean) => {
    result.current = ok
    ref.current?.close() // → 'close' event → onResolve + focus restore
  }

  return (
    <dialog ref={ref} className="modal">
      <div className="modal-box border border-base-300 bg-base-200">
        <h3 className="text-base font-semibold">{title}</h3>
        {body && <div className="mt-2 text-sm text-base-content/70">{body}</div>}
        <div className="modal-action">
          <button type="button" autoFocus className="btn btn-sm btn-ghost" onClick={() => close(false)}>
            Cancel
          </button>
          <button
            type="button"
            className={`btn btn-sm ${danger === false ? 'btn-primary' : 'btn-error'}`}
            onClick={() => close(true)}
          >
            {confirmLabel ?? 'Confirm'}
          </button>
        </div>
      </div>
      {/* daisyUI backdrop: clicking it submits method=dialog → closes (cancel) */}
      <form method="dialog" className="modal-backdrop">
        <button aria-label="Cancel">close</button>
      </form>
    </dialog>
  )
}

// In-app replacement for window.confirm: `await confirm({...})` resolves to a
// boolean; render `element` once in the component. One modal at a time.
export function useConfirm(): {
  confirm: (opts: ConfirmOpts) => Promise<boolean>
  element: ReactNode
} {
  const [req, setReq] = useState<(ConfirmOpts & { resolve: (ok: boolean) => void }) | null>(null)

  const confirm = useCallback(
    (opts: ConfirmOpts) => new Promise<boolean>((resolve) => setReq({ ...opts, resolve })),
    [],
  )

  const element = req ? (
    <ConfirmDialog
      title={req.title}
      body={req.body}
      confirmLabel={req.confirmLabel}
      danger={req.danger}
      onResolve={(ok) => {
        req.resolve(ok)
        setReq(null)
      }}
    />
  ) : null

  return { confirm, element }
}
