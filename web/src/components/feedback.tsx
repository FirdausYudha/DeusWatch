// Shared feedback primitives: toasts and a promise-based confirm dialog, so the app stops
// using the browser's native alert()/confirm() (unstyled, theme-blind, and blocking) and gives
// one consistent, honest voice for "that worked" / "that failed" / "are you sure?".
//
// Usage:
//   const toast = useToast()
//   toast.success('Agent revoked')
//   toast.error(err.message)
//
//   const confirm = useConfirm()
//   if (!(await confirm({ title: 'Delete rule?', danger: true }))) return
//
// One <FeedbackProvider> wraps the app (see main.tsx); both hooks read the same context.
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { Button, Icon } from './ui'
import Modal from './Modal'

type ToastKind = 'success' | 'error' | 'info'
type ToastItem = { id: number; kind: ToastKind; message: string }

export type ConfirmOptions = {
  title: string
  body?: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  /** Style the confirm button as destructive (and nudge the operator that it is irreversible). */
  danger?: boolean
}

type ToastApi = {
  show: (kind: ToastKind, message: string) => void
  success: (message: string) => void
  error: (message: string) => void
  info: (message: string) => void
}

type FeedbackCtx = { toast: ToastApi; confirm: (opts: ConfirmOptions) => Promise<boolean> }

const Ctx = createContext<FeedbackCtx | null>(null)

// How long a toast lingers before auto-dismiss. Errors stay longer because they are read, not
// just glanced at; all are dismissable by hand regardless.
const TOAST_MS: Record<ToastKind, number> = { success: 4000, error: 7000, info: 5000 }

const TOAST_STYLE: Record<ToastKind, string> = {
  success: 'border-success/40 bg-success/10 text-success',
  error: 'border-critical/40 bg-critical/10 text-critical',
  info: 'border-low/40 bg-low/10 text-low',
}

export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const nextId = useRef(1)
  const timers = useRef<Record<number, ReturnType<typeof setTimeout>>>({})

  const dismiss = useCallback((id: number) => {
    setToasts((ts) => ts.filter((t) => t.id !== id))
    const h = timers.current[id]
    if (h) {
      clearTimeout(h)
      delete timers.current[id]
    }
  }, [])

  const show = useCallback((kind: ToastKind, message: string) => {
    const id = nextId.current++
    setToasts((ts) => [...ts, { id, kind, message }])
    timers.current[id] = setTimeout(() => dismiss(id), TOAST_MS[kind])
  }, [dismiss])

  // Clear any outstanding timers if the provider unmounts.
  useEffect(() => () => { for (const h of Object.values(timers.current)) clearTimeout(h) }, [])

  const toast: ToastApi = {
    show,
    success: (m) => show('success', m),
    error: (m) => show('error', m),
    info: (m) => show('info', m),
  }

  // A confirm() call parks its resolve here; the dialog's buttons call it with true/false.
  const [pending, setPending] = useState<(ConfirmOptions & { resolve: (ok: boolean) => void }) | null>(null)
  const confirm = useCallback((opts: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => setPending({ ...opts, resolve }))
  }, [])
  const settle = useCallback((ok: boolean) => {
    setPending((p) => {
      p?.resolve(ok)
      return null
    })
  }, [])

  return (
    <Ctx.Provider value={{ toast, confirm }}>
      {children}

      {/* Toast viewport: top of the stack so it floats over modals and the nav. */}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(92vw,360px)] flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            role={t.kind === 'error' ? 'alert' : 'status'}
            className={`pointer-events-auto flex items-start gap-2 rounded-[10px] border px-3 py-2.5 text-[13px] shadow-lg ${TOAST_STYLE[t.kind]}`}
          >
            <span className="min-w-0 flex-1 break-words text-fg">{t.message}</span>
            <button
              onClick={() => dismiss(t.id)}
              aria-label="Dismiss"
              className="-mr-1 shrink-0 rounded p-0.5 text-dim transition-colors hover:text-fg"
            >
              <Icon name="close" size={14} />
            </button>
          </div>
        ))}
      </div>

      {pending && <ConfirmDialog opts={pending} onResolve={settle} />}
    </Ctx.Provider>
  )
}

function ConfirmDialog({ opts, onResolve }: { opts: ConfirmOptions; onResolve: (ok: boolean) => void }) {
  const confirmRef = useRef<HTMLButtonElement>(null)
  useEffect(() => {
    // Focus the confirm button (after Modal's own first-focusable focus runs) and wire Enter to it.
    // Escape, click-outside, scroll lock and the focus trap come from Modal.
    confirmRef.current?.focus()
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Enter') onResolve(true) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onResolve])

  return (
    <Modal
      title={opts.title}
      onClose={() => onResolve(false)}
      footer={
        <>
          <Button variant="secondary" onClick={() => onResolve(false)}>{opts.cancelLabel ?? 'Cancel'}</Button>
          <Button ref={confirmRef} variant={opts.danger ? 'danger' : 'primary'} onClick={() => onResolve(true)}>
            {opts.confirmLabel ?? (opts.danger ? 'Delete' : 'Confirm')}
          </Button>
        </>
      }
    >
      {opts.body ? <div className="text-[13px] leading-relaxed text-muted">{opts.body}</div> : null}
    </Modal>
  )
}

function useFeedback(): FeedbackCtx {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useToast/useConfirm must be used within <FeedbackProvider>')
  return ctx
}

export function useToast(): ToastApi {
  return useFeedback().toast
}

export function useConfirm(): (opts: ConfirmOptions) => Promise<boolean> {
  return useFeedback().confirm
}
