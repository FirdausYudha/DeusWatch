// Modal is the one dialog shell: a centered panel over a dimmed backdrop, with the chrome every
// overlay needs and used to re-implement by hand (Escape to close, click-outside to close, a focus
// trap, scroll lock, role="dialog"/aria-modal, and focus restored to wherever it was on close).
// Pages compose it instead of rolling their own so a modal behaves the same everywhere.
import { useEffect, useRef, type ReactNode } from 'react'
import { Icon } from './ui'

function focusables(container: HTMLElement | null): HTMLElement[] {
  if (!container) return []
  const sel = 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
  return Array.from(container.querySelectorAll<HTMLElement>(sel)).filter((el) => el.offsetParent !== null)
}

export default function Modal({
  title,
  onClose,
  children,
  footer,
  size = 'md',
}: {
  title?: ReactNode
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  size?: 'sm' | 'md' | 'lg'
}) {
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const prevFocus = document.activeElement as HTMLElement | null
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden' // scroll lock
    // Focus the first focusable control, falling back to the panel itself.
    const f = focusables(panelRef.current)
    ;(f[0] ?? panelRef.current)?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); onClose(); return }
      if (e.key === 'Tab') {
        const items = focusables(panelRef.current)
        if (items.length === 0) { e.preventDefault(); return }
        const first = items[0], last = items[items.length - 1]
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus() }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
      }
    }
    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('keydown', onKey, true)
      document.body.style.overflow = prevOverflow
      prevFocus?.focus?.()
    }
  }, [onClose])

  const maxW = size === 'sm' ? 'max-w-sm' : size === 'lg' ? 'max-w-2xl' : 'max-w-md'
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/60 p-4" onClick={onClose}>
      <div
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        className={`w-full ${maxW} overflow-hidden rounded-[12px] border border-border bg-surface shadow-xl outline-none`}
      >
        {title != null && (
          <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-3">
            <h2 className="text-[15px] font-bold text-fg">{title}</h2>
            <button onClick={onClose} aria-label="Close" className="rounded p-0.5 text-dim transition-colors hover:text-fg">
              <Icon name="close" size={16} />
            </button>
          </div>
        )}
        {children ? <div className="p-5">{children}</div> : null}
        {footer && <div className="flex justify-end gap-2 border-t border-border px-5 py-3">{footer}</div>}
      </div>
    </div>
  )
}
