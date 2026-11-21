// Command palette: press Ctrl/Cmd+K anywhere to search every page and jump to it, instead of
// hunting through the sidebar's four collapsible groups. Keyboard-first (arrows + Enter), filtered
// by the viewer's permissions so it never offers a page they cannot open.
import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { can, type Me } from '../lib/api'
import { NAV } from './Sidebar'
import type { View } from './Sidebar'

type Dest = { view: View; label: string; group: string }

export default function CommandPalette({ me, onNavigate }: { me: Me; onNavigate: (v: View) => void }) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  // Every navigable destination the viewer is allowed to see, flattened from the sidebar groups.
  const dests = useMemo<Dest[]>(
    () =>
      NAV.flatMap((g) =>
        g.items
          .filter((n) => n.view && (!n.perm || can(me, n.perm)))
          .map((n) => ({ view: n.view!, label: n.label, group: g.group })),
      ),
    [me],
  )

  const results = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return dests
    return dests.filter((d) => d.label.toLowerCase().includes(needle) || d.group.toLowerCase().includes(needle))
  }, [q, dests])

  // Open on Ctrl/Cmd+K from anywhere (a deliberate chord, so it fires even inside inputs).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Reset the query and selection each time it opens, and focus the input.
  useEffect(() => {
    if (open) { setQ(''); setIdx(0); setTimeout(() => inputRef.current?.focus(), 0) }
  }, [open])

  // Keep the highlighted row in range as the result list shrinks.
  useEffect(() => { setIdx((i) => Math.min(i, Math.max(0, results.length - 1))) }, [results.length])

  if (!open) return null

  const go = (d: Dest | undefined) => { if (d) { onNavigate(d.view); setOpen(false) } }

  const onKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key === 'Escape') { setOpen(false); return }
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx((i) => Math.min(i + 1, results.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx((i) => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter') { e.preventDefault(); go(results[idx]) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-slate-950/60 p-4 pt-[12vh]" onClick={() => setOpen(false)}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg overflow-hidden rounded-[12px] border border-border bg-surface shadow-xl"
      >
        <input
          ref={inputRef}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Jump to a page…"
          className="w-full border-b border-border bg-transparent px-4 py-3 text-[14px] text-fg outline-none placeholder:text-dim"
        />
        <ul className="max-h-[50vh] overflow-y-auto py-1">
          {results.length === 0 ? (
            <li className="px-4 py-6 text-center text-[13px] text-dim">No matching page</li>
          ) : (
            results.map((d, i) => (
              <li key={d.view}>
                <button
                  onMouseEnter={() => setIdx(i)}
                  onClick={() => go(d)}
                  className={`flex w-full items-center justify-between gap-3 px-4 py-2 text-left text-[13.5px] ${
                    i === idx ? 'bg-accent-soft text-accent' : 'text-fg hover:bg-surface-2'
                  }`}
                >
                  <span>{d.label}</span>
                  <span className="text-[11.5px] text-dim">{d.group}</span>
                </button>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  )
}
