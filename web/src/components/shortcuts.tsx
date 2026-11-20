// Global keyboard shortcuts: press "?" for the cheat sheet, and "g" then a letter to jump between
// pages (Gmail/GitHub-style chord). Mounted once in the authed shell. Shortcuts are ignored while a
// text field is focused, so typing is never hijacked.
import { useEffect, useMemo, useState } from 'react'
import { can, type Me } from '../lib/api'
import type { View } from './Sidebar'
import { Icon } from './ui'

type Shortcut = { chord: string; view: View; label: string; perm?: string }

// The chord is "g " + the final key. Letters are chosen to be mnemonic and not collide.
const NAV_SHORTCUTS: Shortcut[] = [
  { chord: 'g d', view: 'dashboard', label: 'Dashboard', perm: 'view_dashboard' },
  { chord: 'g m', view: 'fleet', label: 'Agent Monitoring', perm: 'view_dashboard' },
  { chord: 'g a', view: 'agents', label: 'Agents', perm: 'view_dashboard' },
  { chord: 'g h', view: 'agenthealth', label: 'Agent Health', perm: 'view_dashboard' },
  { chord: 'g r', view: 'response', label: 'Response', perm: 'approve_remediation' },
  { chord: 'g t', view: 'tickets', label: 'Tickets', perm: 'view_tickets' },
  { chord: 'g n', view: 'network', label: 'Network', perm: 'view_dashboard' },
  { chord: 'g s', view: 'settings', label: 'Settings', perm: 'manage_settings' },
]

function isEditable(el: EventTarget | null): boolean {
  const n = el as HTMLElement | null
  if (!n || !n.tagName) return false
  return n.tagName === 'INPUT' || n.tagName === 'TEXTAREA' || n.tagName === 'SELECT' || n.isContentEditable
}

export default function KeyboardShortcuts({ me, onNavigate }: { me: Me; onNavigate: (v: View) => void }) {
  const [helpOpen, setHelpOpen] = useState(false)
  const items = useMemo(() => NAV_SHORTCUTS.filter((s) => !s.perm || can(me, s.perm)), [me])

  useEffect(() => {
    // Time of the last bare "g", so "g" then a letter within the window counts as one chord.
    let gAt = 0
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setHelpOpen(false); gAt = 0; return }
      if (e.metaKey || e.ctrlKey || e.altKey) return
      if (isEditable(e.target)) return
      if (e.key === '?') { e.preventDefault(); setHelpOpen((o) => !o); return }
      if (e.key === 'g') { gAt = Date.now(); return }
      if (gAt && Date.now() - gAt < 1200) {
        const hit = items.find((s) => s.chord === `g ${e.key.toLowerCase()}`)
        gAt = 0
        if (hit) { e.preventDefault(); onNavigate(hit.view); setHelpOpen(false) }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [items, onNavigate])

  if (!helpOpen) return null
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/60 p-4" onClick={() => setHelpOpen(false)}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-sm rounded-[12px] border border-border bg-surface p-5 shadow-xl"
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-[15px] font-bold text-fg">Keyboard shortcuts</h2>
          <button onClick={() => setHelpOpen(false)} aria-label="Close" className="rounded p-0.5 text-dim hover:text-fg">
            <Icon name="close" size={16} />
          </button>
        </div>
        <ul className="space-y-1.5">
          {items.map((s) => (
            <li key={s.chord} className="flex items-center justify-between gap-3 text-[13px]">
              <span className="text-muted">Go to {s.label}</span>
              <Keys chord={s.chord} />
            </li>
          ))}
          <li className="flex items-center justify-between gap-3 border-t border-border pt-2 text-[13px]">
            <span className="text-muted">Show / hide this help</span>
            <Keys chord="?" />
          </li>
        </ul>
      </div>
    </div>
  )
}

// Keys renders a chord as individual <kbd> caps, e.g. "g d" -> [g][d].
function Keys({ chord }: { chord: string }) {
  return (
    <span className="flex items-center gap-1">
      {chord.split(' ').map((k, i) => (
        <kbd key={i} className="rounded-[5px] border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[12px] text-fg">{k}</kbd>
      ))}
    </span>
  )
}
