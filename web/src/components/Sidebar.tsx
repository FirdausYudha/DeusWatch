import { useState } from 'react'
import { logout, can, type Me } from '../lib/api'
import SupportModal from './SupportModal'

export type View = 'dashboard' | 'agents' | 'snapshots' | 'response' | 'report' | 'tickets' | 'rules' | 'decoders' | 'playbooks' | 'inventory' | 'integrations' | 'users' | 'settings'

type NavItem = { id: string; label: string; view?: View; perm?: string }

const NAV: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', view: 'dashboard', perm: 'view_dashboard' },
  { id: 'response', label: 'Response', view: 'response', perm: 'approve_remediation' },
  { id: 'snapshots', label: 'Snapshots', view: 'snapshots', perm: 'view_dashboard' },
  { id: 'tickets', label: 'Tickets', view: 'tickets', perm: 'view_tickets' },
  { id: 'report', label: 'Report', view: 'report', perm: 'view_dashboard' },
  { id: 'agents', label: 'Agents', view: 'agents', perm: 'view_dashboard' },
  { id: 'inventory', label: 'Inventory', view: 'inventory', perm: 'view_dashboard' },
  { id: 'rules', label: 'Rules', view: 'rules', perm: 'manage_rules' },
  { id: 'decoders', label: 'Decoders', view: 'decoders', perm: 'manage_rules' },
  { id: 'playbooks', label: 'Playbooks', view: 'playbooks', perm: 'manage_rules' },
  { id: 'integrations', label: 'Integrations', view: 'integrations', perm: 'manage_integrations' },
  { id: 'users', label: 'Users', view: 'users', perm: 'manage_users' },
  { id: 'settings', label: 'Settings', view: 'settings', perm: 'manage_settings' },
]

// Inline stroke icons (no icon package, no CDN — the app must run fully offline).
const ICONS: Record<string, string> = {
  dashboard: 'M3 3h7v7H3zM14 3h7v4h-7zM14 11h7v10h-7zM3 14h7v7H3z',
  response: 'M12 3l8 3.5V12c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6.5zM8.5 12l2.5 2.5L16 9.5',
  snapshots: 'M12 8v4l3 2M3.05 11a9 9 0 1 1 .5 4M3 21v-6h6',
  tickets: 'M3 8a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-2a2 2 0 0 0 0-4zM12 6v12',
  report: 'M6 2h8l5 5v15H6zM14 2v5h5M9 13h7M9 17h7',
  agents: 'M3 5h18v6H3zM3 13h18v6H3zM7 8h.01M7 16h.01',
  inventory: 'M21 8V19a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8M3 8l2-4h14l2 4zM3 8h18M12 4v16',
  rules: 'M4 6h10M4 12h10M4 18h10M17 5l2 2 3-3M17 17l2 2 3-3',
  decoders: 'M3 4h18l-7 8v7l-4 2v-9z',
  playbooks: 'M4 4h11a3 3 0 0 1 3 3v13H7a3 3 0 0 1-3-3zM18 7h2v13H8',
  integrations: 'M9 3v6M15 3v6M6 9h12v4a6 6 0 0 1-12 0zM12 19v3',
  users: 'M16 20v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2M9.5 9.5a3 3 0 1 0 0-6 3 3 0 0 0 0 6M21 20v-2a4 4 0 0 0-3-3.8M16 3.7a4 4 0 0 1 0 7.6',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1v.3a2 2 0 1 1-4 0v-.2a1.6 1.6 0 0 0-2.8-1.1l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.6 1.6 0 0 0 4.6 15a1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.2A1.6 1.6 0 0 0 4.6 9a1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.6 1.6 0 0 0 9 4.6h.1A1.6 1.6 0 0 0 10 3.1V3a2 2 0 1 1 4 0v.2a1.6 1.6 0 0 0 1 1.4 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8v.1a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.2a1.6 1.6 0 0 0-1.4 1z',
}

function NavIcon({ id }: { id: string }) {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d={ICONS[id] ?? ICONS.dashboard}
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export default function Sidebar({
  me,
  view,
  onNavigate,
  onLogout,
  open = false,
  onClose,
}: {
  me: Me
  view: View
  onNavigate: (v: View) => void
  onLogout: () => void
  /** Mobile only: whether the slide-over nav is showing. Ignored from `lg` up. */
  open?: boolean
  onClose?: () => void
}) {
  const [showSupport, setShowSupport] = useState(false)

  const handleLogout = async () => {
    await logout()
    onLogout()
  }

  const initials = me.username.slice(0, 2).toUpperCase()

  return (
    <>
      {/* Below `lg` the 232px rail would eat most of a phone screen, so it becomes a slide-over
          with a dimmed backdrop. From `lg` up it is the ordinary sticky rail and the backdrop and
          transform never apply. */}
      {open && (
        <div
          onClick={onClose}
          aria-hidden="true"
          className="fixed inset-0 z-20 bg-slate-950/60 lg:hidden"
        />
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-30 flex h-screen w-[232px] shrink-0 flex-col border-r border-border bg-surface transition-transform lg:sticky lg:top-0 lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
      {/* Brand */}
      <div className="flex h-[60px] items-center gap-2.5 px-[18px]">
        <img src="/deuswatch-eye.png" alt="" aria-hidden="true" className="h-7 w-auto shrink-0" />
        <span className="text-[15px] font-bold tracking-tight text-fg">DeusWatch</span>
      </div>

      {/* Nav */}
      <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto px-2.5 py-3">
        {NAV.map((n) => {
          if (n.perm && !can(me, n.perm)) return null
          const active = n.view === view
          return (
            <button
              key={n.id}
              data-view={n.view}
              onClick={() => { if (n.view) { onNavigate(n.view); onClose?.() } }}
              className={`flex w-full items-center gap-[11px] rounded-[8px] px-3 py-[9px] text-left text-[13.5px] font-medium transition-colors ${
                active ? 'bg-accent-soft text-accent' : 'text-muted hover:bg-surface-2 hover:text-fg'
              }`}
            >
              <span className={active ? 'text-accent' : 'text-dim'}>
                <NavIcon id={n.id} />
              </span>
              {n.label}
              {active && <span className="ml-auto h-[5px] w-[5px] rounded-full bg-accent" />}
            </button>
          )
        })}
      </nav>

      {/* Footer: user, theme, support */}
      <div className="flex flex-col gap-2 border-t border-border p-3">
        <div className="flex items-center gap-2.5 px-1">
          <div className="flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-full bg-accent text-[11px] font-bold text-white">
            {initials}
          </div>
          <div className="min-w-0 leading-tight">
            <div className="truncate text-[12.5px] font-medium text-fg">{me.username}</div>
            <div className="truncate text-[11px] capitalize text-dim">{me.role}</div>
          </div>
          <button
            onClick={handleLogout}
            title="Log out"
            className="ml-auto rounded-[8px] border border-border px-2 py-1 text-[11px] text-muted transition-colors hover:bg-surface-2 hover:text-fg"
          >
            Exit
          </button>
        </div>

        {/* Theme now lives in the Topbar (one control, next to the content it affects), so
            the footer keeps only Support. */}
        <button
          onClick={() => setShowSupport(true)}
          title="Support DeusWatch"
          className="flex items-center justify-center gap-1.5 rounded-[8px] border border-border px-2 py-1.5 text-[11px] text-muted transition-colors hover:bg-surface-2 hover:text-critical"
        >
          <span aria-hidden="true">♥</span> Support DeusWatch
        </button>
      </div>

      {showSupport && <SupportModal onClose={() => setShowSupport(false)} />}
      </aside>
    </>
  )
}
