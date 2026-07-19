import { useState } from 'react'
import { logout, can, type Me } from '../lib/api'
import { useTheme } from '../lib/theme'
import SupportModal from './SupportModal'

export type View = 'dashboard' | 'agents' | 'snapshots' | 'response' | 'report' | 'tickets' | 'rules' | 'decoders' | 'playbooks' | 'integrations' | 'users' | 'settings'

type NavItem = { id: string; label: string; view?: View; perm?: string }

const NAV: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', view: 'dashboard', perm: 'view_dashboard' },
  { id: 'response', label: 'Response', view: 'response', perm: 'approve_remediation' },
  { id: 'snapshots', label: 'Snapshots', view: 'snapshots', perm: 'view_dashboard' },
  { id: 'tickets', label: 'Tickets', view: 'tickets', perm: 'view_tickets' },
  { id: 'report', label: 'Report', view: 'report', perm: 'view_dashboard' },
  { id: 'agents', label: 'Agents', view: 'agents', perm: 'view_dashboard' },
  { id: 'rules', label: 'Rules', view: 'rules', perm: 'manage_rules' },
  { id: 'decoders', label: 'Decoders', view: 'decoders', perm: 'manage_rules' },
  { id: 'playbooks', label: 'Playbooks', view: 'playbooks', perm: 'manage_rules' },
  { id: 'integrations', label: 'Integrations', view: 'integrations', perm: 'manage_integrations' },
  { id: 'users', label: 'Users', view: 'users', perm: 'manage_users' },
  { id: 'settings', label: 'Settings', view: 'settings', perm: 'manage_settings' },
]

// Inline stroke icons (no icon package, no CDN â€” the app must run fully offline).
const ICONS: Record<string, string> = {
  dashboard: 'M3 3h7v7H3zM14 3h7v4h-7zM14 11h7v10h-7zM3 14h7v7H3z',
  response: 'M12 3l8 3.5V12c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6.5zM8.5 12l2.5 2.5L16 9.5',
  snapshots: 'M12 8v4l3 2M3.05 11a9 9 0 1 1 .5 4M3 21v-6h6',
  tickets: 'M3 8a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-2a2 2 0 0 0 0-4zM12 6v12',
  report: 'M6 2h8l5 5v15H6zM14 2v5h5M9 13h7M9 17h7',
  agents: 'M3 5h18v6H3zM3 13h18v6H3zM7 8h.01M7 16h.01',
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
}: {
  me: Me
  view: View
  onNavigate: (v: View) => void
  onLogout: () => void
}) {
  const [showSupport, setShowSupport] = useState(false)
  const [theme, toggleTheme] = useTheme()

  const handleLogout = async () => {
    await logout()
    onLogout()
  }

  const initials = me.username.slice(0, 2).toUpperCase()

  return (
    <aside className="sticky top-0 flex h-screen w-[232px] shrink-0 flex-col border-r border-border bg-surface">
      {/* Brand */}
      <div className="flex h-[60px] items-center gap-2.5 px-[18px]">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path
            d="M12 2 L21 6 V12 C21 17 17 21 12 22 C7 21 3 17 3 12 V6 Z"
            stroke="var(--dw-accent)"
            strokeWidth="2"
            strokeLinejoin="round"
          />
          <path
            d="M8.5 12 L11 14.5 L16 9"
            stroke="var(--dw-accent)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
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
              onClick={() => n.view && onNavigate(n.view)}
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

        <div className="flex items-center gap-2">
          <button
            onClick={toggleTheme}
            title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            className="flex flex-1 items-center justify-center gap-1.5 rounded-[8px] border border-border px-2 py-1.5 text-[11px] text-muted transition-colors hover:bg-surface-2 hover:text-fg"
          >
            {theme === 'dark' ? (
              <>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <circle cx="12" cy="12" r="4" stroke="currentColor" strokeWidth="1.8" />
                  <path
                    d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                  />
                </svg>
                Light
              </>
            ) : (
              <>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path
                    d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                Dark
              </>
            )}
          </button>
          <button
            onClick={() => setShowSupport(true)}
            title="Support DeusWatch"
            className="rounded-[8px] border border-border px-2 py-1.5 text-[11px] text-muted transition-colors hover:bg-surface-2 hover:text-critical"
          >
            â™¥
          </button>
        </div>
      </div>

      {showSupport && <SupportModal onClose={() => setShowSupport(false)} />}
    </aside>
  )
}
