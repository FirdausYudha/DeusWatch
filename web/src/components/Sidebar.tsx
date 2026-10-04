import { useState } from 'react'
import { logout, can, type Me } from '../lib/api'
import { usePersistedState } from '../lib/usePersistedState'
import SupportModal from './SupportModal'

export type View = 'dashboard' | 'agents' | 'fim' | 'snapshots' | 'response' | 'report' | 'tickets' | 'rules' | 'decoders' | 'playbooks' | 'inventory' | 'agenthealth' | 'integrations' | 'users' | 'workspaces' | 'tenants' | 'settings'

type NavItem = { id: string; label: string; view?: View; perm?: string }

type NavGroup = {
  group: string
  items: NavItem[]
}

const NAV: NavGroup[] = [
  {
    group: 'Monitoring & Operations',
    items: [
      { id: 'dashboard', label: 'Dashboard', view: 'dashboard', perm: 'view_dashboard' },
      { id: 'response', label: 'Response', view: 'response', perm: 'approve_remediation' },
      { id: 'tickets', label: 'Tickets', view: 'tickets', perm: 'view_tickets' },
      // File Integrity sits directly above Snapshots on purpose: the two are the same domain
      // split by verb. This page watches what happened to files; Snapshots is where you act on
      // them. Rows here link across.
      { id: 'fim', label: 'File Integrity', view: 'fim', perm: 'view_dashboard' },
      { id: 'snapshots', label: 'Snapshots', view: 'snapshots', perm: 'view_dashboard' },
      { id: 'report', label: 'Report', view: 'report', perm: 'view_dashboard' },
    ],
  },
  {
    group: 'Asset & Endpoint Management',
    items: [
      { id: 'agents', label: 'Agents', view: 'agents', perm: 'view_dashboard' },
      { id: 'agenthealth', label: 'Agent Health', view: 'agenthealth', perm: 'view_dashboard' },
    ],
  },
  {
    group: 'Detection & Automation',
    items: [
      { id: 'rules', label: 'Rules', view: 'rules', perm: 'manage_rules' },
      { id: 'decoders', label: 'Decoders', view: 'decoders', perm: 'manage_rules' },
      { id: 'playbooks', label: 'Playbooks', view: 'playbooks', perm: 'manage_rules' },
      { id: 'integrations', label: 'Integrations', view: 'integrations', perm: 'manage_integrations' },
    ],
  },
  {
    group: 'Administration & Access',
    items: [
      { id: 'users', label: 'Users', view: 'users', perm: 'manage_users' },
      { id: 'workspaces', label: 'Workspaces', view: 'workspaces', perm: 'manage_workspaces' },
      { id: 'tenants', label: 'Tenants', view: 'tenants', perm: 'manage_tenants' },
      { id: 'settings', label: 'Settings', view: 'settings', perm: 'manage_settings' },
    ],
  },
]

// Inline stroke icons (no icon package, no CDN, the app must run fully offline).
const ICONS: Record<string, string> = {
  dashboard: 'M3 3h7v7H3zM14 3h7v4h-7zM14 11h7v10h-7zM3 14h7v7H3z',
  response: 'M12 3l8 3.5V12c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6.5zM8.5 12l2.5 2.5L16 9.5',
  fim: 'M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM13 2v7h7M9 13l2 2 4-4',
  snapshots: 'M12 8v4l3 2M3.05 11a9 9 0 1 1 .5 4M3 21v-6h6',
  tickets: 'M3 8a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-2a2 2 0 0 0 0-4zM12 6v12',
  report: 'M6 2h8l5 5v15H6zM14 2v5h5M9 13h7M9 17h7',
  agents: 'M3 5h18v6H3zM3 13h18v6H3zM7 8h.01M7 16h.01',
  inventory: 'M21 8V19a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8M3 8l2-4h14l2 4zM3 8h18M12 4v16',
  agenthealth: 'M12 3l8 3v5c0 5-3.4 8.3-8 10-4.6-1.7-8-5-8-10V6zM7.5 12h2l1.5 3 2-6 1.5 3h2',
  rules: 'M4 6h10M4 12h10M4 18h10M17 5l2 2 3-3M17 17l2 2 3-3',
  decoders: 'M3 4h18l-7 8v7l-4 2v-9z',
  playbooks: 'M4 4h11a3 3 0 0 1 3 3v13H7a3 3 0 0 1-3-3zM18 7h2v13H8',
  integrations: 'M9 3v6M15 3v6M6 9h12v4a6 6 0 0 1-12 0zM12 19v3',
  users: 'M16 20v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2M9.5 9.5a3 3 0 1 0 0-6 3 3 0 0 0 0 6M21 20v-2a4 4 0 0 0-3-3.8M16 3.7a4 4 0 0 1 0 7.6',
  workspaces: 'M3 7l9-4 9 4-9 4zM3 7v10l9 4 9-4V7M3 12l9 4 9-4',
  tenants: 'M3 21h18M6 21V8l6-4 6 4v13M10 12h4M10 16h4',
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
  // Per-group collapse, remembered across reloads (map of group name → collapsed).
  const [collapsed, setCollapsed] = usePersistedState<Record<string, boolean>>('nav.collapsed', {})
  const toggleGroup = (g: string) => setCollapsed({ ...collapsed, [g]: !collapsed[g] })
  // Rail mode: shrink the whole sidebar to icons so the page gets the width back. Desktop only,
  // because below `lg` the sidebar is already a slide-over that takes no width when shut.
  const [rail, setRail] = usePersistedState('nav.rail', false)

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
      {/* The rail width only ever applies from `lg` up: the mobile slide-over always opens at its
          full width, where shrinking to icons would help nobody. */}
      <aside
        // Exactly ONE lg:w-* is ever emitted. Listing both and relying on the order they appear in
        // the class string does not work: equal-specificity utilities are resolved by their order
        // in the generated stylesheet, so the rail silently kept its full width.
        className={`fixed inset-y-0 left-0 z-30 flex h-screen w-[232px] shrink-0 flex-col border-r border-border bg-surface transition-transform lg:sticky lg:top-0 lg:translate-x-0 ${
          rail ? 'lg:w-[64px]' : 'lg:w-[232px]'
        } ${open ? 'translate-x-0' : '-translate-x-full'}`}
      >
      {/* Brand. In rail mode the logo and wordmark give way to the toggle: 64px cannot hold both,
          and the control you need to get back out must never be the thing that got squeezed. */}
      <div className={`flex h-[60px] items-center gap-2.5 px-[18px] ${rail ? 'lg:justify-center lg:px-0' : ''}`}>
        <img
          src="/deuswatch-eye.png"
          alt=""
          aria-hidden="true"
          className={`h-7 w-auto shrink-0 ${rail ? 'lg:hidden' : ''}`}
        />
        <span className={`text-[16px] font-bold tracking-tight text-fg ${rail ? 'lg:hidden' : ''}`}>DeusWatch</span>
        <button
          onClick={() => setRail(!rail)}
          title={rail ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={rail ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!rail}
          className={`ml-auto hidden rounded-[8px] p-1.5 text-dim transition-colors hover:bg-surface-2 hover:text-fg lg:block ${
            rail ? 'lg:ml-0' : ''
          }`}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d={rail ? 'M9 6l6 6-6 6' : 'M15 6l-6 6 6 6'}
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
      </div>

      {/* Nav, grouped by feature category */}
      <nav className="flex flex-1 flex-col gap-4 overflow-y-auto px-2.5 py-3">
        {NAV.map((group) => {
          const visibleItems = group.items.filter(n => !n.perm || can(me, n.perm))
          if (visibleItems.length === 0) return null

          // In rail mode the group headers are hidden, so their collapse state must be ignored
          // too: otherwise a group collapsed before switching to the rail would hide its icons
          // with no header left to click and no way to get them back.
          const isCollapsed = !rail && !!collapsed[group.group]
          const hasActive = visibleItems.some((n) => n.view === view)

          return (
            <div key={group.group} className="flex flex-col gap-1">
              {/* Group header, click to collapse/expand. Shows an active dot when collapsed but the
                  current page lives inside, so you never lose your place. */}
              <button
                onClick={() => toggleGroup(group.group)}
                aria-expanded={!isCollapsed}
                className={`flex w-full items-center gap-1.5 px-3 py-1.5 text-left text-[12.5px] font-semibold uppercase tracking-wide text-dim transition-colors hover:text-fg ${
                  rail ? 'lg:hidden' : ''
                }`}
              >
                <svg
                  width="10"
                  height="10"
                  viewBox="0 0 24 24"
                  fill="none"
                  aria-hidden="true"
                  className={`shrink-0 transition-transform ${isCollapsed ? '-rotate-90' : ''}`}
                >
                  <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <span>{group.group}</span>
                {isCollapsed && hasActive && <span className="ml-auto h-[5px] w-[5px] rounded-full bg-accent" />}
              </button>
              {/* Items in group */}
              {!isCollapsed && visibleItems.map((n) => {
                const active = n.view === view
                return (
                  <button
                    key={n.id}
                    data-view={n.view}
                    onClick={() => { if (n.view) { onNavigate(n.view); onClose?.() } }}
                    // The label becomes the tooltip in rail mode: an icon-only nav that cannot be
                    // read is a guessing game, and these icons are not universal signs.
                    title={rail ? n.label : undefined}
                    className={`flex w-full items-center gap-[11px] rounded-[8px] px-3 py-[9px] text-left text-[14.5px] font-medium transition-colors ${
                      active ? 'bg-accent-soft text-accent' : 'text-muted hover:bg-surface-2 hover:text-fg'
                    } ${rail ? 'lg:justify-center lg:px-0' : ''}`}
                  >
                    <span className={active ? 'text-accent' : 'text-dim'}>
                      <NavIcon id={n.id} />
                    </span>
                    <span className={rail ? 'lg:hidden' : ''}>{n.label}</span>
                    {active && <span className={`ml-auto h-[5px] w-[5px] rounded-full bg-accent ${rail ? 'lg:hidden' : ''}`} />}
                  </button>
                )
              })}
            </div>
          )
        })}
      </nav>

      {/* Footer: user, theme, support */}
      <div className={`flex flex-col gap-2 border-t border-border p-3 ${rail ? 'lg:px-2' : ''}`}>
        {/* Rail mode keeps the avatar (it is the only "who am I logged in as" cue left) and drops
            the name, role and the Exit button, which has its own icon-sized form below. */}
        <div className={`flex items-center gap-2.5 px-1 ${rail ? 'lg:justify-center lg:px-0' : ''}`}>
          <div
            className="flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-full bg-accent text-[12.5px] font-bold text-white"
            title={rail ? `${me.username} (${me.role})` : undefined}
          >
            {initials}
          </div>
          <div className={`min-w-0 leading-tight ${rail ? 'lg:hidden' : ''}`}>
            <div className="truncate text-[13.5px] font-medium text-fg">{me.username}</div>
            <div className="truncate text-[12.5px] capitalize text-dim">{me.role}</div>
          </div>
          <button
            onClick={handleLogout}
            title="Log out"
            className={`ml-auto rounded-[8px] border border-border px-2 py-1 text-[12.5px] text-muted transition-colors hover:bg-surface-2 hover:text-fg ${
              rail ? 'lg:hidden' : ''
            }`}
          >
            Exit
          </button>
        </div>

        {/* Theme now lives in the Topbar (one control, next to the content it affects), so
            the footer keeps only Support. */}
        <button
          onClick={() => setShowSupport(true)}
          title="Support DeusWatch"
          className={`flex items-center justify-center gap-1.5 rounded-[8px] border border-border px-2 py-1.5 text-[12.5px] text-muted transition-colors hover:bg-surface-2 hover:text-critical ${
            rail ? 'lg:px-0' : ''
          }`}
        >
          <span aria-hidden="true">♥</span>
          <span className={rail ? 'lg:hidden' : ''}>Support DeusWatch</span>
        </button>

        {/* Log out keeps an icon-only form in rail mode, so signing out never requires expanding
            the sidebar first. */}
        <button
          onClick={handleLogout}
          title="Log out"
          aria-label="Log out"
          className={`hidden items-center justify-center rounded-[8px] border border-border px-2 py-1.5 text-muted transition-colors hover:bg-surface-2 hover:text-fg ${
            rail ? 'lg:flex' : ''
          }`}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
      </div>

      {showSupport && <SupportModal onClose={() => setShowSupport(false)} />}
      </aside>
    </>
  )
}
