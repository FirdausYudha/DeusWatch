import { useState } from 'react'
import { logout, can, type Me } from '../lib/api'
import SupportModal from './SupportModal'

export type View = 'dashboard' | 'agents' | 'response' | 'report' | 'tickets' | 'rules' | 'integrations' | 'users' | 'settings'

type NavItem = { id: string; label: string; icon: string; view?: View; perm?: string }

const NAV: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '▣', view: 'dashboard', perm: 'view_dashboard' },
  { id: 'response', label: 'Response', icon: '◈', view: 'response', perm: 'approve_remediation' },
  { id: 'tickets', label: 'Tickets', icon: '◰', view: 'tickets', perm: 'view_tickets' },
  { id: 'report', label: 'Report', icon: '▦', view: 'report', perm: 'view_dashboard' },
  { id: 'agents', label: 'Agents', icon: '▤', view: 'agents', perm: 'view_dashboard' },
  { id: 'rules', label: 'Rules', icon: '⌘', view: 'rules', perm: 'manage_rules' },
  { id: 'integrations', label: 'Integrations', icon: '⧉', view: 'integrations', perm: 'manage_integrations' },
  { id: 'users', label: 'Users', icon: '◉', view: 'users', perm: 'manage_users' },
  { id: 'settings', label: 'Settings', icon: '⚙', view: 'settings', perm: 'manage_settings' },
]

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
  const handleLogout = async () => {
    await logout()
    onLogout()
  }

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-900">
      <div className="flex items-center gap-3 px-5 py-5">
        <img src="/deuswatch-eye.png" alt="DeusWatch" className="h-9 w-auto shrink-0" />
        <div className="leading-tight">
          <div className="font-semibold tracking-tight text-white">
            <span className="text-indigo-400">DEUS</span>WATCH
          </div>
          <div className="text-xs text-slate-500">Security Platform</div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-2">
        {NAV.map((n) => {
          if (n.perm && !can(me, n.perm)) return null
          const clickable = !!n.view
          const active = clickable && n.view === view
          return (
            <button
              key={n.id}
              data-view={n.view}
              onClick={clickable ? () => onNavigate(n.view!) : undefined}
              disabled={!clickable}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                active
                  ? 'bg-indigo-500/10 font-medium text-indigo-300'
                  : clickable
                    ? 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                    : 'cursor-default text-slate-500'
              }`}
            >
              <span className="w-5 text-center text-slate-500">{n.icon}</span>
              {n.label}
              {!clickable && (
                <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-500">
                  soon
                </span>
              )}
            </button>
          )
        })}
      </nav>

      <div className="border-t border-slate-800 px-3 py-3">
        <div className="flex items-center justify-between rounded-lg px-2 py-1.5">
          <div className="leading-tight">
            <div className="text-sm font-medium text-slate-200">{me.username}</div>
            <div className="text-xs capitalize text-slate-500">{me.role}</div>
          </div>
          <button
            onClick={handleLogout}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
          >
            Logout
          </button>
        </div>
        <button
          onClick={() => setShowSupport(true)}
          className="mt-1 w-full rounded-md px-2 py-1.5 text-left text-xs text-slate-500 transition-colors hover:bg-slate-800 hover:text-rose-300"
        >
          <span className="text-rose-400">♥</span> Support DeusWatch
        </button>
      </div>

      {showSupport && <SupportModal onClose={() => setShowSupport(false)} />}
    </aside>
  )
}
