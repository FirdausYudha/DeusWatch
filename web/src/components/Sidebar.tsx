import { logout, type Me } from '../lib/api'

type NavItem = { label: string; icon: string; active?: boolean }

// Navigasi sesuai design doc bagian 5 (web/src/*). Hanya Dashboard yang aktif di
// fondasi; sisanya placeholder "soon".
const NAV: NavItem[] = [
  { label: 'Dashboard', icon: '▣', active: true },
  { label: 'Alerts', icon: '◆' },
  { label: 'Agents', icon: '▤' },
  { label: 'Rules', icon: '⌘' },
  { label: 'Settings', icon: '⚙' },
]

export default function Sidebar({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const handleLogout = async () => {
    await logout()
    onLogout()
  }

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-900">
      <div className="flex items-center gap-3 px-5 py-5">
        <div className="grid h-9 w-9 place-items-center rounded-xl bg-indigo-500 text-lg font-bold text-white shadow-lg shadow-indigo-500/30">
          D
        </div>
        <div className="leading-tight">
          <div className="font-semibold tracking-tight text-white">DeusWatch</div>
          <div className="text-xs text-slate-500">Security Platform</div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-2">
        {NAV.map((n) => (
          <a
            key={n.label}
            className={`flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
              n.active
                ? 'bg-indigo-500/10 font-medium text-indigo-300'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            }`}
          >
            <span className="w-5 text-center text-slate-500">{n.icon}</span>
            {n.label}
            {!n.active && (
              <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-500">
                soon
              </span>
            )}
          </a>
        ))}
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
            Keluar
          </button>
        </div>
        <div className="px-2 pt-2 text-xs text-slate-600">
          <span className="text-rose-400">♥</span> Support DeusWatch
        </div>
      </div>
    </aside>
  )
}
