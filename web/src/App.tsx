import { useEffect, useState } from 'react'
import Sidebar, { type View } from './components/Sidebar'
import Dashboard from './dashboard/Dashboard'
import Agents from './agents/Agents'
import Response from './response/Response'
import Report from './report/Report'
import Users from './users/Users'
import Settings from './settings/Settings'
import Login from './components/Login'
import { fetchMe, getToken, type Me } from './lib/api'

export default function App() {
  const [me, setMe] = useState<Me | null>(null)
  const [checked, setChecked] = useState(false)
  const [view, setView] = useState<View>('dashboard')

  useEffect(() => {
    if (!getToken()) {
      setChecked(true)
      return
    }
    fetchMe()
      .then(setMe)
      .catch(() => {})
      .finally(() => setChecked(true))
  }, [])

  if (!checked) {
    return <div className="grid h-screen place-items-center bg-slate-950 text-slate-500">Memuat…</div>
  }
  if (!me) {
    return <Login onSuccess={setMe} />
  }

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-200">
      <Sidebar me={me} view={view} onNavigate={setView} onLogout={() => setMe(null)} />
      <main className="flex-1 overflow-y-auto">
        {view === 'agents' ? (
          <Agents me={me} />
        ) : view === 'response' ? (
          <Response me={me} />
        ) : view === 'report' ? (
          <Report />
        ) : view === 'users' && me.role === 'admin' ? (
          <Users />
        ) : view === 'settings' ? (
          <Settings />
        ) : (
          <Dashboard />
        )}
      </main>
    </div>
  )
}
