import { useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './dashboard/Dashboard'
import Login from './components/Login'
import { fetchMe, getToken, type Me } from './lib/api'

export default function App() {
  const [me, setMe] = useState<Me | null>(null)
  const [checked, setChecked] = useState(false)

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
      <Sidebar me={me} onLogout={() => setMe(null)} />
      <main className="flex-1 overflow-y-auto">
        <Dashboard />
      </main>
    </div>
  )
}
