import Sidebar from './components/Sidebar'
import Dashboard from './dashboard/Dashboard'

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-200">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <Dashboard />
      </main>
    </div>
  )
}
