import { useEffect, useState } from 'react'
import Sidebar, { type View } from './components/Sidebar'
import Dashboard from './dashboard/Dashboard'
import Agents from './agents/Agents'
import Response from './response/Response'
import Report from './report/Report'
import Tickets from './tickets/Tickets'
import Rules from './rules/Rules'
import Decoders from './decoders/Decoders'
import Playbooks from './playbooks/Playbooks'
import Integrations from './integrations/Integrations'
import Users from './users/Users'
import Settings from './settings/Settings'
import Login from './components/Login'
import { fetchMe, getToken, can, type Me, type NewTicketInput } from './lib/api'

export default function App() {
  const [me, setMe] = useState<Me | null>(null)
  const [checked, setChecked] = useState(false)
  const [view, setView] = useState<View>('dashboard')
  const [ticketPrefill, setTicketPrefill] = useState<NewTicketInput | null>(null)

  // Triggered from an alert ("Create ticket") — jump to Tickets with the form prefilled.
  const createTicketFrom = (prefill: NewTicketInput) => {
    setTicketPrefill(prefill)
    setView('tickets')
  }

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
    return <div className="grid h-screen place-items-center bg-slate-950 text-slate-500">Loading…</div>
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
        ) : view === 'tickets' && can(me, 'view_tickets') ? (
          <Tickets me={me} prefill={ticketPrefill} onPrefillConsumed={() => setTicketPrefill(null)} />
        ) : view === 'report' ? (
          <Report />
        ) : view === 'rules' && can(me, 'manage_rules') ? (
          <Rules />
        ) : view === 'decoders' && can(me, 'manage_rules') ? (
          <Decoders />
        ) : view === 'playbooks' && can(me, 'manage_rules') ? (
          <Playbooks />
        ) : view === 'integrations' && can(me, 'manage_integrations') ? (
          <Integrations />
        ) : view === 'users' && can(me, 'manage_users') ? (
          <Users me={me} />
        ) : view === 'settings' ? (
          <Settings />
        ) : (
          <Dashboard onCreateTicket={can(me, 'manage_tickets') ? createTicketFrom : undefined} />
        )}
      </main>
    </div>
  )
}
