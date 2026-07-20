import { useEffect, useState } from 'react'
import { fetchAgents, agentOnline, type AgentInfo, type Me } from '../lib/api'
import { PageHeader, Card, EmptyState, ErrorText, Pill } from '../components/ui'
import DocLink from '../components/DocLink'
import SnapshotBrowser from './SnapshotBrowser'

/**
 * Snapshots is a first-class page (the redesign promotes it out of the Agents modal): pick an
 * endpoint, then browse its watched files' dated versions, diff them, restore one, quarantine a
 * suspect file, or roll everything back to a point in time after ransomware.
 */
export default function Snapshots({ me, initialAgent }: { me: Me; initialAgent?: string }) {
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [selected, setSelected] = useState(initialAgent ?? '')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchAgents()
      .then((a) => {
        setAgents(a)
        setSelected((cur) => cur || (a.length > 0 ? a[0].name : ''))
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="mx-auto max-w-[1400px] px-6 py-5">
      <PageHeader
        subtitle="File integrity timeline · diff, restore & ransomware recovery"
        actions={<DocLink file="adr/0002-versioned-fim-snapshots.md" label="About snapshots" />}
      />

      {error && <ErrorText>{error}</ErrorText>}

      {loading ? (
        <p className="text-[12px] text-dim">Loading…</p>
      ) : agents.length === 0 ? (
        <EmptyState
          title="No agents enrolled yet"
          hint="Snapshots come from agents watching files. Enroll an endpoint on the Agents page, then enable a snapshot mode on a fim source."
        />
      ) : (
        <div className="grid grid-cols-[14rem_1fr] gap-4">
          {/* Endpoint picker */}
          <Card title="Endpoints" bodyClass="p-2">
            <div className="space-y-1">
              {agents.map((a) => (
                <button
                  key={a.id}
                  onClick={() => setSelected(a.name)}
                  className={`flex w-full items-center gap-2 rounded-[8px] px-2 py-1.5 text-left ${
                    selected === a.name ? 'bg-accent-soft text-accent' : 'text-muted hover:bg-surface-2'
                  }`}
                  title={a.name}
                >
                  <span
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                      a.revoked ? 'bg-critical' : agentOnline(a) ? 'bg-success' : 'bg-dim'
                    }`}
                  />
                  <span className="min-w-0 flex-1 truncate text-[12px]">{a.name}</span>
                  {a.revoked && <Pill className="bg-critical/15 text-critical">revoked</Pill>}
                </button>
              ))}
            </div>
          </Card>

          {/* Timeline for the chosen endpoint */}
          <Card title={selected ? `Watched files — ${selected}` : 'Watched files'}>
            {selected ? (
              <SnapshotBrowser agentName={selected} me={me} />
            ) : (
              <p className="text-[12px] text-dim">Select an endpoint.</p>
            )}
          </Card>
        </div>
      )}
    </div>
  )
}
