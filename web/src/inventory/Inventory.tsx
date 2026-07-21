import { useEffect, useState } from 'react'
import {
  fetchInventory,
  fetchAgentPackages,
  type InventorySummary,
  type Package,
  type Me,
} from '../lib/api'
import { PageHeader } from '../components/ui'
import DocLink from '../components/DocLink'

// Inventory is the read-only software-inventory view (Vulnerability Assessment, phase 1): each
// agent's OS/kernel and its installed packages. It does not evaluate vulnerabilities yet — that is
// phase 2, which will match these packages against vendor advisories.
export default function Inventory({ me }: { me: Me }) {
  void me
  const [agents, setAgents] = useState<InventorySummary[]>([])
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    fetchInventory()
      .then((a) => {
        setAgents(a)
        setSelected((cur) => cur ?? (a[0]?.agent_name ?? null))
      })
      .catch((e) => setError((e as Error).message))
  }, [])

  return (
    <div className="mx-auto max-w-[1400px] px-6 py-5">
      <PageHeader
        subtitle="Installed packages & OS release per endpoint · foundation for vulnerability assessment"
        actions={<DocLink file="inventory.md" label="About inventory" />}
      />

      {error && <p className="mb-4 text-[12.5px] text-rose-400">{error}</p>}

      {agents.length === 0 && !error && (
        <div className="rounded-[12px] border border-dashed border-border px-4 py-12 text-center text-[12.5px] text-dim">
          No inventory reported yet. Agents report their software inventory shortly after startup
          (and every 12h). Make sure the agent is at v2.0.2+ and running.
        </div>
      )}

      {agents.length > 0 && (
        <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
          {/* Fleet: one card per agent, click to inspect its packages. */}
          <div className="space-y-2">
            {agents.map((a) => (
              <AgentCard
                key={a.agent_name}
                a={a}
                active={a.agent_name === selected}
                onClick={() => setSelected(a.agent_name)}
              />
            ))}
          </div>
          {selected && <PackageList agent={selected} />}
        </div>
      )}
    </div>
  )
}

function AgentCard({ a, active, onClick }: { a: InventorySummary; active: boolean; onClick: () => void }) {
  const os = [a.os_id, a.os_version].filter(Boolean).join(' ') || 'unknown OS'
  return (
    <button
      onClick={onClick}
      className={`w-full rounded-[12px] border bg-surface px-4 py-3 text-left transition-colors ${
        active ? 'border-accent ring-1 ring-accent/40' : 'border-border hover:bg-surface-2'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-[13px] font-semibold text-fg">{a.agent_name}</span>
        <span className="shrink-0 rounded-full bg-surface-2 px-2 py-0.5 text-[11px] text-muted">
          {a.pkg_count} pkg
        </span>
      </div>
      <div className="mt-1 truncate text-[11px] capitalize text-muted">
        {os}
        {a.os_codename ? ` (${a.os_codename})` : ''}
      </div>
      <div className="mt-0.5 truncate text-[11px] text-dim">
        {a.kernel || '—'} · {a.arch || '—'} · {a.pkg_manager || 'no package manager'}
      </div>
    </button>
  )
}

function PackageList({ agent }: { agent: string }) {
  const [pkgs, setPkgs] = useState<Package[]>([])
  const [q, setQ] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  // Debounce the search so typing doesn't hammer the API.
  useEffect(() => {
    setLoading(true)
    const t = setTimeout(() => {
      fetchAgentPackages(agent, q)
        .then((p) => {
          setPkgs(p)
          setError('')
        })
        .catch((e) => setError((e as Error).message))
        .finally(() => setLoading(false))
    }, 200)
    return () => clearTimeout(t)
  }, [agent, q])

  return (
    <div className="overflow-hidden rounded-[12px] border border-border bg-surface">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <h2 className="text-[12.5px] font-semibold text-fg">
          Packages on <span className="text-accent">{agent}</span>
        </h2>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by package or source…"
          className="w-64 rounded-[8px] border border-border bg-bg px-2.5 py-1 text-[12px] text-fg outline-none focus:border-accent"
        />
      </div>
      {error && <p className="px-4 py-2 text-[12.5px] text-rose-400">{error}</p>}
      {loading ? (
        <p className="px-4 py-6 text-center text-[12px] text-dim">loading…</p>
      ) : pkgs.length === 0 ? (
        <p className="px-4 py-6 text-center text-[12px] text-dim">
          {q ? 'No packages match that filter.' : 'No packages reported for this agent.'}
        </p>
      ) : (
        <div className="max-h-[calc(100vh-220px)] overflow-y-auto">
          <table className="w-full text-left text-sm">
            <thead className="sticky top-0 bg-surface text-[11px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-4 py-2 font-medium">Package</th>
                <th className="px-4 py-2 font-medium">Version</th>
                <th className="px-4 py-2 font-medium">Arch</th>
                <th className="px-4 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              {pkgs.map((p) => (
                <tr key={`${p.name}/${p.arch}`} className="border-t border-border">
                  <td className="px-4 py-1.5 font-medium text-fg">{p.name}</td>
                  <td className="px-4 py-1.5 font-mono text-[11px] text-muted">{p.version}</td>
                  <td className="px-4 py-1.5 text-[11px] text-dim">{p.arch || '—'}</td>
                  <td className="px-4 py-1.5 text-[11px] text-dim">{p.source || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="border-t border-border px-4 py-2 text-[11px] text-dim">
        {pkgs.length} package{pkgs.length === 1 ? '' : 's'} shown
      </div>
    </div>
  )
}
