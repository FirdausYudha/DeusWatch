import { useEffect, useState } from 'react'
import {
  fetchInventory,
  fetchAgentPackages,
  fetchVulnerabilities,
  fetchAgentVulnerabilities,
  type InventorySummary,
  type Package,
  type VulnSummary,
  type VulnFinding,
  type Me,
} from '../lib/api'
import { PageHeader } from '../components/ui'
import DocLink from '../components/DocLink'

// Inventory is the Vulnerability Assessment view: each agent's OS + installed packages, and the CVE
// findings from matching those packages against vendor advisories (Ubuntu USN / Debian). It leads
// with vulnerabilities (the actionable part) and keeps the raw package list a tab away.
export default function Inventory({ me }: { me: Me }) {
  void me
  const [agents, setAgents] = useState<InventorySummary[]>([])
  const [vulns, setVulns] = useState<Record<string, VulnSummary>>({})
  const [advisoryTotal, setAdvisoryTotal] = useState<number | null>(null)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([fetchInventory(), fetchVulnerabilities()])
      .then(([inv, vo]) => {
        setAgents(inv)
        const byAgent: Record<string, VulnSummary> = {}
        for (const v of vo.agents) byAgent[v.agent_name] = v
        setVulns(byAgent)
        setAdvisoryTotal(vo.advisory_total)
        setSelected((cur) => cur ?? (inv[0]?.agent_name ?? null))
      })
      .catch((e) => setError((e as Error).message))
  }, [])

  return (
    <div className="mx-auto max-w-[1400px] px-6 py-5">
      <PageHeader
        subtitle="Installed software & CVE findings per endpoint (Ubuntu USN / Debian advisories)"
        actions={<DocLink file="vulnerability-assessment.md" label="About vulnerability assessment" />}
      />

      {error && <p className="mb-4 text-[12.5px] text-rose-400">{error}</p>}

      {advisoryTotal === 0 && !error && (
        <div className="mb-4 rounded-[12px] border border-amber-700/40 bg-amber-500/10 px-4 py-2.5 text-[12px] text-amber-200">
          No advisories loaded yet. The worker fetches vendor feeds (Ubuntu USN / Debian) for your
          fleet's releases shortly after startup, then every 12h. Findings appear once a feed is
          cached — this needs internet access on the manager.
        </div>
      )}

      {agents.length === 0 && !error && (
        <div className="rounded-[12px] border border-dashed border-border px-4 py-12 text-center text-[12.5px] text-dim">
          No inventory reported yet. Agents (v2.0.2+) report their software inventory shortly after
          startup and every 12h.
        </div>
      )}

      {agents.length > 0 && (
        <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
          <div className="space-y-2">
            {agents.map((a) => (
              <AgentCard
                key={a.agent_name}
                a={a}
                vuln={vulns[a.agent_name]}
                active={a.agent_name === selected}
                onClick={() => setSelected(a.agent_name)}
              />
            ))}
          </div>
          {selected && <DetailPanel agent={selected} />}
        </div>
      )}
    </div>
  )
}

// SevBadge shows a severity count in its colour, only when non-zero.
function SevBadge({ n, cls, label }: { n: number; cls: string; label: string }) {
  if (!n) return null
  return <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${cls}`}>{n} {label}</span>
}

function AgentCard({
  a,
  vuln,
  active,
  onClick,
}: {
  a: InventorySummary
  vuln?: VulnSummary
  active: boolean
  onClick: () => void
}) {
  const os = [a.os_id, a.os_version].filter(Boolean).join(' ') || 'unknown OS'
  const clean = vuln && vuln.total === 0
  return (
    <button
      onClick={onClick}
      className={`w-full rounded-[12px] border bg-surface px-4 py-3 text-left transition-colors ${
        active ? 'border-accent ring-1 ring-accent/40' : 'border-border hover:bg-surface-2'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-[13px] font-semibold text-fg">{a.agent_name}</span>
        <span className="shrink-0 rounded-full bg-surface-2 px-2 py-0.5 text-[11px] text-muted">{a.pkg_count} pkg</span>
      </div>
      <div className="mt-1 truncate text-[11px] capitalize text-muted">
        {os}
        {a.os_codename ? ` (${a.os_codename})` : ''} · {a.arch || '—'}
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-1">
        <SevBadge n={vuln?.critical ?? 0} cls="text-rose-200 bg-rose-500/20" label="critical" />
        <SevBadge n={vuln?.high ?? 0} cls="text-orange-200 bg-orange-500/15" label="high" />
        <SevBadge n={vuln?.medium ?? 0} cls="text-amber-200 bg-amber-500/15" label="medium" />
        <SevBadge n={vuln?.low ?? 0} cls="text-sky-200 bg-sky-500/15" label="low" />
        {clean && <span className="text-[11px] text-emerald-400">✓ no known CVEs</span>}
        {!vuln && <span className="text-[11px] text-dim">not yet scanned</span>}
      </div>
    </button>
  )
}

const SEV_CLS: Record<string, string> = {
  critical: 'text-rose-200 bg-rose-500/20',
  high: 'text-orange-200 bg-orange-500/15',
  medium: 'text-amber-200 bg-amber-500/15',
  low: 'text-sky-200 bg-sky-500/15',
  negligible: 'text-slate-300 bg-slate-500/15',
  unknown: 'text-muted bg-surface-2',
}

function DetailPanel({ agent }: { agent: string }) {
  const [tab, setTab] = useState<'vulns' | 'packages'>('vulns')
  return (
    <div className="overflow-hidden rounded-[12px] border border-border bg-surface">
      <div className="flex items-center gap-1 border-b border-border px-3 py-2">
        {(['vulns', 'packages'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-[8px] px-3 py-1 text-[12px] font-medium transition-colors ${
              tab === t ? 'bg-accent-soft text-accent' : 'text-muted hover:text-fg'
            }`}
          >
            {t === 'vulns' ? 'Vulnerabilities' : 'Packages'}
          </button>
        ))}
        <span className="ml-auto pr-2 text-[11px] text-dim">{agent}</span>
      </div>
      {tab === 'vulns' ? <VulnList agent={agent} /> : <PackageList agent={agent} />}
    </div>
  )
}

function VulnList({ agent }: { agent: string }) {
  const [rows, setRows] = useState<VulnFinding[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    fetchAgentVulnerabilities(agent)
      .then((v) => {
        setRows(v)
        setError('')
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false))
  }, [agent])

  if (loading) return <p className="px-4 py-6 text-center text-[12px] text-dim">loading…</p>
  if (error) return <p className="px-4 py-2 text-[12.5px] text-rose-400">{error}</p>
  if (rows.length === 0)
    return (
      <p className="px-4 py-8 text-center text-[12.5px] text-emerald-400">
        ✓ No known vulnerabilities for this agent’s installed packages.
      </p>
    )

  return (
    <div className="max-h-[calc(100vh-240px)] overflow-y-auto">
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 bg-surface text-[11px] uppercase tracking-wider text-dim">
          <tr>
            <th className="px-4 py-2 font-medium">Severity</th>
            <th className="px-4 py-2 font-medium">CVE</th>
            <th className="px-4 py-2 font-medium">Package</th>
            <th className="px-4 py-2 font-medium">Installed → Fixed</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((v) => (
            <tr key={`${v.cve}/${v.package}`} className="border-t border-border align-top">
              <td className="px-4 py-1.5">
                <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${SEV_CLS[v.severity] ?? SEV_CLS.unknown}`}>
                  {v.severity || 'unknown'}
                </span>
              </td>
              <td className="px-4 py-1.5">
                <a
                  href={
                    v.source === 'debian'
                      ? `https://security-tracker.debian.org/tracker/${v.cve}`
                      : `https://ubuntu.com/security/${v.cve}`
                  }
                  target="_blank"
                  rel="noreferrer"
                  className="font-mono text-[11px] text-accent hover:underline"
                >
                  {v.cve}
                </a>
              </td>
              <td className="px-4 py-1.5 font-medium text-fg">{v.package}</td>
              <td className="px-4 py-1.5 font-mono text-[11px] text-muted">
                {v.installed_version || '—'}
                {v.fixed_version ? (
                  <>
                    {' → '}
                    <span className="text-emerald-300">{v.fixed_version}</span>
                  </>
                ) : (
                  <span className="text-amber-300"> · no fix yet</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="border-t border-border px-4 py-2 text-[11px] text-dim">
        {rows.length} finding{rows.length === 1 ? '' : 's'} · fix by upgrading the listed package to its fixed version
      </div>
    </div>
  )
}

function PackageList({ agent }: { agent: string }) {
  const [pkgs, setPkgs] = useState<Package[]>([])
  const [q, setQ] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

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
    <div>
      <div className="flex items-center justify-end border-b border-border px-4 py-2">
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
        <div className="max-h-[calc(100vh-260px)] overflow-y-auto">
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
    </div>
  )
}
