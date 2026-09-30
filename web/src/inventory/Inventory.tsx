import { useEffect, useMemo, useState } from 'react'
import {
  can,
  fetchInventory,
  fetchAgentPackages,
  fetchVulnerabilities,
  fetchAgentVulnerabilities,
  rematchVulnerabilities,
  type InventorySummary,
  type Package,
  type VulnSummary,
  type VulnFinding,
  type ScanStatus,
  type Me,
} from '../lib/api'
import { PageHeader, Page, Pagination, usePaged } from '../components/ui'
import DocLink from '../components/DocLink'
import { DonutChart } from '../dashboard/widgets'

// Inventory is the Vulnerability Assessment view: each agent's OS + installed packages, and the CVE
// findings from matching those packages against vendor advisories (Ubuntu USN / Debian). It leads
// with vulnerabilities (the actionable part) and keeps the raw package list a tab away.
export default function Inventory({ me }: { me: Me }) {
  const [agents, setAgents] = useState<InventorySummary[]>([])
  const [vulns, setVulns] = useState<Record<string, VulnSummary>>({})
  const [advisoryTotal, setAdvisoryTotal] = useState<number | null>(null)
  const [scanStatus, setScanStatus] = useState<ScanStatus[]>([])
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [rematching, setRematching] = useState(false)
  const [rematchMsg, setRematchMsg] = useState('')

  const canRematch = can(me, 'manage_settings')

  const load = () =>
    Promise.all([fetchInventory(), fetchVulnerabilities()])
      .then(([inv, vo]) => {
        setAgents(inv)
        const byAgent: Record<string, VulnSummary> = {}
        for (const v of vo.agents) byAgent[v.agent_name] = v
        setVulns(byAgent)
        setAdvisoryTotal(vo.advisory_total)
        setScanStatus(vo.scan_status ?? [])
        setSelected((cur) => cur ?? (inv[0]?.agent_name ?? null))
      })
      .catch((e) => setError((e as Error).message))

  useEffect(() => {
    load()
  }, [])

  const doRematch = async () => {
    setRematching(true)
    setRematchMsg('')
    try {
      const n = await rematchVulnerabilities()
      setRematchMsg(`Rematched ${n} agent${n === 1 ? '' : 's'}.`)
      await load()
      setTimeout(() => setRematchMsg(''), 4000)
    } catch (e) {
      setRematchMsg(`Failed: ${(e as Error).message}`)
    } finally {
      setRematching(false)
    }
  }

  return (
    <Page>
      <PageHeader
        subtitle="Installed software & CVE findings per endpoint (Ubuntu USN / Debian advisories)"
        actions={
          <>
            {rematchMsg && <span className="text-[12.5px] text-dim">{rematchMsg}</span>}
            {canRematch && (
              <button
                onClick={doRematch}
                disabled={rematching}
                className="rounded-[8px] border border-border px-3 py-1.5 text-[13px] font-medium text-muted transition-colors hover:bg-surface-2 hover:text-fg disabled:opacity-50"
                title="Recompute per-agent severities from the currently cached advisories. Useful after upgrading past a release that shipped severity enrichment."
              >
                {rematching ? 'Recomputing…' : 'Recompute severities'}
              </button>
            )}
            <DocLink file="vulnerability-assessment.md" label="About vulnerability assessment" />
          </>
        }
      />

      {error && <p className="mb-4 text-[13.5px] text-rose-400">{error}</p>}

      <ScanStatusBanner status={scanStatus} scanner="trivy-os" label="Trivy vulnerability scan" />

      {advisoryTotal === 0 && !error && (
        <div className="mb-4 rounded-[12px] border border-amber-700/40 bg-amber-500/10 px-4 py-2.5 text-[13px] text-amber-200">
          No advisories loaded yet. The worker fetches vendor feeds (Ubuntu USN / Debian) for your
          fleet's releases shortly after startup, then every 12h. Findings appear once a feed is
          cached. this needs internet access on the manager.
        </div>
      )}

      {agents.length === 0 && !error && (
        <div className="rounded-[12px] border border-dashed border-border px-4 py-12 text-center text-[13.5px] text-dim">
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
          {selected && <DetailPanel agent={selected} summary={vulns[selected]} />}
        </div>
      )}
    </Page>
  )
}

// SevBadge shows a severity count in its colour, only when non-zero.
function SevBadge({ n, cls, label }: { n: number; cls: string; label: string }) {
  if (!n) return null
  return <span className={`rounded px-1.5 py-0.5 text-[12.5px] font-medium ${cls}`}>{n} {label}</span>
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
        <span className="truncate text-[14px] font-semibold text-fg">{a.agent_name}</span>
        <span className="shrink-0 rounded-full bg-surface-2 px-2 py-0.5 text-[12.5px] text-muted">{a.pkg_count} pkg</span>
      </div>
      <div className="mt-1 truncate text-[12.5px] capitalize text-muted">
        {os}
        {a.os_codename ? ` (${a.os_codename})` : ''} · {a.arch || '—'}
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-1">
        <SevBadge n={vuln?.critical ?? 0} cls="text-rose-200 bg-rose-500/20" label="critical" />
        <SevBadge n={vuln?.high ?? 0} cls="text-orange-200 bg-orange-500/15" label="high" />
        <SevBadge n={vuln?.medium ?? 0} cls="text-amber-200 bg-amber-500/15" label="medium" />
        <SevBadge n={vuln?.low ?? 0} cls="text-sky-200 bg-sky-500/15" label="low" />
        {clean && <span className="text-[12.5px] text-emerald-400">✓ no known CVEs</span>}
        {!vuln && <span className="text-[12.5px] text-dim">not yet scanned</span>}
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

// SEV_COLOR is the hex-only palette for the SeverityDonut, keyed by severity. The tones mirror
// SEV_CLS above so the donut slices match their badge in the row table, critical=rose,
// high=orange, medium=amber, low=sky, negligible+unknown=slate. Keeping the mapping literal (not
// derived from tailwind classes) lets DonutChart take it via its `colors` prop without extra work.
const SEV_COLOR: Record<string, string> = {
  critical: '#fb7185',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#38bdf8',
  negligible: '#94a3b8',
  unknown: '#64748b',
}
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'] as const

// ScanStatusBanner surfaces why a Trivy scan produced nothing / stale data, so an all-"unknown"
// donut or an empty SCA list is explained (e.g. Trivy could not download its DB) rather than looking
// like a silent bug. Renders nothing until a scan has run at least once.
export function ScanStatusBanner({ status, scanner, label }: { status: ScanStatus[]; scanner: string; label: string }) {
  const s = status.find((x) => x.scanner === scanner)
  if (!s) return null
  if (!s.ok) {
    return (
      <div className="mb-4 rounded-[12px] border border-rose-700/40 bg-rose-500/10 px-4 py-2.5 text-[13px] text-rose-200">
        <strong>{label} failed.</strong> Findings below may be stale or empty. The trivy service needs
        internet access to ghcr.io for its vulnerability DB. Detail:{' '}
        <span className="font-mono text-[12px]">{s.detail || 'unknown error'}</span>
      </div>
    )
  }
  if (s.scanned === 0) {
    return (
      <div className="mb-4 rounded-[12px] border border-amber-700/40 bg-amber-500/10 px-4 py-2.5 text-[13px] text-amber-200">
        {label} ran but scanned no endpoints yet, nothing to analyze. For SCA, agents must be on
        v2.15.0+ and have shipped dependency manifests.
      </div>
    )
  }
  return null
}

// SeverityDonut is a compact per-agent breakdown of vulnerability counts by severity, tinted with
// the SEV_COLOR palette. Non-zero slices only, an empty summary or a totally-safe agent renders
// nothing (the DetailPanel header stays clean).
function SeverityDonut({ summary }: { summary: VulnSummary }) {
  const data = SEV_ORDER
    .map((sev) => ({ label: sev, count: (summary as unknown as Record<string, number>)[sev] || 0 }))
    .filter((d) => d.count > 0)
  if (data.length === 0) return null
  const colors = data.map((d) => SEV_COLOR[d.label])
  return <DonutChart data={data} color="#6366f1" colors={colors} />
}

function DetailPanel({ agent, summary }: { agent: string; summary?: VulnSummary }) {
  const [tab, setTab] = useState<'vulns' | 'packages'>('vulns')
  return (
    <div className="overflow-hidden rounded-[12px] border border-border bg-surface">
      <div className="flex items-center gap-1 border-b border-border px-3 py-2">
        {(['vulns', 'packages'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-[8px] px-3 py-1 text-[13px] font-medium transition-colors ${
              tab === t ? 'bg-accent-soft text-accent' : 'text-muted hover:text-fg'
            }`}
          >
            {t === 'vulns' ? 'Vulnerabilities' : 'Packages'}
          </button>
        ))}
        <span className="ml-auto pr-2 text-[12.5px] text-dim">{agent}</span>
      </div>
      {/* Compact per-agent donut: only rendered on the Vulnerabilities tab (where it belongs) and
          only when the agent has at least one finding. Sits directly under the tab bar so the row
          table still gets the full viewport height. */}
      {tab === 'vulns' && summary && summary.total > 0 && (
        <div className="border-b border-border px-3 py-1">
          <SeverityDonut summary={summary} />
        </div>
      )}
      {tab === 'vulns' ? <VulnList agent={agent} /> : <PackageList agent={agent} />}
    </div>
  )
}

function VulnList({ agent }: { agent: string }) {
  const [rows, setRows] = useState<VulnFinding[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('') // '' = all severities

  useEffect(() => {
    setLoading(true)
    setFilter('')
    fetchAgentVulnerabilities(agent)
      .then((v) => {
        setRows(v)
        setError('')
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false))
  }, [agent])

  // Accumulated counts per severity across ALL findings (the "jumlah akumulasi severity").
  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const r of rows) c[r.severity || 'unknown'] = (c[r.severity || 'unknown'] || 0) + 1
    return c
  }, [rows])
  const filtered = useMemo(() => (filter ? rows.filter((r) => (r.severity || 'unknown') === filter) : rows), [rows, filter])
  // usePaged must run before any early return (rules of hooks).
  const paged = usePaged(filtered)

  if (loading) return <p className="px-4 py-6 text-center text-[13px] text-dim">loading…</p>
  if (error) return <p className="px-4 py-2 text-[13.5px] text-rose-400">{error}</p>
  if (rows.length === 0)
    return (
      <p className="px-4 py-8 text-center text-[13.5px] text-emerald-400">
        ✓ No known vulnerabilities for this agent’s installed packages.
      </p>
    )

  return (
    <div>
      <SeverityFilterBar counts={counts} total={rows.length} filter={filter} onFilter={(f) => { setFilter(f); paged.setPage(1) }} />
      <table className="w-full text-left text-sm">
        <thead className="bg-surface text-[12.5px] uppercase tracking-wider text-dim">
          <tr>
            <th className="px-4 py-2 font-medium">Severity</th>
            <th className="px-4 py-2 font-medium">CVSS</th>
            <th className="px-4 py-2 font-medium">CVE</th>
            <th className="px-4 py-2 font-medium">Package</th>
            <th className="px-4 py-2 font-medium">Installed → Fixed</th>
          </tr>
        </thead>
        <tbody>
          {paged.slice.map((v) => (
            <tr key={`${v.cve}/${v.package}`} className="border-t border-border align-top">
              <td className="px-4 py-1.5">
                <span className={`rounded px-1.5 py-0.5 text-[12.5px] font-medium ${SEV_CLS[v.severity] ?? SEV_CLS.unknown}`}>
                  {v.severity || 'unknown'}
                </span>
              </td>
              <td className="px-4 py-1.5"><CvssScore severity={v.severity} score={v.cvss} /></td>
              <td className="px-4 py-1.5">
                <a
                  href={
                    v.source === 'debian'
                      ? `https://security-tracker.debian.org/tracker/${v.cve}`
                      : v.cve.startsWith('GHSA-')
                        ? `https://github.com/advisories/${v.cve}`
                        : `https://ubuntu.com/security/${v.cve}`
                  }
                  target="_blank"
                  rel="noreferrer"
                  className="font-mono text-[12.5px] text-accent hover:underline"
                >
                  {v.cve}
                </a>
              </td>
              <td className="px-4 py-1.5 font-medium text-fg">{v.package}</td>
              <td className="px-4 py-1.5 font-mono text-[12.5px] text-muted">
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
      <div className="border-t border-border px-4">
        <Pagination page={paged.page} pages={paged.pages} total={paged.total} perPage={paged.perPage} onPage={paged.setPage} />
      </div>
      <div className="border-t border-border px-4 py-2 text-[12.5px] text-dim">
        {filter ? `${filtered.length} of ${rows.length}` : rows.length} finding{rows.length === 1 ? '' : 's'} · fix by upgrading the listed package to its fixed version
      </div>
    </div>
  )
}

// SeverityFilterBar shows the accumulated per-severity counts as clickable chips plus a dropdown, so
// the operator can both see the breakdown at a glance and filter the table to one severity.
export function SeverityFilterBar({ counts, total, filter, onFilter }: {
  counts: Record<string, number>; total: number; filter: string; onFilter: (f: string) => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-4 py-2">
      <button
        onClick={() => onFilter('')}
        className={`rounded-full px-2.5 py-0.5 text-[12px] font-medium transition-colors ${filter === '' ? 'bg-accent text-white' : 'bg-surface-2 text-muted hover:text-fg'}`}
      >
        All {total}
      </button>
      {SEV_ORDER.map((sev) => (counts[sev] ?? 0) > 0 ? (
        <button
          key={sev}
          onClick={() => onFilter(filter === sev ? '' : sev)}
          className={`rounded-full px-2.5 py-0.5 text-[12px] font-medium transition-colors ${filter === sev ? SEV_CLS[sev] + ' ring-1 ring-inset ring-current' : SEV_CLS[sev] + ' opacity-80 hover:opacity-100'}`}
          title={`Filter to ${sev}`}
        >
          {sev} {counts[sev]}
        </button>
      ) : null)}
      <select
        value={filter}
        onChange={(e) => onFilter(e.target.value)}
        className="ml-auto rounded-[8px] border border-border bg-surface-2 px-2 py-1 text-[12.5px] text-fg outline-none focus:border-accent"
      >
        <option value="">Filter by severity: All</option>
        {SEV_ORDER.map((sev) => <option key={sev} value={sev}>{sev} ({counts[sev] ?? 0})</option>)}
      </select>
    </div>
  )
}

// CvssScore shows the numeric CVSS base score, tinted by severity. Falls back to a dash when Trivy
// reported no score (older vendor data / the legacy OVAL matcher, which carries no CVSS).
export function CvssScore({ severity, score }: { severity: string; score: number }) {
  if (!score || score <= 0) return <span className="text-dim">—</span>
  const cls = severity === 'critical' ? 'text-rose-300' : severity === 'high' ? 'text-orange-300'
    : severity === 'medium' ? 'text-amber-300' : severity === 'low' ? 'text-sky-300' : 'text-muted'
  return <span className={`font-mono text-[12.5px] font-semibold ${cls}`}>{score.toFixed(1)}</span>
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

  const paged = usePaged(pkgs)
  return (
    <div>
      <div className="flex items-center justify-end border-b border-border px-4 py-2">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by package or source…"
          className="w-64 rounded-[8px] border border-border bg-bg px-2.5 py-1 text-[13px] text-fg outline-none focus:border-accent"
        />
      </div>
      {error && <p className="px-4 py-2 text-[13.5px] text-rose-400">{error}</p>}
      {loading ? (
        <p className="px-4 py-6 text-center text-[13px] text-dim">loading…</p>
      ) : pkgs.length === 0 ? (
        <p className="px-4 py-6 text-center text-[13px] text-dim">
          {q ? 'No packages match that filter.' : 'No packages reported for this agent.'}
        </p>
      ) : (
        <div>
          <table className="w-full text-left text-sm">
            <thead className="bg-surface text-[12.5px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-4 py-2 font-medium">Package</th>
                <th className="px-4 py-2 font-medium">Version</th>
                <th className="px-4 py-2 font-medium">Arch</th>
                <th className="px-4 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              {paged.slice.map((p) => (
                <tr key={`${p.name}/${p.arch}`} className="border-t border-border">
                  <td className="px-4 py-1.5 font-medium text-fg">{p.name}</td>
                  <td className="px-4 py-1.5 font-mono text-[12.5px] text-muted">{p.version}</td>
                  <td className="px-4 py-1.5 text-[12.5px] text-dim">{p.arch || '—'}</td>
                  <td className="px-4 py-1.5 text-[12.5px] text-dim">{p.source || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="px-4">
            <Pagination page={paged.page} pages={paged.pages} total={paged.total} perPage={paged.perPage} onPage={paged.setPage} />
          </div>
        </div>
      )}
    </div>
  )
}
