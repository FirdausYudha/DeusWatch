import { useEffect, useMemo, useState } from 'react'
import {
  can,
  fetchInventory,
  fetchAgentPackages,
  saveAssetDetails,
  assetExportURL,
  fetchVulnerabilities,
  fetchAgentVulnerabilities,
  rematchVulnerabilities,
  type InventorySummary,
  type AssetEdit,
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
            {/* A plain link, not a fetch: the browser's own download handles the file, the
                Content-Disposition names it, and the session cookie authenticates it like any
                other request. Their register lives in GLPI, so the job here is to hand the list
                over rather than ask anyone to retype what DeusWatch already sees. */}
            <a
              href={assetExportURL()}
              className="rounded-[8px] border border-border px-3 py-1.5 text-[13px] font-medium text-muted transition-colors hover:bg-surface-2 hover:text-fg"
            >
              Export assets (CSV)
            </a>
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
          {selected && (
            <div className="min-w-0 space-y-4">
              <AssetCard
                a={agents.find((x) => x.agent_name === selected)}
                me={me}
                onSaved={load}
              />
              <DetailPanel agent={selected} summary={vulns[selected]} />
            </div>
          )}
        </div>
      )}
    </Page>
  )
}

// AssetCard shows the hardware facts an asset register is built from: what the machine is called,
// who made it, which model, and the serial number a warranty claim and a stock-take are keyed on.
// It reads the inventory summary already loaded for the list, so selecting an agent costs no fetch.
//
// A field the agent could not read is shown as "—" rather than hidden, because an asset register
// needs to make the gap visible: on Linux the DMI serial is root-only, and a blank cell is the
// prompt to go and fix that, where a missing row just looks complete.
function AssetCard({ a, me, onSaved }: { a?: InventorySummary; me: Me; onSaved: () => void }) {
  // Hooks run before the early return, or their order changes with the selection.
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<AssetEdit>({ location: '', asset_tag: '', asset_notes: '' })
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const canEdit = can(me, 'manage_settings')

  useEffect(() => {
    // A new selection abandons an unsaved edit rather than carrying it to another machine, which
    // is how a location ends up on the wrong asset.
    setEditing(false)
    setErr('')
  }, [a?.agent_name])

  if (!a) return null
  const dash = (s: string) => (s.trim() === '' ? '—' : s)
  const ram = a.memory_mb > 0 ? `${(a.memory_mb / 1024).toFixed(1)} GB` : '—'
  const cpu = a.cpu_cores > 0 ? `${a.cpu_cores} core` : '—'
  const fields: [string, string][] = [
    ['Hostname', dash(a.hostname)],
    ['Serial number', dash(a.serial_number)],
    ['Manufacturer', dash(a.manufacturer)],
    ['Model', dash(a.model)],
    ['CPU / RAM', `${cpu} · ${ram}`],
    ['IP / MAC', `${dash(a.primary_ip)} · ${dash(a.primary_mac)}`],
    ['Location', dash(a.location)],
    ['Asset tag', dash(a.asset_tag)],
  ]

  const startEdit = () => {
    setDraft({ location: a.location, asset_tag: a.asset_tag, asset_notes: a.asset_notes })
    setErr('')
    setEditing(true)
  }
  const save = async () => {
    setBusy(true)
    setErr('')
    try {
      await saveAssetDetails(a.agent_name, draft)
      setEditing(false)
      onSaved()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="rounded-[12px] border border-border bg-surface px-4 py-3">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-[12.5px] font-semibold uppercase tracking-wider text-dim">Asset</h2>
        {canEdit && !editing && (
          <button onClick={startEdit} className="text-[12.5px] font-medium text-accent hover:underline">
            Edit location
          </button>
        )}
      </div>
      {editing ? (
        <div className="flex flex-col gap-3">
          {/* Only the three operator-owned fields are editable. The rest comes from the machine,
              and letting someone type over a serial number would put a value in the register that
              contradicts the device it names. */}
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="flex flex-col gap-1">
              <span className="text-[12.5px] text-dim">Location</span>
              <input
                value={draft.location}
                onChange={(e) => setDraft({ ...draft, location: e.target.value })}
                placeholder="e.g. Ward 3, nurse station 2"
                className="rounded-[8px] border border-border bg-bg px-2 py-1.5 text-[13.5px] text-fg"
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[12.5px] text-dim">Asset tag</span>
              <input
                value={draft.asset_tag}
                onChange={(e) => setDraft({ ...draft, asset_tag: e.target.value })}
                placeholder="your own inventory number"
                className="rounded-[8px] border border-border bg-bg px-2 py-1.5 text-[13.5px] text-fg"
              />
            </label>
          </div>
          <label className="flex flex-col gap-1">
            <span className="text-[12.5px] text-dim">Notes</span>
            <input
              value={draft.asset_notes}
              onChange={(e) => setDraft({ ...draft, asset_notes: e.target.value })}
              className="rounded-[8px] border border-border bg-bg px-2 py-1.5 text-[13.5px] text-fg"
            />
          </label>
          <div className="flex items-center gap-2">
            <button
              onClick={save}
              disabled={busy}
              className="rounded-[8px] bg-accent px-3 py-1.5 text-[12.5px] font-semibold text-white disabled:opacity-40"
            >
              {busy ? 'Saving…' : 'Save'}
            </button>
            <button onClick={() => setEditing(false)} className="text-[12.5px] text-dim hover:underline">
              Cancel
            </button>
          </div>
          {err && <p className="text-[12.5px] text-critical">{err}</p>}
        </div>
      ) : (
        <>
          <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2 lg:grid-cols-3">
            {fields.map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt className="text-[12.5px] text-dim">{label}</dt>
                <dd className="truncate text-[13.5px] text-fg" title={value}>
                  {value}
                </dd>
              </div>
            ))}
          </dl>
          {a.asset_notes && <p className="mt-2 text-[12.5px] text-muted">{a.asset_notes}</p>}
          {a.asset_updated_by && (
            // Who last walked to the machine, because a location nobody has confirmed for a year
            // is a different claim from one checked last week.
            <p className="mt-2 text-[12px] text-dim">
              Location set by {a.asset_updated_by}
              {a.asset_updated_at ? ` · ${new Date(a.asset_updated_at).toLocaleDateString()}` : ''}
            </p>
          )}
        </>
      )}
    </div>
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
        <strong>{label} failed.</strong> Findings below may be stale or empty. The worker needs
        outbound internet to ghcr.io for the Trivy vulnerability DB. Detail:{' '}
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
