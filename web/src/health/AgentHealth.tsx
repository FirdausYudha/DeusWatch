import { useEffect, useState } from 'react'
import type { Me } from '../lib/api'
import { fetchSCA, fetchAgentSCA, type SCASummary, type SCAFinding } from '../lib/api'
import Inventory from '../inventory/Inventory'
import { Page, Card, EmptyState, ErrorText, Pagination, usePaged } from '../components/ui'
import { DonutChart } from '../dashboard/widgets'

// AgentHealth houses the two per-endpoint security views the operator asked to group together:
// Vulnerability Assessment (OS-package CVEs, the existing Inventory view) and SCA (language
// dependency vulnerabilities from Trivy). Each tab's component brings its own <Page>, so the tab
// strip below sits in the same gutter and the content aligns rather than nesting two page shells.
type Tab = 'va' | 'sca'

export default function AgentHealth({ me }: { me: Me }) {
  const [tab, setTab] = useState<Tab>('va')
  return (
    <div>
      <div className="mx-auto max-w-[1400px] px-6 pt-6">
        <div className="inline-flex rounded-[8px] border border-border p-0.5 text-sm">
          {([['va', 'Vulnerability Assessment'], ['sca', 'SCA']] as [Tab, string][]).map(([id, label]) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`rounded-md px-3 py-1 transition-colors ${
                tab === id ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {tab === 'va' ? <Inventory me={me} /> : <SCAView />}
    </div>
  )
}

const SEV_COLOR: Record<string, string> = {
  critical: '#f43f5e', high: '#fb923c', medium: '#f59e0b', low: '#38bdf8', unknown: '#64748b',
}
const SEV_CLS: Record<string, string> = {
  critical: 'bg-rose-500/15 text-rose-300', high: 'bg-orange-500/15 text-orange-300',
  medium: 'bg-amber-500/15 text-amber-300', low: 'bg-sky-500/15 text-sky-300', unknown: 'bg-surface-2 text-muted',
}

// SCAView is a master-detail like Inventory: pick an endpoint on the left, see its dependency-vuln
// findings (with a severity donut) on the right. Data comes from the server-side Trivy SCA scan.
function SCAView() {
  const [agents, setAgents] = useState<SCASummary[] | null>(null)
  const [selected, setSelected] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    fetchSCA()
      .then((rows) => {
        setAgents(rows)
        setSelected((cur) => cur || (rows.length > 0 ? rows[0].agent_name : ''))
        setError('')
      })
      .catch((e) => setError((e as Error).message))
  }, [])

  return (
    <Page>
      {error && <ErrorText>{error}</ErrorText>}
      {agents === null ? (
        <p className="text-[13px] text-dim">Loading…</p>
      ) : agents.length === 0 ? (
        <EmptyState
          title="No dependency manifests reported yet"
          hint="Agents ship language lockfiles (package-lock.json, go.sum, requirements.txt, …) found under common app roots (/home, /opt, /srv, /var/www). Once an agent reports and Trivy scans them, findings appear here."
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
          <div className="space-y-2">
            {agents.map((a) => (
              <SCAAgentCard key={a.agent_name} a={a} active={a.agent_name === selected} onClick={() => setSelected(a.agent_name)} />
            ))}
          </div>
          {selected && <SCADetail agent={selected} summary={agents.find((a) => a.agent_name === selected)} />}
        </div>
      )}
    </Page>
  )
}

function SCAAgentCard({ a, active, onClick }: { a: SCASummary; active: boolean; onClick: () => void }) {
  const worst = a.critical > 0 ? 'critical' : a.high > 0 ? 'high' : a.medium > 0 ? 'medium' : a.low > 0 ? 'low' : 'unknown'
  return (
    <button
      onClick={onClick}
      className={`w-full rounded-[12px] border px-4 py-3 text-left transition-colors ${
        active ? 'border-accent bg-accent-soft' : 'border-border bg-surface hover:bg-surface-2'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-medium text-fg">{a.agent_name}</span>
        <span className={`shrink-0 rounded px-1.5 py-0.5 text-[11.5px] font-medium ${a.total > 0 ? SEV_CLS[worst] : 'bg-surface-2 text-muted'}`}>
          {a.total > 0 ? `${a.total} vuln${a.total === 1 ? '' : 's'}` : 'clean'}
        </span>
      </div>
      <div className="mt-1 text-[12.5px] text-dim">{a.manifests} manifest{a.manifests === 1 ? '' : 's'} scanned</div>
    </button>
  )
}

function SCADetail({ agent, summary }: { agent: string; summary?: SCASummary }) {
  const [rows, setRows] = useState<SCAFinding[] | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    setRows(null)
    fetchAgentSCA(agent)
      .then((f) => { setRows(f); setError('') })
      .catch((e) => setError((e as Error).message))
  }, [agent])

  const donut = summary
    ? [
        { label: 'critical', count: summary.critical },
        { label: 'high', count: summary.high },
        { label: 'medium', count: summary.medium },
        { label: 'low', count: summary.low },
        { label: 'unknown', count: summary.unknown },
      ].filter((d) => d.count > 0)
    : []
  const paged = usePaged(rows ?? [])

  return (
    <Card title={`Dependency vulnerabilities · ${agent}`} bodyClass="p-0">
      {donut.length > 0 && (
        <div className="border-b border-border p-4">
          <DonutChart data={donut} color="#f43f5e" colors={donut.map((d) => SEV_COLOR[d.label])} />
        </div>
      )}
      {error && <div className="p-4"><ErrorText>{error}</ErrorText></div>}
      {rows === null ? (
        <p className="px-4 py-6 text-center text-[13px] text-dim">loading…</p>
      ) : rows.length === 0 ? (
        <p className="px-4 py-8 text-center text-[13.5px] text-emerald-400">✓ No known dependency vulnerabilities for this endpoint.</p>
      ) : (
        <div>
          <table className="w-full text-left text-sm">
            <thead className="bg-surface text-[12.5px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-4 py-2 font-medium">Severity</th>
                <th className="px-4 py-2 font-medium">Vulnerability</th>
                <th className="px-4 py-2 font-medium">Package</th>
                <th className="px-4 py-2 font-medium">Installed → Fixed</th>
                <th className="px-4 py-2 font-medium">Manifest</th>
              </tr>
            </thead>
            <tbody>
              {paged.slice.map((f) => (
                <tr key={`${f.vuln_id}/${f.package}/${f.installed_version}`} className="border-t border-border align-top">
                  <td className="px-4 py-1.5">
                    <span className={`rounded px-1.5 py-0.5 text-[12.5px] font-medium ${SEV_CLS[f.severity] ?? SEV_CLS.unknown}`}>
                      {f.severity || 'unknown'}
                    </span>
                  </td>
                  <td className="px-4 py-1.5">
                    <a href={vulnLink(f.vuln_id)} target="_blank" rel="noreferrer" className="font-mono text-[12.5px] text-accent hover:underline">
                      {f.vuln_id}
                    </a>
                  </td>
                  <td className="px-4 py-1.5">
                    <span className="font-medium text-fg">{f.package}</span>
                    {f.pkg_type && <span className="ml-1.5 rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-dim">{f.pkg_type}</span>}
                  </td>
                  <td className="px-4 py-1.5 font-mono text-[12.5px] text-muted">
                    {f.installed_version || '—'}
                    {f.fixed_version ? <> {' → '}<span className="text-emerald-300">{f.fixed_version}</span></> : <span className="text-amber-300"> · no fix yet</span>}
                  </td>
                  <td className="px-4 py-1.5 text-[12.5px] text-dim" title={f.target}>{shortPath(f.target)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="border-t border-border px-4">
            <Pagination page={paged.page} pages={paged.pages} total={paged.total} perPage={paged.perPage} onPage={paged.setPage} />
          </div>
        </div>
      )}
    </Card>
  )
}

// vulnLink points a CVE at the NVD and a GHSA at the GitHub advisory DB.
function vulnLink(id: string): string {
  if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`
  return `https://nvd.nist.gov/vuln/detail/${id}`
}

// shortPath trims a long absolute manifest path to its last two segments for the table.
function shortPath(p: string): string {
  if (!p) return '—'
  const parts = p.split('/').filter(Boolean)
  return parts.length <= 2 ? p : '…/' + parts.slice(-2).join('/')
}
