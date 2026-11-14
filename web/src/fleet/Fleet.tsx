import { useEffect, useMemo, useState } from 'react'
import {
  fetchAgents, fetchMetricsLatest, fetchVulnerabilities, fetchSCA, fetchBenchmarks, fetchFimAlertCounts,
  agentDisplayStatus,
  type AgentInfo, type DisplayStatus, type HostMetricLatest, type VulnSummary, type SCASummary, type BenchmarkSummary,
} from '../lib/api'
import { Page, Card, StatCard, EmptyState, ErrorText } from '../components/ui'
import DocLink from '../components/DocLink'

// Fleet is the agent-monitoring dashboard: one row per endpoint pulling together every per-agent
// monitoring signal the product already collects - liveness, live CPU/memory/disk, OS-package
// vulnerabilities (VA), dependency vulnerabilities (SCA), and CIS hardening score. The default
// Dashboard answers "what is happening on the network"; this answers "how is each endpoint doing".

const STATUS_STYLE: Record<DisplayStatus, { cls: string; label: string }> = {
  online: { cls: 'bg-ok/15 text-ok', label: 'online' },
  stale: { cls: 'bg-medium/15 text-medium', label: 'stale' },
  offline: { cls: 'bg-critical/15 text-critical', label: 'offline' },
  never: { cls: 'bg-surface-2 text-dim', label: 'never seen' },
  revoked: { cls: 'bg-surface-2 text-dim', label: 'revoked' },
}

// usageTone colours a 0-100 usage figure where higher is worse (CPU, memory, disk).
function usageTone(v: number): string {
  if (v >= 90) return 'text-critical'
  if (v >= 70) return 'text-medium'
  return 'text-fg'
}
// scoreTone colours a CIS score where higher is better.
function scoreTone(v: number): string {
  if (v >= 90) return 'text-ok'
  if (v >= 70) return 'text-medium'
  return 'text-critical'
}

// humanUptime turns seconds-since-boot into a compact "5d 3h".
function humanUptime(sec: number | null | undefined): string {
  if (sec === null || sec === undefined) return '—'
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

// Meter is a compact value + bar for a 0-100 usage figure, or a dash when there is no fresh reading.
function Meter({ v }: { v: number | null }) {
  if (v === null || v === undefined) return <span className="text-dim">—</span>
  const pct = Math.max(0, Math.min(100, v))
  const bar = pct >= 90 ? 'bg-critical' : pct >= 70 ? 'bg-medium' : 'bg-accent'
  return (
    <div className="flex items-center gap-2">
      <span className={`w-10 text-right tabular-nums ${usageTone(pct)}`}>{pct.toFixed(0)}%</span>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-2">
        <div className={`h-full ${bar}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

type Row = {
  agent: AgentInfo
  status: DisplayStatus
  perf?: HostMetricLatest
  va?: VulnSummary
  sca?: SCASummary
  cis: number | null
  fim: number
}

export default function Fleet() {
  const [rows, setRows] = useState<Row[] | null>(null)
  const [error, setError] = useState('')
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null)

  useEffect(() => {
    let live = true
    const load = async () => {
      try {
        const [agents, perf, vuln, sca, bench, fim] = await Promise.all([
          fetchAgents(), fetchMetricsLatest(), fetchVulnerabilities(), fetchSCA(), fetchBenchmarks(), fetchFimAlertCounts(24),
        ])
        if (!live) return
        const perfBy = new Map(perf.map((p) => [p.agent_name, p]))
        const vaBy = new Map(vuln.agents.map((v) => [v.agent_name, v]))
        const scaBy = new Map(sca.agents.map((s) => [s.agent_name, s]))
        // An agent can carry several CIS policies; show the average of their scores.
        const cisScores = new Map<string, number[]>()
        for (const b of bench as BenchmarkSummary[]) {
          const arr = cisScores.get(b.agent_name) ?? []
          arr.push(b.score)
          cisScores.set(b.agent_name, arr)
        }
        const built: Row[] = agents.map((a) => {
          const scores = cisScores.get(a.name)
          return {
            agent: a,
            status: agentDisplayStatus(a),
            perf: perfBy.get(a.name),
            va: vaBy.get(a.name),
            sca: scaBy.get(a.name),
            cis: scores && scores.length ? Math.round(scores.reduce((x, y) => x + y, 0) / scores.length) : null,
            fim: fim[a.name] ?? 0,
          }
        })
        setRows(built)
        setError('')
        setRefreshedAt(new Date())
      } catch (e) {
        if (live) setError((e as Error).message)
      }
    }
    void load()
    const t = setInterval(load, 30_000) // a monitoring board; refresh quietly
    return () => { live = false; clearInterval(t) }
  }, [])

  const summary = useMemo(() => {
    const all = rows ?? []
    const online = all.filter((r) => r.status === 'online').length
    const down = all.filter((r) => r.status === 'offline' || r.status === 'stale' || r.status === 'never').length
    const critical = all.filter((r) => (r.va?.critical ?? 0) > 0 || (r.sca?.critical ?? 0) > 0).length
    const cisVals = all.map((r) => r.cis).filter((v): v is number => v !== null)
    const avgCis = cisVals.length ? Math.round(cisVals.reduce((a, b) => a + b, 0) / cisVals.length) : null
    const fim = all.reduce((n, r) => n + r.fim, 0)
    return { total: all.length, online, down, critical, avgCis, fim }
  }, [rows])

  return (
    <Page>
      {error && <ErrorText>{error}</ErrorText>}

      <div className="mb-4 flex justify-end">
        <DocLink file="agent-monitoring.md" label="About this dashboard" />
      </div>

      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard label="Agents" value={summary.total} />
        <StatCard label="Online" value={summary.online} accentClass="text-ok" />
        <StatCard label="Offline / stale" value={summary.down} accentClass={summary.down ? 'text-critical' : 'text-fg'} />
        <StatCard label="With critical vulns" value={summary.critical} accentClass={summary.critical ? 'text-critical' : 'text-fg'} hint="VA or SCA critical" />
        <StatCard label="FIM alerts 24h" value={summary.fim} accentClass={summary.fim ? 'text-high' : 'text-fg'} />
        <StatCard label="Avg CIS score" value={summary.avgCis === null ? '—' : `${summary.avgCis}%`} accentClass={summary.avgCis === null ? 'text-fg' : scoreTone(summary.avgCis)} />
      </div>

      <Card
        title="Agents"
        kicker={refreshedAt ? `updated ${refreshedAt.toLocaleTimeString()}` : undefined}
        bodyClass="p-0"
      >
        {rows === null ? (
          <p className="px-4 py-8 text-center text-[13px] text-dim">Loading…</p>
        ) : rows.length === 0 ? (
          <EmptyState title="No agents enrolled yet" hint="Enroll an agent from the Agents page; it appears here once it checks in." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13.5px]">
              <thead className="bg-surface text-[12px] uppercase tracking-wider text-dim">
                <tr>
                  <th className="px-4 py-2 font-medium">Agent</th>
                  <th className="px-4 py-2 font-medium">Status</th>
                  <th className="px-4 py-2 font-medium">CPU</th>
                  <th className="px-4 py-2 font-medium">Memory</th>
                  <th className="px-4 py-2 font-medium">Disk</th>
                  <th className="px-4 py-2 font-medium">Uptime</th>
                  <th className="px-4 py-2 font-medium" title="File-integrity alerts in the last 24h">FIM 24h</th>
                  <th className="px-4 py-2 font-medium" title="OS-package vulnerabilities (critical / high)">VA c/h</th>
                  <th className="px-4 py-2 font-medium" title="Dependency vulnerabilities (critical / high)">SCA c/h</th>
                  <th className="px-4 py-2 font-medium" title="CIS hardening score">CIS</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const s = STATUS_STYLE[r.status]
                  return (
                    <tr key={r.agent.id} className="border-t border-border">
                      <td className="px-4 py-2">
                        <div className="font-medium text-fg">{r.agent.name}</div>
                        <div className="text-[12px] text-dim">{r.agent.os}</div>
                      </td>
                      <td className="px-4 py-2">
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-[12px] font-semibold ${s.cls}`}>{s.label}</span>
                      </td>
                      <td className="px-4 py-2"><Meter v={r.perf?.cpu_pct ?? null} /></td>
                      <td className="px-4 py-2"><Meter v={r.perf?.mem_pct ?? null} /></td>
                      <td className="px-4 py-2"><Meter v={r.perf?.disk_pct ?? null} /></td>
                      <td className="px-4 py-2 tabular-nums text-muted">{humanUptime(r.perf?.uptime_sec)}</td>
                      <td className="px-4 py-2 tabular-nums">
                        {r.fim > 0 ? <span className="text-high">{r.fim}</span> : <span className="text-dim">0</span>}
                      </td>
                      <td className="px-4 py-2"><VulnCell crit={r.va?.critical} high={r.va?.high} /></td>
                      <td className="px-4 py-2"><VulnCell crit={r.sca?.critical} high={r.sca?.high} /></td>
                      <td className="px-4 py-2">
                        {r.cis === null ? <span className="text-dim">—</span> : <span className={`font-medium ${scoreTone(r.cis)}`}>{r.cis}%</span>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </Page>
  )
}

// VulnCell shows critical/high counts, muted when both are zero so a clean fleet is calm, not loud.
function VulnCell({ crit, high }: { crit?: number; high?: number }) {
  if (crit === undefined && high === undefined) return <span className="text-dim">—</span>
  const c = crit ?? 0, h = high ?? 0
  if (c === 0 && h === 0) return <span className="text-dim">0 / 0</span>
  return (
    <span className="tabular-nums">
      <span className={c > 0 ? 'text-critical' : 'text-dim'}>{c}</span>
      <span className="text-dim"> / </span>
      <span className={h > 0 ? 'text-high' : 'text-dim'}>{h}</span>
    </span>
  )
}
