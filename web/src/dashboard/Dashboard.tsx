import { useEffect, useState } from 'react'
import {
  fetchHealth, fetchStats, fetchAlerts,
  SEVERITY, type DepState, type Health, type Stats, type EventRow, type NewTicketInput,
} from '../lib/api'

type DotState = 'good' | 'bad' | 'unknown'

function Dot({ state }: { state: DotState }) {
  const color = state === 'good' ? 'bg-emerald-400' : state === 'bad' ? 'bg-rose-400' : 'bg-amber-400'
  const glow = state === 'good' ? 'shadow-[0_0_10px_2px] shadow-emerald-400/40' : ''
  return <span className={`inline-block h-2.5 w-2.5 rounded-full ${color} ${glow}`} />
}

function depDot(s: DepState): DotState {
  return s === 'reachable' ? 'good' : s === 'unreachable' ? 'bad' : 'unknown'
}

function SeverityBadge({ sev }: { sev: number }) {
  const m = SEVERITY[sev] ?? SEVERITY[0]
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${m.cls}`}>{m.label}</span>
}

const VERDICT_BADGE: Record<string, string> = {
  malicious: 'text-rose-300 bg-rose-500/15',
  suspicious: 'text-amber-300 bg-amber-500/15',
  needs_review: 'text-sky-300 bg-sky-500/15',
  benign: 'text-emerald-300 bg-emerald-500/15',
}

// LLMVerdict shows the LLM triage verdict (if any) with the summary in a tooltip.
function LLMVerdict({ a }: { a: EventRow }) {
  if (!a.dw_llm_verdict) return <span className="text-slate-600">—</span>
  const cls = VERDICT_BADGE[a.dw_llm_verdict] ?? 'text-slate-400 bg-slate-700/40'
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${cls}`} title={a.dw_llm_summary || undefined}>
      {a.dw_llm_verdict}
    </span>
  )
}

// ThreatIntel shows the CTI/GeoIP enrichment summary for one alert.
function ThreatIntel({ a }: { a: EventRow }) {
  const abuse = a.dw_enrichment_abuse_confidence
  const otx = a.dw_enrichment_otx_pulse_count
  if (a.dw_enrichment_status !== 'enriched' && abuse == null) {
    return <span className="text-slate-600">—</span>
  }
  const abuseCls = abuse == null ? '' : abuse >= 90 ? 'text-rose-300 bg-rose-500/15' : abuse >= 50 ? 'text-amber-300 bg-amber-500/15' : 'text-slate-400 bg-slate-700/40'
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {a.source_geo_country_iso && (
        <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300" title={a.source_geo_city || undefined}>
          {a.source_geo_country_iso}
        </span>
      )}
      {abuse != null && (
        <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${abuseCls}`} title="AbuseIPDB confidence">
          abuse {abuse}
        </span>
      )}
      {otx != null && otx > 0 && (
        <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-xs font-medium text-violet-300" title="OTX pulses">
          otx {otx}
        </span>
      )}
      {a.dw_severity_escalated_by && (
        <span className="rounded bg-orange-500/15 px-1.5 py-0.5 text-xs font-medium text-orange-300" title={`Escalated by: ${a.dw_severity_escalated_by}`}>
          ↑
        </span>
      )}
    </div>
  )
}

function StatCard({ label, value, accent }: { label: string; value: number | string; accent?: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-xs uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-1 text-3xl font-semibold ${accent ?? 'text-white'}`}>{value}</div>
    </div>
  )
}

// alertToTicket builds a prefilled ticket from an alert row (raise a DFIR case).
function alertToTicket(a: EventRow): NewTicketInput {
  const lines = [
    `Source IP: ${a.source_ip || 'unknown'}`,
    `Rule: ${a.rule_name || a.rule_id || a.dw_label || '—'}`,
    a.threat_technique_id ? `MITRE: ${a.threat_technique_id} · ${a.threat_tactic_name}` : '',
    a.dw_llm_verdict ? `LLM verdict: ${a.dw_llm_verdict}` : '',
    '',
    a.event_original || '',
  ].filter(Boolean)
  return {
    title: `${a.rule_name || a.dw_label || 'Alert'}${a.source_ip ? ` from ${a.source_ip}` : ''}`,
    description: lines.join('\n'),
    severity: a.event_severity,
    source_ip: a.source_ip || '',
    rule_id: a.rule_id || '',
  }
}

export default function Dashboard({ onCreateTicket }: { onCreateTicket?: (t: NewTicketInput) => void }) {
  const [health, setHealth] = useState<Health | null>(null)
  const [stats, setStats] = useState<Stats | null>(null)
  const [alerts, setAlerts] = useState<EventRow[]>([])
  const [updated, setUpdated] = useState<Date | null>(null)

  useEffect(() => {
    let active = true
    const tick = async () => {
      const h = await fetchHealth()
      if (active) setHealth(h)
      try {
        const [s, a] = await Promise.all([fetchStats(), fetchAlerts(15)])
        if (active) {
          setStats(s)
          setAlerts(a)
        }
      } catch {
        // API/DB not ready yet — leave empty
      }
      if (active) setUpdated(new Date())
    }
    void tick()
    const id = setInterval(tick, 5000)
    return () => {
      active = false
      clearInterval(id)
    }
  }, [])

  const services: { name: string; sub: string; state: DotState; detail: string }[] = [
    { name: 'API Server', sub: 'Go · :8080', state: health ? (health.api === 'alive' ? 'good' : 'bad') : 'unknown', detail: health?.api ?? 'checking…' },
    { name: 'PostgreSQL + TimescaleDB', sub: 'log storage', state: health ? depDot(health.postgres) : 'unknown', detail: health?.postgres ?? 'checking…' },
    { name: 'NATS JetStream', sub: 'message bus', state: health ? depDot(health.nats) : 'unknown', detail: health?.nats ?? 'checking…' },
  ]
  const allReady = health?.ready ?? false
  const maxSev = Math.max(1, ...(stats?.by_severity ?? []).map((s) => s.count))

  return (
    <div className="mx-auto max-w-6xl px-8 py-8">
      <header className="mb-8 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Dashboard</h1>
          <p className="mt-1 text-sm text-slate-500">DeusWatch status & detection · updates every 5s</p>
        </div>
        <div className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium ${allReady ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-amber-500/30 bg-amber-500/10 text-amber-300'}`}>
          <Dot state={allReady ? 'good' : 'unknown'} />
          {allReady ? 'All systems ready' : 'Waiting for dependencies'}
        </div>
      </header>

      {/* Counters */}
      <section className="mb-8 grid gap-3 sm:grid-cols-3">
        <StatCard label="Total event" value={stats?.total_events ?? '—'} />
        <StatCard label="Total alert" value={stats?.total_alerts ?? '—'} accent="text-orange-300" />
        <StatCard label="Alerts (24h)" value={stats?.alerts_24h ?? '—'} accent="text-rose-300" />
      </section>

      {/* Top IPs + Severity */}
      <section className="mb-8 grid gap-3 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Top source IP</h2>
          {stats?.top_source_ips?.length ? (
            <ul className="space-y-2">
              {stats.top_source_ips.map((ip) => (
                <li key={ip.ip} className="flex items-center justify-between text-sm">
                  <span className="font-mono text-slate-300">{ip.ip}</span>
                  <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-400">{ip.count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-600">no data yet</p>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Severity breakdown</h2>
          {stats?.by_severity?.length ? (
            <ul className="space-y-2">
              {stats.by_severity.map((s) => (
                <li key={s.severity} className="flex items-center gap-3 text-sm">
                  <span className="w-16"><SeverityBadge sev={s.severity} /></span>
                  <div className="h-2 flex-1 overflow-hidden rounded bg-slate-800">
                    <div className="h-full rounded bg-indigo-500" style={{ width: `${(s.count / maxSev) * 100}%` }} />
                  </div>
                  <span className="w-8 text-right text-xs text-slate-400">{s.count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-600">no data yet</p>
          )}
        </div>
      </section>

      {/* Recent alerts */}
      <section className="mb-8">
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Recent alerts</h2>
        <div className="overflow-hidden rounded-xl border border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Source IP</th>
                <th className="px-4 py-2 font-medium">Rule</th>
                <th className="px-4 py-2 font-medium">MITRE</th>
                <th className="px-4 py-2 font-medium">Threat Intel</th>
                <th className="px-4 py-2 font-medium">LLM</th>
                <th className="px-4 py-2 font-medium">Severity</th>
                {onCreateTicket && <th className="px-4 py-2 font-medium"></th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/40">
              {alerts.length ? (
                alerts.map((a, i) => (
                  <tr key={i} className="hover:bg-slate-800/40">
                    <td className="px-4 py-2 text-slate-400">{new Date(a.time).toLocaleString('en-US')}</td>
                    <td className="px-4 py-2 font-mono text-slate-300">{a.source_ip || '—'}</td>
                    <td className="px-4 py-2 text-slate-300">{a.rule_name || a.dw_label}</td>
                    <td className="px-4 py-2 text-slate-400">{a.threat_technique_id ? `${a.threat_technique_id} · ${a.threat_tactic_name}` : '—'}</td>
                    <td className="px-4 py-2"><ThreatIntel a={a} /></td>
                    <td className="px-4 py-2"><LLMVerdict a={a} /></td>
                    <td className="px-4 py-2"><SeverityBadge sev={a.event_severity} /></td>
                    {onCreateTicket && (
                      <td className="px-4 py-2 text-right">
                        <button
                          onClick={() => onCreateTicket(alertToTicket(a))}
                          className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800"
                          title="Raise a Tier-2 ticket from this alert"
                        >
                          + Ticket
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={onCreateTicket ? 8 : 7} className="px-4 py-6 text-center text-sm text-slate-600">
                    {health?.api === 'down' ? 'API unreachable — run docker compose up' : 'No alerts yet. Trigger an SSH brute-force to see them here.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-slate-600">
          {updated ? `Last updated ${updated.toLocaleTimeString('en-US')}` : 'Connecting to API…'}
        </p>
      </section>

      {/* System Health */}
      <section>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">System Health</h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {services.map((s) => (
            <div key={s.name} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-200">{s.name}</span>
                <Dot state={s.state} />
              </div>
              <div className="mt-1 text-xs text-slate-500">{s.sub}</div>
              <div className={`mt-3 font-mono text-sm ${s.state === 'good' ? 'text-emerald-400' : s.state === 'bad' ? 'text-rose-400' : 'text-amber-400'}`}>{s.detail}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
