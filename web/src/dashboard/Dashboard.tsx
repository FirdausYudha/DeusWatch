import { useEffect, useState } from 'react'
import {
  fetchHealth, fetchAlerts, fetchDashboardData, fetchLayout, saveLayout,
  SEVERITY, type DepState, type Health, type EventRow, type NewTicketInput,
  type DashboardData, type DashWidget, type WidgetKind,
} from '../lib/api'
import { StatWidget, BarChart, DonutChart, LineChart, TableWidget, AttackMap, WIDGET_COLORS } from './widgets'

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
function LLMVerdict({ a }: { a: EventRow }) {
  if (!a.dw_llm_verdict) return <span className="text-slate-600">—</span>
  const cls = VERDICT_BADGE[a.dw_llm_verdict] ?? 'text-slate-400 bg-slate-700/40'
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${cls}`} title={a.dw_llm_summary || undefined}>{a.dw_llm_verdict}</span>
}
function ThreatIntel({ a }: { a: EventRow }) {
  const abuse = a.dw_enrichment_abuse_confidence
  const otx = a.dw_enrichment_otx_pulse_count
  if (a.dw_enrichment_status !== 'enriched' && abuse == null) return <span className="text-slate-600">—</span>
  const abuseCls = abuse == null ? '' : abuse >= 90 ? 'text-rose-300 bg-rose-500/15' : abuse >= 50 ? 'text-amber-300 bg-amber-500/15' : 'text-slate-400 bg-slate-700/40'
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {a.source_geo_country_iso && <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300" title={a.source_geo_city || undefined}>{a.source_geo_country_iso}</span>}
      {abuse != null && <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${abuseCls}`} title="AbuseIPDB confidence">abuse {abuse}</span>}
      {otx != null && otx > 0 && <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-xs font-medium text-violet-300" title="OTX pulses">otx {otx}</span>}
      {a.dw_severity_escalated_by && <span className="rounded bg-orange-500/15 px-1.5 py-0.5 text-xs font-medium text-orange-300" title={`Escalated by: ${a.dw_severity_escalated_by}`}>↑</span>}
    </div>
  )
}

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

// ── Widget layout catalog ──────────────────────────────────
const uid = () => Math.random().toString(36).slice(2, 10)
const STAT_SOURCES = ['total_events', 'total_alerts', 'alerts_24h']

const SOURCES: { source: string; label: string; kind: WidgetKind }[] = [
  { source: 'total_events', label: 'Total events (stat)', kind: 'stat' },
  { source: 'total_alerts', label: 'Total alerts (stat)', kind: 'stat' },
  { source: 'alerts_24h', label: 'Alerts 24h (stat)', kind: 'stat' },
  { source: 'timeline', label: 'Events over time (line)', kind: 'line' },
  { source: 'severity', label: 'Severity breakdown', kind: 'bar' },
  { source: 'source_ips', label: 'Top source IPs', kind: 'bar' },
  { source: 'rules', label: 'Top rules', kind: 'bar' },
  { source: 'techniques', label: 'Top MITRE techniques', kind: 'bar' },
  { source: 'verdicts', label: 'LLM verdicts', kind: 'donut' },
  { source: 'countries', label: 'Attack origins (map)', kind: 'map' },
]

function kindsFor(source: string): WidgetKind[] {
  if (STAT_SOURCES.includes(source)) return ['stat']
  if (source === 'timeline') return ['line']
  if (source === 'countries') return ['map', 'bar', 'donut', 'table']
  return ['bar', 'donut', 'table']
}

function defaultWidgets(): DashWidget[] {
  const mk = (w: Omit<DashWidget, 'id'>): DashWidget => ({ id: uid(), ...w })
  return [
    mk({ kind: 'stat', source: 'total_events', title: 'Total events', color: '#6366f1', wide: false }),
    mk({ kind: 'stat', source: 'total_alerts', title: 'Total alerts', color: '#fb923c', wide: false }),
    mk({ kind: 'stat', source: 'alerts_24h', title: 'Alerts (24h)', color: '#f43f5e', wide: false }),
    mk({ kind: 'line', source: 'timeline', title: 'Events over time', color: '#6366f1', wide: true }),
    mk({ kind: 'bar', source: 'severity', title: 'Severity breakdown', color: '#6366f1', wide: false }),
    mk({ kind: 'bar', source: 'source_ips', title: 'Top source IPs', color: '#38bdf8', wide: false }),
    mk({ kind: 'donut', source: 'verdicts', title: 'LLM verdicts', color: '#8b5cf6', wide: false }),
    mk({ kind: 'map', source: 'countries', title: 'Attack origins', color: '#f43f5e', wide: true }),
  ]
}

function WidgetBody({ w, data }: { w: DashWidget; data: DashboardData | null }) {
  if (!data) return <p className="py-6 text-center text-sm text-slate-600">loading…</p>
  switch (w.kind) {
    case 'stat': {
      const v = w.source === 'total_alerts' ? data.total_alerts : w.source === 'alerts_24h' ? data.alerts_24h : data.total_events
      return <StatWidget value={v} color={w.color} />
    }
    case 'line':
      return <LineChart points={data.timeline} color={w.color} />
    case 'donut':
      return <DonutChart data={data.series[w.source] ?? []} color={w.color} />
    case 'table':
      return <TableWidget data={data.series[w.source] ?? []} />
    case 'map':
      return <AttackMap data={data.series['countries'] ?? []} color={w.color} />
    default:
      return <BarChart data={data.series[w.source] ?? []} color={w.color} />
  }
}

export default function Dashboard({ onCreateTicket }: { onCreateTicket?: (t: NewTicketInput) => void }) {
  const [health, setHealth] = useState<Health | null>(null)
  const [alerts, setAlerts] = useState<EventRow[]>([])
  const [data, setData] = useState<DashboardData | null>(null)
  const [updated, setUpdated] = useState<Date | null>(null)
  const [widgets, setWidgets] = useState<DashWidget[]>(defaultWidgets())
  const [edit, setEdit] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [addSource, setAddSource] = useState('severity')

  // Load the saved layout once.
  useEffect(() => {
    fetchLayout()
      .then((l) => { if (l?.widgets?.length) setWidgets(l.widgets) })
      .catch(() => {})
  }, [])

  // Poll live data.
  useEffect(() => {
    let active = true
    const tick = async () => {
      const h = await fetchHealth()
      if (active) setHealth(h)
      try {
        const [d, a] = await Promise.all([fetchDashboardData(24), fetchAlerts(15)])
        if (active) { setData(d); setAlerts(a) }
      } catch {
        /* API/DB not ready */
      }
      if (active) setUpdated(new Date())
    }
    void tick()
    const id = setInterval(tick, 5000)
    return () => { active = false; clearInterval(id) }
  }, [])

  const mutate = (fn: (ws: DashWidget[]) => DashWidget[]) => { setWidgets(fn); setDirty(true) }
  const patch = (id: string, p: Partial<DashWidget>) => mutate((ws) => ws.map((w) => (w.id === id ? { ...w, ...p } : w)))
  const remove = (id: string) => mutate((ws) => ws.filter((w) => w.id !== id))
  const move = (id: string, dir: -1 | 1) =>
    mutate((ws) => {
      const i = ws.findIndex((w) => w.id === id)
      const j = i + dir
      if (i < 0 || j < 0 || j >= ws.length) return ws
      const next = [...ws]
      ;[next[i], next[j]] = [next[j], next[i]]
      return next
    })
  const add = () => {
    const meta = SOURCES.find((s) => s.source === addSource)!
    mutate((ws) => [...ws, { id: uid(), kind: meta.kind, source: meta.source, title: meta.label.replace(/ \(.*\)$/, ''), color: '#6366f1', wide: meta.kind === 'line' || meta.kind === 'map' }])
  }
  const save = async () => {
    try {
      await saveLayout({ widgets })
      setDirty(false)
    } catch {
      /* ignore */
    }
  }
  const reset = () => { setWidgets(defaultWidgets()); setDirty(true) }

  const services: { name: string; sub: string; state: DotState; detail: string }[] = [
    { name: 'API Server', sub: 'Go · :8080', state: health ? (health.api === 'alive' ? 'good' : 'bad') : 'unknown', detail: health?.api ?? 'checking…' },
    { name: 'PostgreSQL + TimescaleDB', sub: 'log storage', state: health ? depDot(health.postgres) : 'unknown', detail: health?.postgres ?? 'checking…' },
    { name: 'NATS JetStream', sub: 'message bus', state: health ? depDot(health.nats) : 'unknown', detail: health?.nats ?? 'checking…' },
  ]
  const allReady = health?.ready ?? false

  return (
    <div className="mx-auto max-w-6xl px-8 py-8">
      <header className="mb-6 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Dashboard</h1>
          <p className="mt-1 text-sm text-slate-500">DeusWatch detection · updates every 5s</p>
        </div>
        <div className="flex items-center gap-2">
          {edit && (
            <>
              <button onClick={reset} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800">Reset</button>
              <button onClick={save} disabled={!dirty} className="rounded-lg bg-indigo-500 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-400 disabled:opacity-50">
                {dirty ? 'Save layout' : 'Saved'}
              </button>
            </>
          )}
          <button
            onClick={() => setEdit((e) => !e)}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${edit ? 'border-indigo-500 bg-indigo-500/10 text-indigo-300' : 'border-slate-700 text-slate-300 hover:bg-slate-800'}`}
          >
            {edit ? 'Done' : '✎ Customize'}
          </button>
          <div className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium ${allReady ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-amber-500/30 bg-amber-500/10 text-amber-300'}`}>
            <Dot state={allReady ? 'good' : 'unknown'} />
            {allReady ? 'Ready' : 'Waiting'}
          </div>
        </div>
      </header>

      {edit && (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-xl border border-indigo-500/30 bg-indigo-500/5 px-4 py-3 text-sm">
          <span className="text-xs font-medium text-slate-400">Add widget:</span>
          <select value={addSource} onChange={(e) => setAddSource(e.target.value)} className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm outline-none focus:border-indigo-500">
            {SOURCES.map((s) => <option key={s.source} value={s.source}>{s.label}</option>)}
          </select>
          <button onClick={add} className="rounded-lg bg-indigo-500 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-400">+ Add</button>
          <span className="text-xs text-slate-600">· drag-free: use ↑ ↓ on each widget to reorder, the swatches to recolor, and the type menu to switch chart.</span>
        </div>
      )}

      {/* Customizable widget grid */}
      <section className="mb-8 grid gap-3 lg:grid-cols-2">
        {widgets.map((w) => (
          <div key={w.id} className={`rounded-xl border border-slate-800 bg-slate-900/60 p-4 ${w.wide ? 'lg:col-span-2' : ''}`}>
            <div className="mb-3 flex items-center justify-between gap-2">
              {edit ? (
                <input value={w.title} onChange={(e) => patch(w.id, { title: e.target.value })} className="min-w-0 flex-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 outline-none focus:border-indigo-500" />
              ) : (
                <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500">{w.title}</h2>
              )}
              {edit && (
                <div className="flex shrink-0 items-center gap-1">
                  {kindsFor(w.source).length > 1 && (
                    <select value={w.kind} onChange={(e) => patch(w.id, { kind: e.target.value as WidgetKind })} className="rounded border border-slate-700 bg-slate-800 px-1 py-0.5 text-[11px] text-slate-300 outline-none">
                      {kindsFor(w.source).map((k) => <option key={k} value={k}>{k}</option>)}
                    </select>
                  )}
                  <div className="flex items-center gap-0.5">
                    {WIDGET_COLORS.map((c) => (
                      <button key={c} onClick={() => patch(w.id, { color: c })} title={c} className={`h-3.5 w-3.5 rounded-full ${w.color === c ? 'ring-2 ring-white/60' : ''}`} style={{ background: c }} />
                    ))}
                  </div>
                  <button onClick={() => patch(w.id, { wide: !w.wide })} title="Toggle width" className={`rounded border px-1 text-[11px] ${w.wide ? 'border-indigo-500 text-indigo-300' : 'border-slate-700 text-slate-400'}`}>↔</button>
                  <button onClick={() => move(w.id, -1)} title="Move up" className="rounded border border-slate-700 px-1 text-[11px] text-slate-400 hover:bg-slate-800">↑</button>
                  <button onClick={() => move(w.id, 1)} title="Move down" className="rounded border border-slate-700 px-1 text-[11px] text-slate-400 hover:bg-slate-800">↓</button>
                  <button onClick={() => remove(w.id)} title="Remove" className="rounded border border-rose-900/60 px-1 text-[11px] text-rose-300 hover:bg-rose-500/10">✕</button>
                </div>
              )}
            </div>
            <WidgetBody w={w} data={data} />
          </div>
        ))}
        {widgets.length === 0 && (
          <p className="lg:col-span-2 rounded-xl border border-dashed border-slate-800 px-4 py-10 text-center text-sm text-slate-600">
            No widgets. Click “Customize” to add some.
          </p>
        )}
      </section>

      {/* Recent alerts (fixed) — raise tickets from here */}
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
                        <button onClick={() => onCreateTicket(alertToTicket(a))} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800" title="Raise a Tier-2 ticket from this alert">+ Ticket</button>
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
        <p className="mt-3 text-xs text-slate-600">{updated ? `Last updated ${updated.toLocaleTimeString('en-US')}` : 'Connecting to API…'}</p>
      </section>

      {/* System Health (fixed) */}
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
