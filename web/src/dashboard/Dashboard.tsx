import { useEffect, useState, Fragment, type ReactNode } from 'react'
import {
  fetchHealth, searchEvents, exportEventsToWebhook, fetchDashboardData, fetchLayout, saveLayout,
  fetchStorageStatus, requestFimRestore,
  SEVERITY, type DepState, type Health, type EventRow, type NewTicketInput,
  type DashboardData, type DashWidget, type WidgetKind, type DashRange, type EventSearch,
  type StorageStatus,
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
function FileHashBadge({ a }: { a: EventRow }) {
  const v = a.dw_filehash_verdict
  if (!v || v === 'unknown') return null
  const bad = v === 'known_bad'
  const cls = bad ? 'text-rose-300 bg-rose-500/15' : 'text-emerald-300 bg-emerald-500/15'
  const title = `${a.file_path || 'file'}${a.dw_filehash_detail ? ` — ${a.dw_filehash_detail}` : ''}`
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${cls}`} title={title}>
      {bad ? '☣ malware' : '✓ known-good'}
    </span>
  )
}
// ScoreDoughnut renders the composite threat score (0-100) as a small colored ring -
// higher = redder. Summarizes fired_times + AbuseIPDB + OTX + severity into one indicator.
function ScoreDoughnut({ score, band, title }: { score: number; band: string; title?: string }) {
  const color = band === 'critical' ? '#fb7185' : band === 'high' ? '#fb923c' : band === 'medium' ? '#fbbf24' : '#64748b'
  const r = 8
  const circ = 2 * Math.PI * r
  const off = circ * (1 - Math.max(0, Math.min(100, score)) / 100)
  return (
    <span title={title} className="inline-flex items-center">
      <svg width="24" height="24" viewBox="0 0 24 24">
        <circle cx="12" cy="12" r={r} fill="none" stroke="#1e293b" strokeWidth="3.5" />
        <circle cx="12" cy="12" r={r} fill="none" stroke={color} strokeWidth="3.5"
          strokeDasharray={circ} strokeDashoffset={off} strokeLinecap="round" transform="rotate(-90 12 12)" />
        <text x="12" y="12.5" textAnchor="middle" dominantBaseline="middle" fontSize="8.5" fontWeight="700" fill={color}>{score}</text>
      </svg>
    </span>
  )
}

function ThreatIntel({ a }: { a: EventRow }) {
  const abuse = a.dw_enrichment_abuse_confidence
  const otx = a.dw_enrichment_otx_pulse_count
  const hasFileVerdict = !!a.dw_filehash_verdict && a.dw_filehash_verdict !== 'unknown'
  const hasScore = a.threat_score > 0
  if (!hasScore && a.dw_enrichment_status !== 'enriched' && abuse == null && !hasFileVerdict) return <span className="text-slate-600">—</span>
  const abuseCls = abuse == null ? '' : abuse >= 90 ? 'text-rose-300 bg-rose-500/15' : abuse >= 50 ? 'text-amber-300 bg-amber-500/15' : 'text-slate-400 bg-slate-700/40'
  const scoreTitle = `Composite threat score ${a.threat_score}/100 (${a.threat_band})` +
    (abuse != null ? ` · abuse ${abuse}` : '') + (otx ? ` · otx ${otx}` : '')
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {hasScore && <ScoreDoughnut score={a.threat_score} band={a.threat_band} title={scoreTitle} />}
      {a.source_geo_country_iso && <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300" title={a.source_geo_city || undefined}>{a.source_geo_country_iso}</span>}
      {/* When there is no accumulated score yet, fall back to the raw CTI badges. */}
      {!hasScore && abuse != null && <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${abuseCls}`} title="AbuseIPDB confidence">abuse {abuse}</span>}
      {!hasScore && otx != null && otx > 0 && <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-xs font-medium text-violet-300" title="OTX pulses">otx {otx}</span>}
      <FileHashBadge a={a} />
      {a.dw_severity_escalated_by && <span className="rounded bg-orange-500/15 px-1.5 py-0.5 text-xs font-medium text-orange-300" title={`Escalated by: ${a.dw_severity_escalated_by}`}>↑</span>}
    </div>
  )
}

// RestoreButton requests that the reporting agent revert a modified/defaced file to its
// known-good snapshot. Manual, one-click - never fires automatically.
function RestoreButton({ agent, path }: { agent: string; path: string }) {
  const [state, setState] = useState<'idle' | 'busy' | 'done' | 'err'>('idle')
  const [msg, setMsg] = useState('')
  const onClick = async (e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm(`Restore ${path} on ${agent} to its known-good snapshot? This overwrites the current file on the endpoint.`)) return
    setState('busy'); setMsg('')
    try { await requestFimRestore(agent, path); setState('done') }
    catch (err) { setState('err'); setMsg((err as Error).message) }
  }
  if (state === 'done') return <span className="text-xs text-emerald-400">✓ restore requested (applies within ~15s)</span>
  return (
    <span className="flex items-center gap-2">
      {state === 'err' && <span className="text-xs text-rose-400" title={msg}>failed</span>}
      <button onClick={onClick} disabled={state === 'busy'}
        className="rounded-md border border-amber-700/60 px-2 py-1 text-xs text-amber-200 hover:bg-amber-500/10 disabled:opacity-50">
        {state === 'busy' ? 'Requesting…' : 'Restore file'}
      </button>
    </span>
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

// ── Time-range picker ──────────────────────────────────────
const RANGE_PRESETS: { label: string; hours: number }[] = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 24 * 7 },
  { label: '30d', hours: 24 * 30 },
]

// localInput formats a Date for a datetime-local input (local time, minute precision).
function localInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

// resolveRange turns the picker state into a DashRange, or null if the custom
// inputs are incomplete/invalid (caller skips fetching until valid).
function resolveRange(preset: number | 'custom', from: string, to: string): DashRange | null {
  if (preset !== 'custom') return { hours: preset }
  if (!from || !to) return null
  const f = new Date(from)
  const t = new Date(to)
  if (isNaN(+f) || isNaN(+t)) return null
  return { from: f, to: t }
}

function TimeRangePicker({
  preset, from, to, onPreset, onFrom, onTo,
}: {
  preset: number | 'custom'
  from: string
  to: string
  onPreset: (h: number | 'custom') => void
  onFrom: (v: string) => void
  onTo: (v: string) => void
}) {
  const startCustom = () => {
    if (!to) onTo(localInput(new Date()))
    if (!from) onFrom(localInput(new Date(Date.now() - 24 * 3600 * 1000)))
    onPreset('custom')
  }
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {RANGE_PRESETS.map((r) => (
        <button
          key={r.label}
          onClick={() => onPreset(r.hours)}
          className={`rounded-md border px-2 py-1 text-xs font-medium transition-colors ${
            preset === r.hours ? 'border-indigo-500 bg-indigo-500/10 text-indigo-300' : 'border-slate-700 text-slate-400 hover:bg-slate-800'
          }`}
        >
          {r.label}
        </button>
      ))}
      <button
        onClick={startCustom}
        className={`rounded-md border px-2 py-1 text-xs font-medium transition-colors ${
          preset === 'custom' ? 'border-indigo-500 bg-indigo-500/10 text-indigo-300' : 'border-slate-700 text-slate-400 hover:bg-slate-800'
        }`}
      >
        Custom
      </button>
      {preset === 'custom' && (
        <div className="flex flex-wrap items-center gap-1.5">
          <input
            type="datetime-local"
            value={from}
            max={to || undefined}
            onChange={(e) => onFrom(e.target.value)}
            className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 outline-none focus:border-indigo-500 [color-scheme:dark]"
          />
          <span className="text-xs text-slate-500">→</span>
          <input
            type="datetime-local"
            value={to}
            min={from || undefined}
            onChange={(e) => onTo(e.target.value)}
            className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 outline-none focus:border-indigo-500 [color-scheme:dark]"
          />
        </div>
      )}
    </div>
  )
}

export default function Dashboard({ onCreateTicket }: { onCreateTicket?: (t: NewTicketInput) => void }) {
  const [health, setHealth] = useState<Health | null>(null)
  const [storage, setStorage] = useState<StorageStatus | null>(null)
  const [data, setData] = useState<DashboardData | null>(null)
  const [updated, setUpdated] = useState<Date | null>(null)
  // Time range: a preset number of hours, or 'custom' with from/to (datetime-local strings).
  const [preset, setPreset] = useState<number | 'custom'>(24)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [widgets, setWidgets] = useState<DashWidget[]>(defaultWidgets())
  const [edit, setEdit] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [addSource, setAddSource] = useState('severity')
  // Drag-and-drop reorder state: which widget is dragging, which is the drop target,
  // and which one's grip handle armed the drag.
  const [dragId, setDragId] = useState<string | null>(null)
  const [overId, setOverId] = useState<string | null>(null)
  const [grip, setGrip] = useState<string | null>(null)

  // Load the saved layout once.
  useEffect(() => {
    fetchLayout()
      .then((l) => { if (l?.widgets?.length) setWidgets(l.widgets) })
      .catch(() => {})
  }, [])

  // Poll live data for the selected time range. Re-subscribes when the range
  // changes; a custom range with incomplete inputs simply skips the data fetch.
  useEffect(() => {
    let active = true
    const tick = async () => {
      const h = await fetchHealth()
      if (active) setHealth(h)
      fetchStorageStatus().then((s) => { if (active) setStorage(s) }).catch(() => {})
      const range = resolveRange(preset, from, to)
      if (range) {
        try {
          const d = await fetchDashboardData(range)
          if (active) setData(d)
        } catch {
          /* API/DB not ready */
        }
      }
      if (active) setUpdated(new Date())
    }
    void tick()
    const id = setInterval(tick, 5000)
    return () => { active = false; clearInterval(id) }
  }, [preset, from, to])

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
  // reorder moves the dragged widget to the drop target's position.
  const reorder = (fromId: string, toId: string) =>
    mutate((ws) => {
      const from = ws.findIndex((w) => w.id === fromId)
      const to = ws.findIndex((w) => w.id === toId)
      if (from < 0 || to < 0 || from === to) return ws
      const next = [...ws]
      const [moved] = next.splice(from, 1)
      next.splice(to, 0, moved)
      return next
    })
  const clearDrag = () => { setDragId(null); setOverId(null); setGrip(null) }
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
          <div className="mt-3">
            <TimeRangePicker
              preset={preset}
              from={from}
              to={to}
              onPreset={(h) => setPreset(h)}
              onFrom={setFrom}
              onTo={setTo}
            />
          </div>
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
          <span className="text-xs text-slate-600">· drag the ⠿ handle to reorder (or use ↑ ↓); swatches recolor, the type menu switches chart.</span>
        </div>
      )}

      {/* Customizable widget grid */}
      <section className="mb-8 grid gap-3 lg:grid-cols-2">
        {widgets.map((w) => (
          <div
            key={w.id}
            draggable={edit && grip === w.id}
            onDragStart={(e) => { setDragId(w.id); e.dataTransfer.effectAllowed = 'move' }}
            onDragOver={(e) => { if (edit && dragId && dragId !== w.id) { e.preventDefault(); setOverId(w.id) } }}
            onDragLeave={() => setOverId((o) => (o === w.id ? null : o))}
            onDrop={(e) => { e.preventDefault(); if (dragId) reorder(dragId, w.id); clearDrag() }}
            onDragEnd={clearDrag}
            className={`rounded-xl border bg-slate-900/60 p-4 transition-all ${w.wide ? 'lg:col-span-2' : ''} ${
              overId === w.id ? 'border-indigo-400 ring-2 ring-indigo-400/40' : 'border-slate-800'
            } ${dragId === w.id ? 'opacity-40' : ''}`}
          >
            <div className="mb-3 flex items-center justify-between gap-2">
              <div className="flex min-w-0 flex-1 items-center gap-2">
                {edit && (
                  <span
                    onMouseDown={() => setGrip(w.id)}
                    onMouseUp={() => setGrip(null)}
                    className="cursor-grab select-none text-base leading-none text-slate-600 hover:text-slate-300 active:cursor-grabbing"
                    title="Drag to reorder"
                  >
                    ⠿
                  </span>
                )}
                {edit ? (
                  <input value={w.title} onChange={(e) => patch(w.id, { title: e.target.value })} className="min-w-0 flex-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 outline-none focus:border-indigo-500" />
                ) : (
                  <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500">{w.title}</h2>
                )}
              </div>
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

      {/* Searchable events & alerts — filter by IP / rule / MITRE / level / time */}
      <EventsPanel onCreateTicket={onCreateTicket} apiDown={health?.api === 'down'} />

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

      {/* Log storage (fixed) */}
      <StoragePanel s={storage} />
    </div>
  )
}

function StoragePanel({ s }: { s: StorageStatus | null }) {
  const pct = s?.budget_bytes ? Math.min(100, s.used_percent) : null
  const barColor = pct == null ? 'bg-slate-600' : pct >= 90 ? 'bg-rose-500' : pct >= 75 ? 'bg-amber-500' : 'bg-emerald-500'
  const repl = s?.replication
  return (
    <section className="mt-6">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Log Storage</h2>
      <div className="grid gap-3 sm:grid-cols-3">
        {/* Capacity */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-200">Database size</span>
            <Dot state={!s ? 'unknown' : s.reachable ? (pct != null && pct >= 90 ? 'bad' : 'good') : 'bad'} />
          </div>
          <div className="mt-1 text-xs text-slate-500">{s?.host ? `host: ${s.host}` : 'log storage'}</div>
          <div className="mt-3 font-mono text-sm text-slate-200">
            {!s ? 'checking…' : !s.reachable ? 'unreachable' : s.db_size_pretty}
            {s?.reachable && <span className="text-slate-500"> · {s.events_count.toLocaleString('en-US')} events</span>}
          </div>
          {pct != null && (
            <div className="mt-2">
              <div className="h-2 overflow-hidden rounded bg-slate-800">
                <div className={`h-full rounded ${barColor}`} style={{ width: `${pct}%` }} />
              </div>
              <div className="mt-1 text-xs text-slate-500">{pct}% of {(s!.budget_bytes / 1073741824).toFixed(0)} GB budget</div>
            </div>
          )}
          {s?.reachable && !s.budget_bytes && <div className="mt-2 text-xs text-slate-600">set STORAGE_BUDGET_GB for a usage bar + near-full alerts</div>}
        </div>

        {/* Lifecycle (retention + compression = ILM equivalent) */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-200">Lifecycle</span>
            <Dot state={s?.reachable ? 'good' : s ? 'unknown' : 'unknown'} />
          </div>
          <div className="mt-1 text-xs text-slate-500">TimescaleDB retention + compression</div>
          <div className="mt-3 font-mono text-sm text-slate-200">
            {s?.retention_days != null ? `retention ${s.retention_days}d` : 'retention: —'}
          </div>
          <div className="font-mono text-xs text-slate-500">
            {s?.compression_days != null ? `compress after ${s.compression_days}d` : 'compression: —'}
          </div>
        </div>

        {/* Replication */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-200">Replication</span>
            <Dot state={!repl ? 'unknown' : repl.enabled ? 'good' : 'unknown'} />
          </div>
          <div className="mt-1 text-xs text-slate-500">PostgreSQL streaming</div>
          <div className={`mt-3 font-mono text-sm ${repl?.enabled ? 'text-emerald-400' : 'text-amber-400'}`}>
            {!repl ? 'checking…' : repl.enabled ? 'active' : 'not configured'}
          </div>
          {repl?.standbys?.length ? (
            <div className="mt-1 font-mono text-xs text-slate-500">{repl.standbys.join(', ')}</div>
          ) : null}
        </div>
      </div>
    </section>
  )
}

// ── Searchable events & alerts table ───────────────────────
const ROW_OPTIONS = [5, 20, 50, 100]
const SEV_OPTIONS: { label: string; value: number }[] = [
  { label: 'Any level', value: -1 },
  { label: 'Info+', value: 0 },
  { label: 'Low+', value: 1 },
  { label: 'Medium+', value: 2 },
  { label: 'High+', value: 3 },
  { label: 'Critical', value: 4 },
]
const fieldCls =
  'rounded-md border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-200 outline-none focus:border-indigo-500 [color-scheme:dark]'

// cleanEvent drops empty/null fields so the expanded "full log" JSON shows only what the
// event actually carries (Wazuh-style), rather than a wall of blank keys.
function cleanEvent(a: EventRow): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(a)) {
    if (v === '' || v === null || v === undefined) continue
    // Already rendered in their own blocks above the JSON (Recommended playbook /
    // File change diff) - repeating the multi-line text here becomes one very long
    // cut-off line that drowns the rest of the log.
    if (k === 'dw_remediation_action' || k === 'file_diff') continue
    out[k] = v
  }
  return out
}

function EventsPanel({ onCreateTicket, apiDown }: { onCreateTicket?: (t: NewTicketInput) => void; apiDown: boolean }) {
  const [rows, setRows] = useState<EventRow[]>([])
  const [expanded, setExpanded] = useState<number | null>(null)
  const [q, setQ] = useState('')
  const [ip, setIp] = useState('')
  const [agent, setAgent] = useState('')
  const [rule, setRule] = useState('')
  const [technique, setTechnique] = useState('')
  const [severity, setSeverity] = useState(-1)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [alertsOnly, setAlertsOnly] = useState(true) // default to alerts to keep the table clean; uncheck to see all events
  const [limit, setLimit] = useState(20)
  const [updated, setUpdated] = useState<Date | null>(null)
  const [open, setOpen] = useState(false)

  // Fetch on any filter change (debounced) + a periodic refresh.
  useEffect(() => {
    let active = true
    const load = () => {
      const f: EventSearch = {
        q: q || undefined,
        ip: ip || undefined,
        agent: agent || undefined,
        rule: rule || undefined,
        technique: technique || undefined,
        severity: severity >= 0 ? severity : undefined,
        alerts: alertsOnly || undefined,
        from: from ? new Date(from).toISOString() : undefined,
        to: to ? new Date(to).toISOString() : undefined,
        limit,
      }
      searchEvents(f)
        .then((r) => { if (active) { setRows(r); setUpdated(new Date()) } })
        .catch(() => {})
    }
    const t = setTimeout(load, 300)
    const id = setInterval(load, 10_000)
    return () => { active = false; clearTimeout(t); clearInterval(id) }
  }, [q, ip, agent, rule, technique, severity, from, to, alertsOnly, limit])

  const hasFilter = !!(ip || agent || rule || technique || severity >= 0 || from || to || alertsOnly)
  const reset = () => {
    setIp(''); setAgent(''); setRule(''); setTechnique(''); setSeverity(-1); setFrom(''); setTo(''); setAlertsOnly(false)
  }
  const [whMsg, setWhMsg] = useState('')
  const sendWebhook = async () => {
    setWhMsg('Sending…')
    try {
      const n = await exportEventsToWebhook({
        q: q || undefined, ip: ip || undefined, agent: agent || undefined, rule: rule || undefined, technique: technique || undefined,
        severity: severity >= 0 ? severity : undefined, alerts: alertsOnly || undefined,
        from: from ? new Date(from).toISOString() : undefined, to: to ? new Date(to).toISOString() : undefined, limit,
      })
      setWhMsg(`Sent ${n} ✓`)
    } catch (e) {
      setWhMsg((e as Error).message)
    }
  }

  return (
    <section className="mb-8">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
          Events &amp; Alerts
          <span className="ml-2 normal-case text-slate-600">{rows.length} shown</span>
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search logs… (IP, rule, host, file, message)"
            className={`${fieldCls} w-64`}
          />
          <button
            onClick={() => setOpen((o) => !o)}
            className={`rounded-md border px-2.5 py-1.5 text-xs font-medium ${hasFilter || open ? 'border-indigo-500 bg-indigo-500/10 text-indigo-300' : 'border-slate-700 text-slate-300 hover:bg-slate-800'}`}
          >
            ⛃ Filters{hasFilter ? ' ·' : ''}
          </button>
          <button
            onClick={sendWebhook}
            className="rounded-md border border-slate-700 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800"
            title="Send these filtered events as JSON to the configured export webhook"
          >
            ↗ Webhook
          </button>
          {whMsg && <span className="text-xs text-slate-500">{whMsg}</span>}
          <label className="flex items-center gap-1 text-xs text-slate-400">
            Show
            <select value={limit} onChange={(e) => setLimit(Number(e.target.value))} className={fieldCls}>
              {ROW_OPTIONS.map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {open && (
        <div className="mb-3 flex flex-wrap items-end gap-2 rounded-xl border border-indigo-500/30 bg-indigo-500/5 px-4 py-3">
          <Field label="Source IP"><input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g. 45.155" className={`${fieldCls} w-32`} /></Field>
          <Field label="Agent"><input value={agent} onChange={(e) => setAgent(e.target.value)} placeholder="agent name" className={`${fieldCls} w-32`} /></Field>
          <Field label="Rule"><input value={rule} onChange={(e) => setRule(e.target.value)} placeholder="rule id/name" className={`${fieldCls} w-36`} /></Field>
          <Field label="MITRE ID"><input value={technique} onChange={(e) => setTechnique(e.target.value)} placeholder="e.g. T1110" className={`${fieldCls} w-28`} /></Field>
          <Field label="Min level">
            <select value={severity} onChange={(e) => setSeverity(Number(e.target.value))} className={fieldCls}>
              {SEV_OPTIONS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
            </select>
          </Field>
          <Field label="From"><input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} className={fieldCls} /></Field>
          <Field label="To"><input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} className={fieldCls} /></Field>
          <label className="flex items-center gap-1.5 px-1 text-xs text-slate-300">
            <input type="checkbox" checked={alertsOnly} onChange={(e) => setAlertsOnly(e.target.checked)} className="h-4 w-4 accent-indigo-500" />
            Alerts only
          </label>
          {hasFilter && (
            <button onClick={reset} className="rounded-md border border-slate-700 px-2.5 py-1.5 text-xs text-slate-400 hover:bg-slate-800 hover:text-rose-300">Clear</button>
          )}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2 font-medium">Time</th>
              <th className="px-4 py-2 font-medium">Agent</th>
              <th className="px-4 py-2 font-medium">Source IP</th>
              <th className="px-4 py-2 font-medium">Rule / Event</th>
              <th className="px-4 py-2 font-medium">MITRE</th>
              <th className="px-4 py-2 font-medium">Threat Intel</th>
              <th className="px-4 py-2 font-medium">LLM</th>
              <th className="px-4 py-2 font-medium">Severity</th>
              {onCreateTicket && <th className="px-4 py-2 font-medium"></th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {rows.length ? (
              rows.map((a, i) => (
                <Fragment key={i}>
                  <tr
                    className="cursor-pointer hover:bg-slate-800/40"
                    onClick={() => setExpanded(expanded === i ? null : i)}
                    title="Click to view the full JSON log"
                  >
                    <td className="px-4 py-2 text-slate-400">{new Date(a.time).toLocaleString('en-US')}</td>
                    <td className="px-4 py-2 text-slate-300">
                      {a.agent_id ? (
                        <button
                          onClick={(e) => { e.stopPropagation(); setAgent(a.agent_id); setOpen(true) }}
                          className="rounded text-slate-300 hover:text-indigo-300"
                          title={`Filter by agent ${a.agent_id}`}
                        >
                          {a.agent_id}
                        </button>
                      ) : '—'}
                    </td>
                    <td className="px-4 py-2 font-mono text-slate-300">{a.source_ip || '—'}</td>
                    <td className="px-4 py-2 text-slate-300">
                      {a.rule_name || a.dw_label || a.event_action || a.event_category || '—'}
                      {a.file_path && (
                        <span className="mt-0.5 block truncate text-xs text-slate-500" title={a.file_path}>
                          location: <span className="font-mono text-slate-400">{a.file_path}</span>
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-slate-400">{a.threat_technique_id ? `${a.threat_technique_id} · ${a.threat_tactic_name}` : '—'}</td>
                    <td className="px-4 py-2"><ThreatIntel a={a} /></td>
                    <td className="px-4 py-2"><LLMVerdict a={a} /></td>
                    <td className="px-4 py-2"><SeverityBadge sev={a.event_severity} /></td>
                    {onCreateTicket && (
                      <td className="px-4 py-2 text-right">
                        <button onClick={(e) => { e.stopPropagation(); onCreateTicket(alertToTicket(a)) }} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800" title="Raise a Tier-2 ticket from this event">+ Ticket</button>
                      </td>
                    )}
                  </tr>
                  {expanded === i && (
                    <tr className="bg-slate-950/60">
                      <td colSpan={onCreateTicket ? 9 : 8} className="px-4 py-3">
                        {a.dw_remediation_action && (
                          <div className="mb-3 rounded-lg border border-indigo-900/50 bg-indigo-500/5 p-3">
                            <div className="mb-1 text-xs font-medium uppercase tracking-wider text-indigo-300">
                              Recommended playbook {a.dw_remediation_source === 'playbook' ? '' : `(${a.dw_remediation_source})`}
                            </div>
                            <pre className="whitespace-pre-wrap text-sm leading-relaxed text-slate-300">{a.dw_remediation_action}</pre>
                          </div>
                        )}
                        {(a.file_diff || (a.event_category === 'file' && a.file_path)) && (
                          <div className="mb-3 rounded-lg border border-amber-900/50 bg-amber-500/5 p-3">
                            <div className="mb-1 flex items-center justify-between">
                              <span className="text-xs font-medium uppercase tracking-wider text-amber-300">
                                File change{a.file_path ? ` — ${a.file_path}` : ''}
                              </span>
                              {a.file_path && a.agent_id && <RestoreButton agent={a.agent_id} path={a.file_path} />}
                            </div>
                            {(a.process_name || a.user_name) && (
                              <div className="mb-2 text-xs text-slate-400">
                                changed by{' '}
                                {a.process_name && (
                                  <span className="font-mono text-amber-200">
                                    {a.process_name}{a.process_pid ? ` (pid ${a.process_pid})` : ''}
                                  </span>
                                )}
                                {a.user_name && (
                                  <> {a.process_name ? 'as user ' : 'user '}<span className="font-mono text-amber-200">{a.user_name}</span></>
                                )}
                                <span className="ml-1 text-slate-600">· who-data</span>
                              </div>
                            )}
                            {a.file_diff && (
                              <pre className="max-h-80 overflow-auto rounded bg-slate-950 p-2 font-mono text-xs leading-relaxed">
                                {a.file_diff.split('\n').map((line, k) => (
                                  <div key={k} className={line.startsWith('+') ? 'text-emerald-400' : line.startsWith('-') ? 'text-rose-400' : 'text-slate-500'}>{line}</div>
                                ))}
                              </pre>
                            )}
                          </div>
                        )}
                        <div className="mb-1 text-xs font-medium uppercase tracking-wider text-slate-500">Full log (JSON)</div>
                        <pre className="max-h-96 overflow-y-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs leading-relaxed text-slate-300">
{JSON.stringify(cleanEvent(a), null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))
            ) : (
              <tr>
                <td colSpan={onCreateTicket ? 9 : 8} className="px-4 py-6 text-center text-sm text-slate-600">
                  {apiDown ? 'API unreachable — run docker compose up' : hasFilter || q ? 'No events match these filters.' : 'No events yet.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs text-slate-600">{updated ? `Last updated ${updated.toLocaleTimeString('en-US')}` : 'Loading…'}</p>
    </section>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-slate-500">
      {label}
      {children}
    </label>
  )
}
