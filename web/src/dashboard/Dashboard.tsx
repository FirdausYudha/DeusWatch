import { useEffect, useState, Fragment, type ReactNode } from 'react'
import {
  fetchHealth, searchEvents, exportEventsToWebhook, fetchDashboardData,
  fetchStorageStatus, requestFimRestore,
  fetchLayout, saveLayout, deleteLayout,
  SEVERITY, type DepState, type Health, type EventRow, type NewTicketInput,
  type DashboardData, type WidgetKind, type EventSearch, type DashRange,
  type StorageStatus, type TimelineBucket,
} from '../lib/api'
import { StatWidget, BarChart, DonutChart, LineChart, TableWidget, AttackMap, RiskyIPsWidget, SuspiciousIPsWidget, SlowScannerWidget, AgentsWidget } from './widgets'
import AttackGeoMap from './geo/AttackGeoMap'
import DocLink from '../components/DocLink'
import { PageHeader } from '../components/ui'
import { usePersistedState } from '../lib/usePersistedState'
import { localInput, type DashRangeState } from '../lib/range'

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
  return <span className={`rounded px-1.5 py-0.5 text-[12.5px] font-medium ${m.cls}`}>{m.label}</span>
}
// DirectionBadge tags an event's direction relative to our network. LATERAL is the highest-value
// signal for a SOAR (attacker already past the perimeter), so it gets the sharpest color; INBOUND is
// the typical external attack pattern; OUTBOUND flags a possibly-compromised internal host reaching
// out (C2/exfil). Hidden when the API couldn't classify (empty).
const DIRECTION_BADGE: Record<string, { label: string; cls: string; title: string }> = {
  inbound: { label: 'INBOUND', cls: 'text-sky-300 bg-sky-500/15', title: 'External source hitting one of our hosts (typical attack pattern)' },
  outbound: { label: 'OUTBOUND', cls: 'text-amber-300 bg-amber-500/15', title: 'Internal source reaching an external destination — possible C2 or data exfil' },
  lateral: { label: 'LATERAL', cls: 'text-rose-300 bg-rose-500/15', title: 'Internal ↔ internal — attacker moving inside our network' },
}
function DirectionBadge({ d }: { d?: string }) {
  if (!d) return null
  const m = DIRECTION_BADGE[d]
  if (!m) return null
  return <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold tracking-wide ${m.cls}`} title={m.title}>{m.label}</span>
}
const VERDICT_BADGE: Record<string, string> = {
  malicious: 'text-rose-300 bg-rose-500/15',
  suspicious: 'text-amber-300 bg-amber-500/15',
  needs_review: 'text-sky-300 bg-sky-500/15',
  benign: 'text-emerald-300 bg-emerald-500/15',
}
function LLMVerdict({ a }: { a: EventRow }) {
  if (!a.dw_llm_verdict) return <span className="text-dim">—</span>
  const cls = VERDICT_BADGE[a.dw_llm_verdict] ?? 'text-muted bg-surface-2'
  return <span className={`rounded px-1.5 py-0.5 text-[12.5px] font-medium ${cls}`} title={a.dw_llm_summary || undefined}>{a.dw_llm_verdict}</span>
}
function FileHashBadge({ a }: { a: EventRow }) {
  const v = a.dw_filehash_verdict
  if (!v || v === 'unknown') return null
  const bad = v === 'known_bad'
  const cls = bad ? 'text-rose-300 bg-rose-500/15' : 'text-emerald-300 bg-emerald-500/15'
  const title = `${a.file_path || 'file'}${a.dw_filehash_detail ? ` — ${a.dw_filehash_detail}` : ''}`
  return (
    <span className={`rounded px-1.5 py-0.5 text-[12.5px] font-medium ${cls}`} title={title}>
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

// classifyThreatFamily surfaces ransomware / malware / virus / trojan directly on the events
// feed. Rather than adding a schema column, it derives the family from the fields already
// carried on the event (YARA rule names, VirusTotal verdicts, filehash detail, dw_label). This
// keeps the feature migration-free while still catching the flows that matter — YARA hits set
// rule_name/dw_label, VirusTotal enrichment sets dw_filehash_verdict/detail.
function classifyThreatFamily(a: EventRow): { label: string; cls: string } | null {
  const hay = `${a.rule_name || ''} ${a.dw_label || ''} ${a.dw_filehash_verdict || ''} ${a.dw_filehash_detail || ''} ${a.event_action || ''}`.toLowerCase()
  if (!hay.trim()) return null
  if (hay.includes('ransomware')) return { label: 'ransomware', cls: 'bg-rose-500/15 text-rose-300 border-rose-500/30' }
  if (hay.includes('trojan')) return { label: 'trojan', cls: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30' }
  if (hay.includes('virus')) return { label: 'virus', cls: 'bg-amber-500/15 text-amber-300 border-amber-500/30' }
  if (hay.includes('malware')) return { label: 'malware', cls: 'bg-orange-500/15 text-orange-300 border-orange-500/30' }
  return null
}

function ThreatFamilyPill({ a }: { a: EventRow }) {
  const c = classifyThreatFamily(a)
  if (!c) return null
  return (
    <span className={`ml-1.5 inline-flex rounded border px-1.5 py-0 text-[10.5px] font-semibold uppercase tracking-wide ${c.cls}`}>
      {c.label}
    </span>
  )
}

function ThreatIntel({ a }: { a: EventRow }) {
  const abuse = a.dw_enrichment_abuse_confidence
  const otx = a.dw_enrichment_otx_pulse_count
  const hasFileVerdict = !!a.dw_filehash_verdict && a.dw_filehash_verdict !== 'unknown'
  const hasScore = a.threat_score > 0
  if (!hasScore && a.dw_enrichment_status !== 'enriched' && abuse == null && !hasFileVerdict) return <span className="text-dim">—</span>
  const abuseCls = abuse == null ? '' : abuse >= 90 ? 'text-rose-300 bg-rose-500/15' : abuse >= 50 ? 'text-amber-300 bg-amber-500/15' : 'text-muted bg-surface-2'
  const scoreTitle = `Composite threat score ${a.threat_score}/100 (${a.threat_band})` +
    (abuse != null ? ` · abuse ${abuse}` : '') + (otx ? ` · otx ${otx}` : '')
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {hasScore && <ScoreDoughnut score={a.threat_score} band={a.threat_band} title={scoreTitle} />}
      {a.source_geo_country_iso && <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[12.5px] text-fg" title={a.source_geo_city || undefined}>{a.source_geo_country_iso}</span>}
      {/* When there is no accumulated score yet, fall back to the raw CTI badges. */}
      {!hasScore && abuse != null && <span className={`rounded px-1.5 py-0.5 text-[12.5px] font-medium ${abuseCls}`} title="AbuseIPDB confidence">abuse {abuse}</span>}
      {!hasScore && otx != null && otx > 0 && <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-[12.5px] font-medium text-violet-300" title="OTX pulses">otx {otx}</span>}
      <FileHashBadge a={a} />
      {a.dw_severity_escalated_by && <span className="rounded bg-orange-500/15 px-1.5 py-0.5 text-[12.5px] font-medium text-orange-300" title={`Escalated by: ${a.dw_severity_escalated_by}`}>↑</span>}
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
  if (state === 'done') return <span className="text-[12.5px] text-emerald-400">✓ restore requested (applies within ~15s)</span>
  return (
    <span className="flex items-center gap-2">
      {state === 'err' && <span className="text-[12.5px] text-rose-400" title={msg}>failed</span>}
      <button onClick={onClick} disabled={state === 'busy'}
        className="rounded-md border border-amber-700/60 px-2 py-1 text-[12.5px] text-amber-200 hover:bg-amber-500/10 disabled:opacity-50">
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

// ── Static dashboard layout ───────────────────────────────────────────────────
// The dashboard is a FIXED, designed layout rather than a user-arranged one.
//
// Every row adds up to the full column count, which is the point: a free-form arrangement kept
// stranding a 2-column panel beside an empty third, and a saved layout from an older grid made it
// worse (a `wide` flag that meant "full width" in a 2-column grid means "two thirds" here, so old
// layouts wrapped and left holes). A fixed layout cannot drift out of shape.
type Panel = {
  kind: WidgetKind
  source: string
  title: string
  color: string
  /** Columns this panel occupies on a wide screen. The grid is 3 columns. */
  span: 1 | 2 | 3
}

// panelId is the stable key used to persist an operator's preferred order. Derived from source+kind
// so it survives renames of `title` / palette changes without invalidating a saved layout.
function panelId(p: { source: string; kind: WidgetKind }): string {
  return `${p.source}:${p.kind}`
}

// reconcileOrder combines what the operator saved with the current PANELS set: it drops IDs the
// code no longer ships (a widget was removed from PANELS after the operator saved) and appends new
// PANELS at the end (a widget was added to PANELS after the operator's last save). Result is the
// operator's preferred order, complete and current.
function reconcileOrder(savedIds: readonly string[] | undefined, current: Panel[]): Panel[] {
  const currentById = new Map(current.map((p) => [panelId(p), p]))
  const out: Panel[] = []
  const placed = new Set<string>()
  if (savedIds) {
    for (const id of savedIds) {
      const p = currentById.get(id)
      if (p && !placed.has(id)) {
        out.push(p)
        placed.add(id)
      }
    }
  }
  for (const p of current) {
    const id = panelId(p)
    if (!placed.has(id)) {
      out.push(p)
      placed.add(id)
    }
  }
  return out
}

const PANELS: Panel[] = [
  // Headline numbers — one row of three.
  { kind: 'stat', source: 'total_events', title: 'Total events', color: '#6366f1', span: 1 },
  { kind: 'stat', source: 'total_alerts', title: 'Total alerts', color: '#fb923c', span: 1 },
  { kind: 'stat', source: 'alerts_24h', title: 'Alerts (24h)', color: '#f43f5e', span: 1 },
  // The prototype's 2fr/1fr pairing: a trend beside the breakdown that explains it.
  { kind: 'line', source: 'timeline', title: 'Events over time', color: '#6366f1', span: 2 },
  { kind: 'bar', source: 'severity', title: 'Severity breakdown', color: '#6366f1', span: 1 },
  // Who is hitting us — three comparable lists side by side.
  { kind: 'bar', source: 'source_ips', title: 'Top source IPs', color: '#38bdf8', span: 1 },
  { kind: 'risk', source: 'risky_ips', title: 'Top risky IPs', color: '#f43f5e', span: 1 },
  { kind: 'watch', source: 'suspicious_ips', title: 'Suspicious IPs (recon)', color: '#f59e0b', span: 1 },
  // Where the attacks LAND — helps operators see whether attention is concentrated on one port or
  // fanning across web/DB/SSH, and which asset/IP is currently the bullseye. Auto-grows as the data
  // grows (the BarChart tops the list at whatever LIMIT the SQL returns).
  { kind: 'bar', source: 'destination_ports', title: 'Top destination ports', color: '#22d3ee', span: 1 },
  { kind: 'bar', source: 'destination_ips', title: 'Top destination IPs / agents', color: '#22d3ee', span: 2 },
  // The slow-scanner table needs width for its columns; the donut is happy small.
  { kind: 'slow', source: 'slow_scanners', title: 'Slow scanners (multi-day)', color: '#38bdf8', span: 2 },
  { kind: 'donut', source: 'verdicts', title: 'LLM verdicts', color: '#8b5cf6', span: 1 },
  // Fleet health at a glance — sits after the "who is attacking us" row, before the map, so the
  // operator can spot a silent endpoint (never-connected / stale / offline) without leaving the
  // dashboard. Full width for legibility across long agent names + status pill.
  { kind: 'agents', source: 'agents', title: 'Agents', color: '#10b981', span: 3 },
  // The map reads best full width.
  { kind: 'map', source: 'countries', title: 'Attack origins', color: '#f43f5e', span: 3 },
]

// A 2-column panel is full width at the 2-column breakpoint, two thirds at three columns.
const SPAN_CLASS: Record<1 | 2 | 3, string> = {
  1: '',
  2: 'sm:col-span-2',
  3: 'sm:col-span-2 lg:col-span-3',
}

function WidgetBody({ w, data, geoRange, geoEnabled }: { w: Panel; data: DashboardData | null; geoRange: DashRange | null; geoEnabled: boolean }) {
  if (!data) return <p className="py-6 text-center text-[13.5px] text-dim">loading…</p>
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
      // Feature flag (localStorage `deuswatch.ui.dashboard.geo_map`): when on, render the animated
      // geo map with attack arcs (docs/geo-map.md); off = the classic flag+heat-bar list. Kept as
      // an opt-in in v1 so an operator can fall back if the new widget misbehaves in their env.
      return geoEnabled
        ? <AttackGeoMap range={geoRange} />
        : <AttackMap data={data.series['countries'] ?? []} color={w.color} />
    case 'risk':
      return <RiskyIPsWidget data={data.risky_ips ?? []} />
    case 'watch':
      return <SuspiciousIPsWidget data={data.suspicious_ips ?? []} />
    case 'slow':
      return <SlowScannerWidget data={data.slow_scanners ?? []} />
    case 'agents':
      // Fetches its own agents list on mount + 15s refresh (independent of the dashboard bundle
      // so status flips are visible without waiting for the next dashboard poll).
      return <AgentsWidget />
    default:
      return <BarChart data={data.series[w.source] ?? []} color={w.color} />
  }
}

export default function Dashboard({
  range,
  onCreateTicket,
}: {
  range: DashRangeState
  onCreateTicket?: (t: NewTicketInput) => void
}) {
  const [health, setHealth] = useState<Health | null>(null)
  const [storage, setStorage] = useState<StorageStatus | null>(null)
  const [data, setData] = useState<DashboardData | null>(null)
  const [updated, setUpdated] = useState<Date | null>(null)
  // Feature flag for the animated geo map. Persisted per-browser so an operator's choice survives
  // reloads. Off in v1 — flip via the toggle in the header (state key: dashboard.geo_map).
  const [geoEnabled, setGeoEnabled] = usePersistedState<boolean>('dashboard.geo_map', false)
  // Operator override for the incident timeline's bucket width; '' = server auto-picks based
  // on the selected window. Persisted per-browser so a wide/short zoom preference sticks.
  const [timelineBucket, setTimelineBucket] = usePersistedState<TimelineBucket>('dashboard.timeline_bucket', '')

  // Layout customization: operator can enter edit mode, drag panels to reorder, save or reset.
  // `panels` is the effective render order — starts as the default PANELS, replaced with the
  // reconciled saved order once fetchLayout resolves. Reconciler tolerates historical shapes so a
  // pre-v2.0 saved layout still lands cleanly (see reconcileOrder + DashLayout in lib/api.ts).
  const [panels, setPanels] = useState<Panel[]>(PANELS)
  const [edit, setEdit] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [dragId, setDragId] = useState<string | null>(null)
  const [overId, setOverId] = useState<string | null>(null)
  const [saveMsg, setSaveMsg] = useState('')

  useEffect(() => {
    fetchLayout()
      .then((l) => {
        if (!l) return
        // v2 shape: {v:2, order:string[]}. v1 shape: {widgets:[{source,kind,...}]}. Both map to a
        // list of stable ids we can hand to reconcileOrder.
        const ids: string[] | undefined =
          Array.isArray(l.order) ? l.order :
          Array.isArray(l.widgets) ? l.widgets.map((w) => panelId({ source: w.source, kind: w.kind })) :
          undefined
        if (ids && ids.length > 0) setPanels(reconcileOrder(ids, PANELS))
      })
      .catch(() => { /* no saved layout, no problem — stick with defaults */ })
  }, [])

  const reorder = (fromId: string, toId: string) => {
    setPanels((cur) => {
      const from = cur.findIndex((p) => panelId(p) === fromId)
      const to = cur.findIndex((p) => panelId(p) === toId)
      if (from < 0 || to < 0 || from === to) return cur
      const next = [...cur]
      const [moved] = next.splice(from, 1)
      next.splice(to, 0, moved)
      return next
    })
    setDirty(true)
    setSaveMsg('')
  }
  // Keyboard-accessible fallback for arrow reordering (matches the pre-v2.0 behaviour so a
  // keyboard-only operator can still use the feature).
  const nudge = (id: string, dir: -1 | 1) => {
    setPanels((cur) => {
      const i = cur.findIndex((p) => panelId(p) === id)
      const j = i + dir
      if (i < 0 || j < 0 || j >= cur.length) return cur
      const next = [...cur]
      ;[next[i], next[j]] = [next[j], next[i]]
      return next
    })
    setDirty(true)
    setSaveMsg('')
  }
  const clearDrag = () => { setDragId(null); setOverId(null) }
  const saveOrder = async () => {
    try {
      await saveLayout({ v: 2, order: panels.map(panelId) })
      setDirty(false)
      setSaveMsg('Saved.')
      setTimeout(() => setSaveMsg(''), 2000)
    } catch (e) {
      setSaveMsg(String((e as Error).message))
    }
  }
  const resetOrder = async () => {
    try {
      await deleteLayout()
      setPanels(PANELS)
      setDirty(false)
      setSaveMsg('Reset to default.')
      setTimeout(() => setSaveMsg(''), 2000)
    } catch (e) {
      setSaveMsg(String((e as Error).message))
    }
  }

  // Poll live data for the selected time range. Re-subscribes when the range
  // changes; a custom range with incomplete inputs simply skips the data fetch.
  useEffect(() => {
    let active = true
    const tick = async () => {
      const h = await fetchHealth()
      if (active) setHealth(h)
      fetchStorageStatus().then((s) => { if (active) setStorage(s) }).catch(() => {})
      if (range.resolved) {
        try {
          const d = await fetchDashboardData(range.resolved, timelineBucket)
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
  }, [range.preset, range.from, range.to, timelineBucket])

  const services: { name: string; sub: string; state: DotState; detail: string }[] = [
    { name: 'API Server', sub: 'Go · :8080', state: health ? (health.api === 'alive' ? 'good' : 'bad') : 'unknown', detail: health?.api ?? 'checking…' },
    { name: 'PostgreSQL + TimescaleDB', sub: 'log storage', state: health ? depDot(health.postgres) : 'unknown', detail: health?.postgres ?? 'checking…' },
    { name: 'NATS JetStream', sub: 'message bus', state: health ? depDot(health.nats) : 'unknown', detail: health?.nats ?? 'checking…' },
  ]
  const allReady = health?.ready ?? false

  return (
    <div className="mx-auto max-w-[1400px] px-6 py-5">
      <PageHeader
        actions={
          <>
            {edit && (
              <>
                {saveMsg && <span className="text-[12.5px] text-dim">{saveMsg}</span>}
                <button
                  onClick={resetOrder}
                  className="rounded-[8px] border border-border px-3 py-1.5 text-[13px] font-medium text-muted transition-colors hover:bg-surface-2 hover:text-fg"
                  title="Discard your saved layout and restore the default panel order"
                >
                  Reset
                </button>
                <button
                  onClick={saveOrder}
                  disabled={!dirty}
                  className="rounded-[8px] bg-accent px-3 py-1.5 text-[13px] font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-40"
                >
                  {dirty ? 'Save layout' : 'Saved'}
                </button>
              </>
            )}
            <button
              onClick={() => { setEdit((e) => !e); clearDrag() }}
              className={`rounded-[8px] border px-3 py-1.5 text-[13px] font-medium transition-colors ${
                edit ? 'border-accent bg-accent-soft text-accent' : 'border-border text-muted hover:bg-surface-2 hover:text-fg'
              }`}
              title={edit ? 'Exit edit mode' : 'Enter edit mode to drag panels'}
            >
              {edit ? 'Done' : '✎ Edit layout'}
            </button>
            <span
              className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-[12.5px] font-medium ${
                allReady ? 'border-success/30 bg-success/10 text-success' : 'border-medium/30 bg-medium/10 text-medium'
              }`}
            >
              <Dot state={allReady ? 'good' : 'unknown'} />
              {allReady ? 'Ready' : 'Waiting'}
            </span>
          </>
        }
      />


      {/* Customizable widget grid. Three columns on wide screens, two at medium, one on mobile.
          `grid-auto-flow: dense` backfills 1-col panels behind a 2-col panel at the narrower
          breakpoints. `gap-5` (was gap-3) gives the cards more room to breathe at 1400px. Edit mode
          enables drag-and-drop reorder via a grip icon (the pre-v2.0 mechanism, restored). */}
      <section className="mb-8 grid gap-5 [grid-auto-flow:dense] sm:grid-cols-2 lg:grid-cols-3">
        {panels.map((w) => {
          const id = panelId(w)
          const isDragging = dragId === id
          const isOver = overId === id && dragId !== id
          return (
            <div
              key={id}
              tabIndex={edit ? 0 : -1}
              draggable={edit}
              onDragStart={(e) => {
                if (!edit) return
                setDragId(id)
                e.dataTransfer.effectAllowed = 'move'
              }}
              onDragOver={(e) => {
                if (!edit || !dragId || dragId === id) return
                e.preventDefault()
                setOverId(id)
              }}
              onDragLeave={() => setOverId((o) => (o === id ? null : o))}
              onDrop={(e) => {
                if (!edit || !dragId) return
                e.preventDefault()
                reorder(dragId, id)
                clearDrag()
              }}
              onDragEnd={clearDrag}
              onKeyDown={(e) => {
                if (!edit) return
                if (e.key === 'ArrowDown' || e.key === 'ArrowRight') { e.preventDefault(); nudge(id, +1) }
                if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') { e.preventDefault(); nudge(id, -1) }
              }}
              className={`rounded-[12px] border bg-surface p-[18px] shadow-sm transition-all ${SPAN_CLASS[w.span]} ${
                isOver ? 'border-accent ring-2 ring-accent/40' : 'border-border'
              } ${isDragging ? 'opacity-40' : ''} ${edit ? 'cursor-grab hover:border-accent/50 active:cursor-grabbing' : ''}`}
            >
              <h2
                className={`mb-3 flex items-center gap-2 ${
                  w.kind === 'stat'
                    ? 'text-[13px] font-semibold uppercase tracking-[0.4px] text-dim'
                    : 'text-[14.5px] font-bold tracking-tight text-fg'
                }`}
              >
                {edit && (
                  <span
                    aria-hidden="true"
                    className="select-none text-base leading-none text-dim"
                    title="Drag to reorder (or focus and press ↑ / ↓)"
                  >
                    ⠿
                  </span>
                )}
                <span>{w.title}</span>
                {/* Small toggle in the map panel header so an operator can switch between the classic
                    flag list and the animated geo map (docs/geo-map.md). Persisted per browser. */}
                {w.kind === 'map' && (
                  <button
                    onClick={() => setGeoEnabled(!geoEnabled)}
                    className="ml-auto rounded-[6px] border border-border px-2 py-0.5 text-[11.5px] font-medium text-muted transition-colors hover:bg-surface-2 hover:text-fg"
                    title={geoEnabled ? 'Switch to the classic flag list' : 'Switch to the animated geo map (beta)'}
                  >
                    {geoEnabled ? '🗺 map' : '⚑ list'}
                  </button>
                )}
                {/* Timeline bucket picker on the "Events over time" panel — '' = server auto-picks. */}
                {w.kind === 'line' && w.source === 'timeline' && (
                  <select
                    value={timelineBucket}
                    onChange={(e) => setTimelineBucket(e.target.value as TimelineBucket)}
                    onMouseDown={(e) => e.stopPropagation()}
                    onDragStart={(e) => e.preventDefault()}
                    className="ml-auto rounded-[6px] border border-border bg-surface-2 px-1.5 py-0.5 text-[11.5px] font-medium text-muted outline-none transition-colors hover:text-fg"
                    title="Bucket width for the timeline"
                  >
                    <option value="">auto</option>
                    <option value="1min">1 min</option>
                    <option value="5min">5 min</option>
                    <option value="15min">15 min</option>
                    <option value="30min">30 min</option>
                    <option value="1h">1 h</option>
                    <option value="6h">6 h</option>
                    <option value="1d">1 d</option>
                  </select>
                )}
              </h2>
              <WidgetBody w={w} data={data} geoRange={range.resolved} geoEnabled={geoEnabled} />
            </div>
          )
        })}
      </section>

      {/* Searchable events & alerts — filter by IP / rule / MITRE / level / time */}
      <EventsPanel onCreateTicket={onCreateTicket} apiDown={health?.api === 'down'} />

      {/* System Health (fixed) */}
      <section>
        <h2 className="mb-3 text-[12.5px] font-semibold uppercase tracking-wider text-dim">System Health</h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {services.map((s) => (
            <div key={s.name} className="rounded-[12px] border border-border bg-surface p-4">
              <div className="flex items-center justify-between">
                <span className="text-[13.5px] font-medium text-fg">{s.name}</span>
                <Dot state={s.state} />
              </div>
              <div className="mt-1 text-[12.5px] text-dim">{s.sub}</div>
              <div className={`mt-3 font-mono text-[13.5px] ${s.state === 'good' ? 'text-emerald-400' : s.state === 'bad' ? 'text-rose-400' : 'text-amber-400'}`}>{s.detail}</div>
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
      <h2 className="mb-3 text-[12.5px] font-semibold uppercase tracking-wider text-dim">Log Storage</h2>
      <div className="grid gap-3 sm:grid-cols-3">
        {/* Capacity */}
        <div className="rounded-[12px] border border-border bg-surface p-4">
          <div className="flex items-center justify-between">
            <span className="text-[13.5px] font-medium text-fg">Database size</span>
            <Dot state={!s ? 'unknown' : s.reachable ? (pct != null && pct >= 90 ? 'bad' : 'good') : 'bad'} />
          </div>
          <div className="mt-1 text-[12.5px] text-dim">{s?.host ? `host: ${s.host}` : 'log storage'}</div>
          <div className="mt-3 font-mono text-[13.5px] text-fg">
            {!s ? 'checking…' : !s.reachable ? 'unreachable' : s.db_size_pretty}
            {s?.reachable && <span className="text-dim"> · {s.events_count.toLocaleString('en-US')} events</span>}
          </div>
          {pct != null && (
            <div className="mt-2">
              <div className="h-2 overflow-hidden rounded bg-surface-2">
                <div className={`h-full rounded ${barColor}`} style={{ width: `${pct}%` }} />
              </div>
              <div className="mt-1 text-[12.5px] text-dim">{pct}% of {(s!.budget_bytes / 1073741824).toFixed(0)} GB budget</div>
            </div>
          )}
          {s?.reachable && !s.budget_bytes && <div className="mt-2 text-[12.5px] text-dim">set STORAGE_BUDGET_GB for a usage bar + near-full alerts</div>}
        </div>

        {/* Lifecycle (retention + compression = ILM equivalent) */}
        <div className="rounded-[12px] border border-border bg-surface p-4">
          <div className="flex items-center justify-between">
            <span className="text-[13.5px] font-medium text-fg">Lifecycle</span>
            <Dot state={s?.reachable ? 'good' : s ? 'unknown' : 'unknown'} />
          </div>
          <div className="mt-1 text-[12.5px] text-dim">TimescaleDB retention + compression</div>
          <div className="mt-3 font-mono text-[13.5px] text-fg">
            {s?.retention_days != null ? `retention ${s.retention_days}d` : 'retention: —'}
          </div>
          <div className="font-mono text-[12.5px] text-dim">
            {s?.compression_days != null ? `compress after ${s.compression_days}d` : 'compression: —'}
          </div>
        </div>

        {/* Replication */}
        <div className="rounded-[12px] border border-border bg-surface p-4">
          <div className="flex items-center justify-between">
            <span className="text-[13.5px] font-medium text-fg">Replication</span>
            <Dot state={!repl ? 'unknown' : repl.enabled ? 'good' : 'unknown'} />
          </div>
          <div className="mt-1 text-[12.5px] text-dim">PostgreSQL streaming</div>
          <div className={`mt-3 font-mono text-[13.5px] ${repl?.enabled ? 'text-emerald-400' : 'text-amber-400'}`}>
            {!repl ? 'checking…' : repl.enabled ? 'active' : 'not configured'}
          </div>
          {repl?.standbys?.length ? (
            <div className="mt-1 font-mono text-[12.5px] text-dim">{repl.standbys.join(', ')}</div>
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
  'rounded-md border border-border bg-surface-2 px-2 py-1.5 text-[13.5px] text-fg outline-none focus:border-accent [color-scheme:dark]'

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
  // Preference-like filters are persisted so they survive leaving the page (the free-text
  // search above stays transient — a hidden search that came back would confuse more than help).
  const [severity, setSeverity] = usePersistedState('events.severity', -1)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [alertsOnly, setAlertsOnly] = usePersistedState('events.alertsOnly', true) // uncheck to see all events
  const [limit, setLimit] = usePersistedState('events.limit', 20)
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
        <h2 className="text-[12.5px] font-semibold uppercase tracking-wider text-dim">
          Events &amp; Alerts
          <span className="ml-2 normal-case text-dim">{rows.length} shown</span>
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
            className={`rounded-md border px-2.5 py-1.5 text-[12.5px] font-medium ${hasFilter || open ? 'border-accent bg-accent-soft text-accent' : 'border-border text-fg hover:bg-surface-2'}`}
          >
            ⛃ Filters{hasFilter ? ' ·' : ''}
          </button>
          <button
            onClick={sendWebhook}
            className="rounded-md border border-border px-2.5 py-1.5 text-[12.5px] font-medium text-fg hover:bg-surface-2"
            title="Send these filtered events as JSON to the configured export webhook"
          >
            ↗ Webhook
          </button>
          {whMsg && <span className="text-[12.5px] text-dim">{whMsg}</span>}
          <label className="flex items-center gap-1 text-[12.5px] text-muted">
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
        <div className="mb-3 flex flex-wrap items-end gap-2 rounded-[12px] border border-accent/30 bg-accent-soft px-4 py-3">
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
          <label className="flex items-center gap-1.5 px-1 text-[12.5px] text-fg">
            <input type="checkbox" checked={alertsOnly} onChange={(e) => setAlertsOnly(e.target.checked)} className="h-4 w-4 accent-indigo-500" />
            Alerts only
          </label>
          {hasFilter && (
            <button onClick={reset} className="rounded-md border border-border px-2.5 py-1.5 text-[12.5px] text-muted hover:bg-surface-2 hover:text-rose-300">Clear</button>
          )}
        </div>
      )}

      <div className="overflow-hidden rounded-[12px] border border-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-surface text-[12.5px] uppercase tracking-wider text-dim">
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
          <tbody className="divide-y divide-border bg-surface">
            {rows.length ? (
              rows.map((a, i) => (
                <Fragment key={i}>
                  <tr
                    className="cursor-pointer hover:bg-surface-2"
                    onClick={() => setExpanded(expanded === i ? null : i)}
                    title="Click to view the full JSON log"
                  >
                    <td className="px-4 py-2 text-muted">{new Date(a.time).toLocaleString('en-US')}</td>
                    <td className="px-4 py-2 text-fg">
                      {a.agent_id ? (
                        <button
                          onClick={(e) => { e.stopPropagation(); setAgent(a.agent_id); setOpen(true) }}
                          className="rounded text-fg hover:text-accent"
                          title={`Filter by agent ${a.agent_id}`}
                        >
                          {a.agent_id}
                        </button>
                      ) : '—'}
                    </td>
                    <td className="px-4 py-2 font-mono text-fg">
                      <div className="flex items-center gap-1.5">
                        <span>{a.source_ip || '—'}</span>
                        <DirectionBadge d={a.direction} />
                      </div>
                    </td>
                    <td className="px-4 py-2 text-fg">
                      {a.rule_name || a.dw_label || a.event_action || a.event_category || '—'}
                      <ThreatFamilyPill a={a} />
                      {a.file_path && (
                        <span className="mt-0.5 block truncate text-[12.5px] text-dim" title={a.file_path}>
                          location: <span className="font-mono text-muted">{a.file_path}</span>
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-muted">{a.threat_technique_id ? `${a.threat_technique_id} · ${a.threat_tactic_name}` : '—'}</td>
                    <td className="px-4 py-2"><ThreatIntel a={a} /></td>
                    <td className="px-4 py-2"><LLMVerdict a={a} /></td>
                    <td className="px-4 py-2"><SeverityBadge sev={a.event_severity} /></td>
                    {onCreateTicket && (
                      <td className="px-4 py-2 text-right">
                        <button onClick={(e) => { e.stopPropagation(); onCreateTicket(alertToTicket(a)) }} className="rounded-md border border-border px-2 py-1 text-[12.5px] text-fg transition-colors hover:bg-surface-2" title="Raise a Tier-2 ticket from this event">+ Ticket</button>
                      </td>
                    )}
                  </tr>
                  {expanded === i && (
                    <tr className="bg-bg">
                      <td colSpan={onCreateTicket ? 9 : 8} className="px-4 py-3">
                        {a.dw_remediation_action && (
                          <div className="mb-3 rounded-[8px] border border-indigo-900/50 bg-accent-soft p-3">
                            <div className="mb-1 text-[12.5px] font-medium uppercase tracking-wider text-accent">
                              Recommended playbook {a.dw_remediation_source === 'playbook' ? '' : `(${a.dw_remediation_source})`}
                            </div>
                            <pre className="whitespace-pre-wrap text-[13.5px] leading-relaxed text-fg">{a.dw_remediation_action}</pre>
                          </div>
                        )}
                        {(a.http_uri || a.http_host || a.http_status > 0) && (
                          <div className="mb-3 rounded-[8px] border border-cyan-900/50 bg-cyan-500/5 p-3">
                            <div className="mb-1 text-[12.5px] font-medium uppercase tracking-wider text-cyan-300">
                              HTTP request{a.event_action === 'waf_block' ? ' · WAF blocked' : ''}
                            </div>
                            <div className="space-y-0.5 font-mono text-[12.5px] text-fg">
                              {(a.http_method || a.http_uri) && (
                                <div><span className="text-dim">{a.http_method || 'GET'}</span> {a.http_uri || '—'}{a.http_status > 0 && <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 text-muted">{a.http_status}</span>}</div>
                              )}
                              {a.http_host && <div><span className="text-dim">host:</span> {a.http_host}</div>}
                            </div>
                          </div>
                        )}
                        {(a.file_diff || (a.event_category === 'file' && a.file_path)) && (
                          <div className="mb-3 rounded-[8px] border border-amber-900/50 bg-amber-500/5 p-3">
                            <div className="mb-1 flex items-center justify-between">
                              <span className="text-[12.5px] font-medium uppercase tracking-wider text-amber-300">
                                File change{a.file_path ? ` — ${a.file_path}` : ''}
                              </span>
                              {a.file_path && a.agent_id && <RestoreButton agent={a.agent_id} path={a.file_path} />}
                            </div>
                            {(a.process_name || a.user_name) && (
                              <div className="mb-2 text-[12.5px] text-muted">
                                changed by{' '}
                                {a.process_name && (
                                  <span className="font-mono text-amber-200">
                                    {a.process_name}{a.process_pid ? ` (pid ${a.process_pid})` : ''}
                                  </span>
                                )}
                                {a.user_name && (
                                  <> {a.process_name ? 'as user ' : 'user '}<span className="font-mono text-amber-200">{a.user_name}</span></>
                                )}
                                <span className="ml-1 text-dim">· who-data</span>
                                <DocLink file="whodata.md" label="docs" className="ml-2" />
                              </div>
                            )}
                            {a.file_diff && (
                              <pre className="max-h-80 overflow-auto rounded bg-bg p-2 font-mono text-[12.5px] leading-relaxed">
                                {a.file_diff.split('\n').map((line, k) => (
                                  <div key={k} className={line.startsWith('+') ? 'text-emerald-400' : line.startsWith('-') ? 'text-rose-400' : 'text-dim'}>{line}</div>
                                ))}
                              </pre>
                            )}
                          </div>
                        )}
                        <div className="mb-1 text-[12.5px] font-medium uppercase tracking-wider text-dim">Full log (JSON)</div>
                        <pre className="max-h-96 overflow-y-auto whitespace-pre-wrap break-words rounded-[8px] border border-border bg-surface p-3 text-[12.5px] leading-relaxed text-fg">
{JSON.stringify(cleanEvent(a), null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))
            ) : (
              <tr>
                <td colSpan={onCreateTicket ? 9 : 8} className="px-4 py-6 text-center text-[13.5px] text-dim">
                  {apiDown ? 'API unreachable — run docker compose up' : hasFilter || q ? 'No events match these filters.' : 'No events yet.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-[12.5px] text-dim">{updated ? `Last updated ${updated.toLocaleTimeString('en-US')}` : 'Loading…'}</p>
    </section>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-[11px] uppercase tracking-wide text-dim">
      {label}
      {children}
    </label>
  )
}
