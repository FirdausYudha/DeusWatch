import * as React from 'react'
import { useEffect, useState } from 'react'
import type { SeriesPoint, TimelinePoint, RiskyIP, SuspiciousIP, SlowScanner, AgentInfo, DisplayStatus, CommFlow, CommFlowDirection, SrcDstFlow } from '../lib/api'
import { fetchAgents, agentDisplayStatus } from '../lib/api'

export const WIDGET_COLORS = ['#6366f1', '#10b981', '#f43f5e', '#f59e0b', '#38bdf8', '#8b5cf6', '#fb923c']
// Categorical palette for donut segments, starting from the widget's chosen color.
function palette(start: string): string[] {
  const i = Math.max(0, WIDGET_COLORS.indexOf(start))
  return [...WIDGET_COLORS.slice(i), ...WIDGET_COLORS.slice(0, i)]
}

function Empty() {
  return <p className="py-6 text-center text-[13.5px] text-dim">no data yet</p>
}

// Sized to match the StatCard tile (26px/700). tabular-nums keeps the digits on a fixed pitch so
// a counter ticking up doesn't make the number jitter horizontally.
export function StatWidget({ value, color }: { value: number; color: string }) {
  return (
    <div className="py-2 text-[28px] font-bold tabular-nums leading-none" style={{ color }}>
      {value.toLocaleString('en-US')}
    </div>
  )
}

export function BarChart({ data, color }: { data: SeriesPoint[]; color: string }) {
  if (!data?.length) return <Empty />
  const max = Math.max(1, ...data.map((d) => d.count))
  return (
    <ul className="space-y-1.5">
      {data.map((d, i) => (
        <li key={i} className="flex items-center gap-2 text-sm">
          <span className="w-28 truncate text-muted" title={d.label}>{d.label || '—'}</span>
          <div className="h-2 flex-1 overflow-hidden rounded bg-surface-2">
            <div className="h-full rounded" style={{ width: `${(d.count / max) * 100}%`, background: color }} />
          </div>
          <span className="w-8 text-right text-[12.5px] text-muted">{d.count}</span>
        </li>
      ))}
    </ul>
  )
}

// DonutChart renders a compact donut with a legend. The optional `colors` prop overrides the
// category palette — used by SeverityDonut in the Inventory page to tint slices by severity
// (critical=red, high=orange, medium=amber, low=sky, negligible/unknown=slate) so the donut
// matches the badge palette in the vulnerability table instead of the categorical widget colours.
export function DonutChart({ data, color, colors }: { data: SeriesPoint[]; color: string; colors?: string[] }) {
  if (!data?.length) return <Empty />
  const paletteColors = colors ?? palette(color)
  const total = data.reduce((a, d) => a + d.count, 0) || 1
  const R = 30
  const C = 2 * Math.PI * R
  let offset = 0
  return (
    <div className="flex items-center gap-5 py-2">
      <svg viewBox="0 0 80 80" className="h-28 w-28 -rotate-90">
        <circle cx="40" cy="40" r={R} fill="none" stroke="#1e293b" strokeWidth="12" />
        {data.map((d, i) => {
          const dash = (d.count / total) * C
          const seg = (
            <circle
              key={i}
              cx="40"
              cy="40"
              r={R}
              fill="none"
              stroke={paletteColors[i % paletteColors.length]}
              strokeWidth="12"
              strokeDasharray={`${dash} ${C - dash}`}
              strokeDashoffset={-offset}
            />
          )
          offset += dash
          return seg
        })}
      </svg>
      <ul className="space-y-1 text-xs">
        {data.map((d, i) => (
          <li key={i} className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: paletteColors[i % paletteColors.length] }} />
            <span className="text-fg">{d.label || '—'}</span>
            <span className="text-dim">{d.count}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function LineChart({ points, color }: { points: TimelinePoint[]; color: string }) {
  if (!points?.length) return <Empty />
  const W = 320, H = 90, pad = 6
  const max = Math.max(1, ...points.map((p) => p.count))
  const n = points.length
  const x = (i: number) => pad + (n > 1 ? (i / (n - 1)) * (W - 2 * pad) : 0)
  const y = (v: number) => H - pad - (v / max) * (H - 2 * pad)
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.count).toFixed(1)}`).join(' ')
  const area = `${line} L${x(n - 1).toFixed(1)},${H - pad} L${x(0).toFixed(1)},${H - pad} Z`
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-28 w-full" preserveAspectRatio="none">
      <path d={area} fill={color} opacity="0.15" />
      <path d={line} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />
    </svg>
  )
}

// TenantLinesWidget draws one line per tenant on a shared axis (v2.10.0, superadmin-only).
// Self-fetches from /api/dashboard/timeline-by-tenant on mount + on range change, so it's
// independent of the main dashboard bundle. Silently hides itself on 403 (regular tenant users
// can't see cross-tenant data) or when the API returns empty.
export function TenantLinesWidget({ range }: { range: { hours?: number; from?: Date; to?: Date } | null }) {
  const [series, setSeries] = React.useState<Array<{ tenant_id: string; tenant_name: string; points: Array<{ time: string; count: number }> }>>([])
  const [forbidden, setForbidden] = React.useState(false)
  React.useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const s = await (await import('../lib/api')).fetchTenantTimeline(range ?? 24, '')
        if (alive) setSeries(s)
      } catch (e) {
        if (String((e as Error).message).includes('403') && alive) setForbidden(true)
      }
    }
    load()
    const t = setInterval(load, 15000)
    return () => { alive = false; clearInterval(t) }
  }, [range])
  if (forbidden) return <p className="py-6 text-center text-[13.5px] text-dim">requires manage_tenants</p>
  if (!series.length || series.every((s) => !s.points.some((p) => p.count > 0))) return <Empty />
  const W = 320, H = 90, pad = 6
  const n = series[0]?.points.length ?? 0
  const max = Math.max(1, ...series.flatMap((s) => s.points.map((p) => p.count)))
  const x = (i: number) => pad + (n > 1 ? (i / (n - 1)) * (W - 2 * pad) : 0)
  const y = (v: number) => H - pad - (v / max) * (H - 2 * pad)
  // A discrete palette that's readable in both themes; wraps beyond 8 tenants.
  const palette = ['#6366f1', '#22d3ee', '#f59e0b', '#10b981', '#f43f5e', '#8b5cf6', '#38bdf8', '#a3e635']
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-28 w-full" preserveAspectRatio="none">
        {series.map((s, si) => {
          if (!s.points.length) return null
          const d = s.points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.count).toFixed(1)}`).join(' ')
          return <path key={s.tenant_id} d={d} fill="none" stroke={palette[si % palette.length]} strokeWidth="1.5" vectorEffect="non-scaling-stroke" opacity="0.9" />
        })}
      </svg>
      <ul className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11.5px] text-muted">
        {series.map((s, si) => (
          <li key={s.tenant_id} className="inline-flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: palette[si % palette.length] }} />
            <span className="truncate">{s.tenant_name}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function TableWidget({ data }: { data: SeriesPoint[] }) {
  if (!data?.length) return <Empty />
  return (
    <table className="w-full text-sm">
      <tbody className="divide-y divide-border">
        {data.map((d, i) => (
          <tr key={i}>
            <td className="py-1.5 pr-2 text-fg">{d.label || '—'}</td>
            <td className="py-1.5 text-right font-mono text-[12.5px] text-muted">{d.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

// Band colours for the composite score (matches the doughnut on the events table).
const BAND_STYLE: Record<string, string> = {
  critical: 'text-rose-300 bg-rose-500/15',
  high: 'text-orange-300 bg-orange-500/15',
  medium: 'text-amber-300 bg-amber-500/15',
  low: 'text-muted bg-surface-2',
}
function bandColor(band: string): string {
  return band === 'critical' ? '#f43f5e' : band === 'high' ? '#fb923c' : band === 'medium' ? '#f59e0b' : '#64748b'
}

// RiskyIPsWidget ranks source IPs by their 0–100 composite score (fired times + AbuseIPDB +
// OTX + worst severity) — the "who to ban first" list, not just who was noisiest.
export function RiskyIPsWidget({ data }: { data: RiskyIP[] }) {
  if (!data?.length) return <Empty />
  return (
    <ul className="space-y-1.5">
      {data.map((r) => (
        <li key={r.ip} className="flex items-center gap-2 text-sm">
          <span className="w-32 shrink-0 truncate font-mono text-[12.5px] text-fg" title={r.ip}>{r.ip}</span>
          <div className="h-2 flex-1 overflow-hidden rounded bg-surface-2">
            <div className="h-full rounded" style={{ width: `${Math.min(100, r.score)}%`, background: bandColor(r.band) }} />
          </div>
          <span className="w-7 text-right text-[12.5px] font-medium text-fg">{r.score}</span>
          {/* Cross-agent fan-out: this IP hit more than one of our endpoints (campaign behaviour). */}
          {(r.agents ?? 0) > 1 && (
            <span
              className="shrink-0 rounded bg-high/15 px-1.5 py-0.5 text-[11px] font-medium text-high"
              title={`Touched ${r.agents} of your endpoints — cross-agent fan-out raises the score`}
            >
              {r.agents} hosts
            </span>
          )}
          <span className={`w-14 shrink-0 rounded px-1.5 py-0.5 text-center text-[11px] font-medium ${BAND_STYLE[r.band] ?? BAND_STYLE.low}`}>
            {r.band}
          </span>
        </li>
      ))}
    </ul>
  )
}

// SlowScannerWidget lists the MULTI-DAY pattern static rules can never catch: sources that come
// back on separate days at a volume too low to trip any burst threshold ("2 today, none tomorrow,
// 5 the day after"). The day-strip makes the recurrence visible at a glance.
export function SlowScannerWidget({ data }: { data: SlowScanner[] }) {
  if (!data?.length)
    return (
      <p className="py-6 text-center text-[12.5px] text-dim">
        No slow scanners yet — this watchlist needs a few days of history to see a pattern.
      </p>
    )
  return (
    <ul className="space-y-2">
      {data.map((r) => (
        <li key={r.ip} className="flex items-center gap-2">
          <span className="w-32 shrink-0 truncate font-mono text-[12.5px] text-fg" title={r.ip}>
            {r.ip}
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5 text-[11px] text-dim">
              <span title="Separate days this source came back — the recurrence signal">
                <b className="text-muted">{r.active_days}</b> active days
              </span>
              <span>·</span>
              <span title="Total events across the whole window (deliberately low)">{r.events} events</span>
              <span>·</span>
              <span title="Days between first and last sighting">{r.span_days}d span</span>
              {r.agents > 1 && (
                <>
                  <span>·</span>
                  <span className="text-high" title="Touched more than one of your endpoints">
                    {r.agents} hosts
                  </span>
                </>
              )}
            </div>
            <div className="mt-1 h-1.5 overflow-hidden rounded bg-surface-2">
              <div
                className="h-full rounded"
                style={{ width: `${Math.min(100, r.score)}%`, background: bandColor(r.band) }}
              />
            </div>
          </div>
          <span className="w-7 text-right text-[12.5px] font-medium text-fg">{r.score}</span>
          <span
            className={`w-14 shrink-0 rounded px-1.5 py-0.5 text-center text-[11px] font-medium ${BAND_STYLE[r.band] ?? BAND_STYLE.low}`}
          >
            {r.band}
          </span>
        </li>
      ))}
    </ul>
  )
}

// SuspiciousIPsWidget lists low-and-slow reconnaissance: external IPs whose behaviour looks like
// scanning (many distinct targets, failures, spread over time) even without any CTI/WAF hit.
export function SuspiciousIPsWidget({ data }: { data: SuspiciousIP[] }) {
  if (!data?.length) return <Empty />
  return (
    <ul className="space-y-2">
      {data.map((r) => (
        <li
          key={r.ip}
          className="flex items-center gap-2"
          title={`${r.contacts} contacts · ${r.fanout} distinct targets · ${r.failures} failed · seen across ${r.distinct_hours}h`}
        >
          <span className="w-32 shrink-0 truncate font-mono text-[12.5px] text-fg" title={r.ip}>
            {r.ip}
          </span>
          {/* Meta above a full-width bar (mirrors SlowScannerWidget) — keeps the bar from being
              squished in this narrow column and left-aligns the signals so rows read cleanly. */}
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5 text-[11px] text-dim">
              <span title="Failed attempts (blocked/denied/4xx/auth-failure)">
                <b className="text-muted">{r.failures}</b> failures
              </span>
              <span>·</span>
              <span title="Separate clock-hours this source appeared in — the low-and-slow signature">
                {r.distinct_hours}h seen
              </span>
              {r.fanout > 0 && (
                <>
                  <span>·</span>
                  <span title="Distinct endpoints or ports probed">{r.fanout} targets</span>
                </>
              )}
            </div>
            <div className="mt-1 h-1.5 overflow-hidden rounded bg-surface-2">
              <div
                className="h-full rounded"
                style={{ width: `${Math.min(100, r.score)}%`, background: bandColor(r.band) }}
              />
            </div>
          </div>
          <span className="w-7 text-right text-[12.5px] font-medium text-fg">{r.score}</span>
        </li>
      ))}
    </ul>
  )
}

// flag converts an ISO-3166 alpha-2 code to its emoji flag.
function flag(iso?: string): string {
  if (!iso || iso.length !== 2) return '🌐'
  return String.fromCodePoint(...[...iso.toUpperCase()].map((c) => 127397 + c.charCodeAt(0)))
}

// AttackMap shows attack origins by country (flag + heat bar), ranked.
export function AttackMap({ data, color }: { data: SeriesPoint[]; color: string }) {
  if (!data?.length) return <Empty />
  const max = Math.max(1, ...data.map((d) => d.count))
  return (
    <ul className="grid grid-cols-1 gap-x-8 gap-y-1.5 sm:grid-cols-2">
      {data.map((d, i) => (
        <li key={i} className="flex items-center gap-2 text-sm">
          <span className="text-[16px] leading-none">{flag(d.label)}</span>
          <span className="w-8 font-mono text-[12.5px] text-fg">{d.label}</span>
          <div className="h-2 flex-1 overflow-hidden rounded bg-surface-2">
            <div className="h-full rounded" style={{ width: `${(d.count / max) * 100}%`, background: color }} />
          </div>
          <span className="w-8 text-right text-[12.5px] text-muted">{d.count}</span>
        </li>
      ))}
    </ul>
  )
}

// AgentsWidget lists every enrolled agent with its current status. It self-refreshes every 15s so an
// agent coming back online (or dropping off) is visible without a page reload. Sorted so the
// operator's actionable state — "never connected" first (something is wrong with enrollment), then
// stale / offline (something is wrong with an agent) — sits at the top, and healthy agents follow.
// Status semantics come from agentDisplayStatus (lib/api.ts): online = fresh heartbeat, never = no
// heartbeat ever seen, stale = quiet for >24h (or worker marks it), offline = quiet for a while.
export function AgentsWidget() {
  const [agents, setAgents] = useState<AgentInfo[] | null>(null)
  const [err, setErr] = useState<string>('')
  useEffect(() => {
    const load = () => {
      fetchAgents()
        .then((rows) => {
          setAgents(rows)
          setErr('')
        })
        .catch((e) => setErr(String((e as Error).message ?? e)))
    }
    load()
    // 5s cadence: agent starts → sends first heartbeat immediately (cmd/agent/main.go beat()) →
    // gateway's MarkHealth commits → next widget tick within 5s flips the badge to online. Combined
    // that gets an operator from "just installed the agent" to "green dot on the dashboard" in
    // well under 10 seconds. Endpoint is cheap (small SELECT) so the extra polling is fine.
    const t = setInterval(load, 5_000)
    return () => clearInterval(t)
  }, [])
  if (err) return <p className="py-6 text-center text-[13.5px] text-critical">{err}</p>
  if (!agents) return <p className="py-6 text-center text-[13.5px] text-dim">loading…</p>
  if (agents.length === 0) return <Empty />
  const rank: Record<DisplayStatus, number> = { never: 0, offline: 1, stale: 2, revoked: 3, online: 4 }
  const sorted = [...agents].sort((a, b) => rank[agentDisplayStatus(a)] - rank[agentDisplayStatus(b)])
  return (
    <ul className="space-y-1.5">
      {sorted.map((a) => {
        const st = agentDisplayStatus(a)
        return (
          <li
            key={a.id}
            className="flex items-center gap-2 text-sm"
            title={agentTitle(a, st)}
          >
            <span
              aria-hidden="true"
              className="h-2 w-2 shrink-0 rounded-full"
              style={{ background: STATUS_COLOR[st] }}
            />
            <span className="min-w-0 flex-1 truncate font-medium text-fg">{a.name}</span>
            <span className="hidden text-[11.5px] text-dim sm:inline">{a.os || '—'}</span>
            <span
              className={`w-[110px] shrink-0 rounded px-1.5 py-0.5 text-center text-[11px] font-medium ${STATUS_STYLE[st]}`}
            >
              {STATUS_LABEL[st]}
            </span>
          </li>
        )
      })}
    </ul>
  )
}

const STATUS_LABEL: Record<DisplayStatus, string> = {
  online: 'online',
  never: 'never connected',
  stale: 'stale',
  offline: 'offline',
  revoked: 'revoked',
}
const STATUS_COLOR: Record<DisplayStatus, string> = {
  online: '#10b981',
  never: '#f59e0b',
  stale: '#fb923c',
  offline: '#94a3b8',
  revoked: '#f43f5e',
}
// Reused pill styles matching band badges elsewhere in the app (bg tint + strong text color).
const STATUS_STYLE: Record<DisplayStatus, string> = {
  online: 'bg-emerald-500/15 text-emerald-500',
  never: 'bg-amber-500/15 text-amber-500',
  stale: 'bg-orange-500/15 text-orange-500',
  offline: 'bg-slate-500/15 text-slate-400',
  revoked: 'bg-rose-500/15 text-rose-500',
}

function agentTitle(a: AgentInfo, st: DisplayStatus): string {
  const parts = [a.name, a.os || 'unknown OS', STATUS_LABEL[st]]
  if (a.last_seen_at) parts.push('last seen ' + new Date(a.last_seen_at).toLocaleString())
  else parts.push('never checked in since enrolment')
  if (a.health_detail) parts.push(a.health_detail)
  return parts.join(' · ')
}

// ── Bipartite node-link graph (v2.13.0) ─────────────────────────────────────────
// A shared SVG renderer for the Communication Graph and Source→Destination Graph. Both are
// "flows between two node buckets" — no force simulation needed, which keeps the widget
// dependency-free (no d3, works fully offline) and predictable to read: node order is
// deterministic (busiest at the top), edges are quadratic bézier curves whose thickness
// scales with the edge weight.
type BipartiteEdge = {
  src: string          // stable key for the left-column node (dedup + node lookup)
  dst: string          // stable key for the right-column node
  srcLabel: string
  dstLabel: string
  count: number
  color: string        // stroke colour for this edge — direction-driven or a single hue
  tooltip: string      // rendered as <title> so the browser shows on hover
}

// bipartiteFlow renders a two-column node-link diagram. `maxPerSide` caps how many nodes
// each column shows (busiest first) so a hostile fleet doesn't produce a wall of overlapping
// lines; edges pointing at trimmed nodes are dropped.
function BipartiteFlow({ edges, leftHeader, rightHeader, maxPerSide = 8 }: {
  edges: BipartiteEdge[]
  leftHeader: string
  rightHeader: string
  maxPerSide?: number
}) {
  if (!edges.length) return <Empty />
  // Fold edges into per-side node totals so we can rank + trim.
  const leftTotals = new Map<string, { label: string; count: number }>()
  const rightTotals = new Map<string, { label: string; count: number }>()
  for (const e of edges) {
    const l = leftTotals.get(e.src) ?? { label: e.srcLabel, count: 0 }
    l.count += e.count; l.label = e.srcLabel; leftTotals.set(e.src, l)
    const r = rightTotals.get(e.dst) ?? { label: e.dstLabel, count: 0 }
    r.count += e.count; r.label = e.dstLabel; rightTotals.set(e.dst, r)
  }
  const topN = <T extends { count: number }>(m: Map<string, T>): [string, T][] =>
    Array.from(m.entries()).sort((a, b) => b[1].count - a[1].count).slice(0, maxPerSide)
  const leftNodes = topN(leftTotals)
  const rightNodes = topN(rightTotals)
  const leftKeep = new Set(leftNodes.map(([k]) => k))
  const rightKeep = new Set(rightNodes.map(([k]) => k))
  const shown = edges.filter((e) => leftKeep.has(e.src) && rightKeep.has(e.dst))
  if (!shown.length) return <Empty />
  // SVG geometry: fixed width, height grows with node count so labels don't overlap.
  const W = 640
  const rowH = 26
  const rows = Math.max(leftNodes.length, rightNodes.length)
  const H = 32 + rows * rowH
  const xLeft = 130     // right edge of left labels (edges start here)
  const xRight = 510    // left edge of right labels (edges end here)
  const y0 = 28
  const posLeft: Record<string, number> = {}
  const posRight: Record<string, number> = {}
  leftNodes.forEach(([k], i) => (posLeft[k] = y0 + i * rowH))
  rightNodes.forEach(([k], i) => (posRight[k] = y0 + i * rowH))
  const maxCount = Math.max(1, ...shown.map((e) => e.count))
  return (
    <div className="w-full overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="block h-auto w-full text-fg" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Communication flow graph">
        {/* Column headers */}
        <text x={xLeft - 8} y={16} textAnchor="end" className="fill-current text-[10px] uppercase tracking-wider" fill="currentColor" opacity="0.5">{leftHeader}</text>
        <text x={xRight + 8} y={16} textAnchor="start" className="fill-current text-[10px] uppercase tracking-wider" fill="currentColor" opacity="0.5">{rightHeader}</text>
        {/* Edges — drawn first so nodes sit on top */}
        <g fill="none" strokeLinecap="round">
          {shown.map((e, i) => {
            const y1 = posLeft[e.src], y2 = posRight[e.dst]
            if (y1 === undefined || y2 === undefined) return null
            const midX = (xLeft + xRight) / 2
            const d = `M ${xLeft} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${xRight} ${y2}`
            const w = 1 + (e.count / maxCount) * 4
            return (
              <path key={i} d={d} stroke={e.color} strokeWidth={w} opacity="0.55">
                <title>{e.tooltip}</title>
              </path>
            )
          })}
        </g>
        {/* Left nodes */}
        {leftNodes.map(([k, n], i) => (
          <g key={'l-' + k}>
            <circle cx={xLeft} cy={y0 + i * rowH} r={4} fill="currentColor" opacity="0.7" />
            <text x={xLeft - 8} y={y0 + i * rowH + 4} textAnchor="end" fill="currentColor" className="text-[11.5px]">
              <title>{n.label} · {n.count} events</title>
              {truncate(n.label, 24)}
            </text>
          </g>
        ))}
        {/* Right nodes */}
        {rightNodes.map(([k, n], i) => (
          <g key={'r-' + k}>
            <circle cx={xRight} cy={y0 + i * rowH} r={4} fill="currentColor" opacity="0.7" />
            <text x={xRight + 8} y={y0 + i * rowH + 4} textAnchor="start" fill="currentColor" className="text-[11.5px]">
              <title>{n.label} · {n.count} events</title>
              {truncate(n.label, 20)}
            </text>
          </g>
        ))}
      </svg>
    </div>
  )
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s
  return s.slice(0, n - 1) + '…'
}

// DIRECTION_COLOR is the direction-driven palette shared by CommunicationGraphWidget and
// the traffic-direction donut, so the two widgets read as the same visual system.
const DIRECTION_COLOR: Record<CommFlowDirection, string> = {
  inbound:  '#f43f5e',  // rose  — external → us (the common attack shape)
  outbound: '#fb923c',  // orange — us → external (beaconing / exfil)
  lateral:  '#f59e0b',  // amber — internal → internal (attacker moving inside)
  unknown:  '#64748b',  // slate — we couldn't classify
}

// CommunicationGraphWidget (v2.13.0): grouped flows from external ASN / country / internal
// subnet nodes to enrolled-agent or destination-IP nodes, coloured by traffic direction.
// Data feed comes from CommunicationFlow() in the store — the SQL emits pre-computed source
// / dest keys plus a direction label so this component is pure rendering.
export function CommunicationGraphWidget({ data }: { data: CommFlow[] | undefined }) {
  if (!data || data.length === 0) return <Empty />
  const edges: BipartiteEdge[] = data.map((f) => ({
    src: f.source_key,
    dst: f.dest_key,
    srcLabel: f.source_label,
    dstLabel: f.dest_label,
    count: f.count,
    color: DIRECTION_COLOR[f.direction] || DIRECTION_COLOR.unknown,
    tooltip: `${f.source_label} → ${f.dest_label}\n${f.direction} · ${f.count} events`,
  }))
  return (
    <div>
      <BipartiteFlow edges={edges} leftHeader="source (ASN / country)" rightHeader="destination" />
      {/* Compact direction legend under the graph so operators know what the colours mean. */}
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11.5px] text-muted">
        {(Object.keys(DIRECTION_COLOR) as CommFlowDirection[]).map((d) => (
          <span key={d} className="inline-flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: DIRECTION_COLOR[d] }} />
            {d}
          </span>
        ))}
      </div>
    </div>
  )
}

// SrcDstGraphWidget (v2.13.0): external attacker source IP → agent it landed on. Same
// bipartite shape but a single edge colour (cyan) since direction is implicit ("inbound").
export function SrcDstGraphWidget({ data, agents }: { data: SrcDstFlow[] | undefined; agents?: AgentInfo[] }) {
  if (!data || data.length === 0) return <Empty />
  // If we have the agents list, decorate each right-side label with the agent's own last-known
  // source IP (from AgentInfo when present) — operator asked for "source ip (attacker) → agent
  // (bersama source ip dari agent kita nya)".
  const agentByName = new Map<string, AgentInfo>()
  for (const a of agents ?? []) agentByName.set(a.name, a)
  const edges: BipartiteEdge[] = data.map((f) => {
    const a = agentByName.get(f.agent_name)
    // AgentInfo doesn't carry an IP field today (v2.13.0), so we surface OS + name as the
    // secondary label. A future migration adding agent host_ip can plug in here.
    const dstLabel = a ? `${f.agent_name} (${a.os || 'agent'})` : f.agent_name
    return {
      src: f.source_ip,
      dst: f.agent_name,
      srcLabel: f.source_ip,
      dstLabel,
      count: f.count,
      color: '#22d3ee',
      tooltip: `${f.source_ip} → ${f.agent_name}\n${f.count} events`,
    }
  })
  return <BipartiteFlow edges={edges} leftHeader="attacker IP" rightHeader="agent" />
}
