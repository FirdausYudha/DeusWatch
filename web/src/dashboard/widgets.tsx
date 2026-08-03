import { useEffect, useState } from 'react'
import type { SeriesPoint, TimelinePoint, RiskyIP, SuspiciousIP, SlowScanner, AgentInfo, DisplayStatus } from '../lib/api'
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
