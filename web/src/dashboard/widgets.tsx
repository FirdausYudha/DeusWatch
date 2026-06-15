import type { SeriesPoint, TimelinePoint } from '../lib/api'

export const WIDGET_COLORS = ['#6366f1', '#10b981', '#f43f5e', '#f59e0b', '#38bdf8', '#8b5cf6', '#fb923c']
// Categorical palette for donut segments, starting from the widget's chosen color.
function palette(start: string): string[] {
  const i = Math.max(0, WIDGET_COLORS.indexOf(start))
  return [...WIDGET_COLORS.slice(i), ...WIDGET_COLORS.slice(0, i)]
}

function Empty() {
  return <p className="py-6 text-center text-sm text-slate-600">no data yet</p>
}

export function StatWidget({ value, color }: { value: number; color: string }) {
  return <div className="py-2 text-4xl font-semibold" style={{ color }}>{value.toLocaleString('en-US')}</div>
}

export function BarChart({ data, color }: { data: SeriesPoint[]; color: string }) {
  if (!data?.length) return <Empty />
  const max = Math.max(1, ...data.map((d) => d.count))
  return (
    <ul className="space-y-1.5">
      {data.map((d, i) => (
        <li key={i} className="flex items-center gap-2 text-sm">
          <span className="w-28 truncate text-slate-400" title={d.label}>{d.label || '—'}</span>
          <div className="h-2 flex-1 overflow-hidden rounded bg-slate-800">
            <div className="h-full rounded" style={{ width: `${(d.count / max) * 100}%`, background: color }} />
          </div>
          <span className="w-8 text-right text-xs text-slate-400">{d.count}</span>
        </li>
      ))}
    </ul>
  )
}

export function DonutChart({ data, color }: { data: SeriesPoint[]; color: string }) {
  if (!data?.length) return <Empty />
  const colors = palette(color)
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
              stroke={colors[i % colors.length]}
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
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: colors[i % colors.length] }} />
            <span className="text-slate-300">{d.label || '—'}</span>
            <span className="text-slate-500">{d.count}</span>
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
      <tbody className="divide-y divide-slate-800">
        {data.map((d, i) => (
          <tr key={i}>
            <td className="py-1.5 pr-2 text-slate-300">{d.label || '—'}</td>
            <td className="py-1.5 text-right font-mono text-xs text-slate-400">{d.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
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
          <span className="text-lg leading-none">{flag(d.label)}</span>
          <span className="w-8 font-mono text-xs text-slate-300">{d.label}</span>
          <div className="h-2 flex-1 overflow-hidden rounded bg-slate-800">
            <div className="h-full rounded" style={{ width: `${(d.count / max) * 100}%`, background: color }} />
          </div>
          <span className="w-8 text-right text-xs text-slate-400">{d.count}</span>
        </li>
      ))}
    </ul>
  )
}
