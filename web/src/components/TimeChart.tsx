import {
  ResponsiveContainer, AreaChart, Area, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts'

// TimeChart is the one time-series chart used by both the host Performance board and the SNMP
// Network board, so every graph in the product reads the same. It takes long (key, points) series
// and folds them into the row-per-timestamp shape recharts wants.

export type ChartSeries = { key: string; points: { t: string; v: number }[] }

export const LINE_COLORS = ['#6366f1', '#10b981', '#f43f5e', '#f59e0b', '#38bdf8', '#8b5cf6', '#fb923c']

const AXIS_TICK = { fill: 'var(--color-muted)', fontSize: 11 }
const AXIS_LINE = 'var(--color-border)'
const TIP = {
  contentStyle: { background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: 12, color: 'var(--color-fg)' },
  labelStyle: { color: 'var(--color-muted)' },
  itemStyle: { color: 'var(--color-fg)' },
}

function fmtTick(t: string): string {
  const d = new Date(t)
  return isNaN(+d) ? t : d.toLocaleString('en-US', { month: 'numeric', day: 'numeric', hour: 'numeric', minute: '2-digit', hour12: false })
}
function fmtTime(t: string): string {
  const d = new Date(t)
  return isNaN(+d) ? t : d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// humanBps turns bytes/sec into a readable rate, shared by the host-network and SNMP-interface charts.
export function humanBps(v: number): string {
  const u = ['B/s', 'KB/s', 'MB/s', 'GB/s']
  let i = 0
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`
}

function toWide(series: ChartSeries[]) {
  const byT = new Map<string, Record<string, number | string>>()
  const keys: string[] = []
  for (const s of series) {
    if (s.points.length === 0) continue
    if (!keys.includes(s.key)) keys.push(s.key)
    for (const p of s.points) {
      let row = byT.get(p.t)
      if (!row) { row = { t: p.t }; byT.set(p.t, row) }
      row[s.key] = p.v
    }
  }
  const data = [...byT.values()].sort((a, b) => (a.t < b.t ? -1 : 1))
  return { data, keys }
}

export default function TimeChart({
  series, unit, area, domain, fmt, height = 220,
}: {
  series: ChartSeries[]
  unit?: string
  area?: boolean
  domain?: [number, number]
  fmt?: (v: number) => string
  height?: number
}) {
  const { data, keys } = toWide(series)
  if (data.length === 0) {
    return <p className="py-10 text-center text-[13px] text-dim">no data yet</p>
  }

  const tipFmt = (v: unknown): string =>
    typeof v === 'number' ? (fmt ? fmt(v) : `${v.toFixed(1)}${unit ?? ''}`) : String(v ?? '')
  const yFmt = (v: number) => (fmt ? fmt(v) : `${v}${unit ?? ''}`)
  const labelFmt = (l: unknown) => fmtTime(String(l))
  const gid = `g-${keys.join('_')}`

  return (
    <ResponsiveContainer width="100%" height={height}>
      {area ? (
        <AreaChart data={data} margin={{ left: 4, right: 20, top: 6, bottom: 0 }}>
          <defs>
            <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={LINE_COLORS[0]} stopOpacity={0.35} />
              <stop offset="100%" stopColor={LINE_COLORS[0]} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={AXIS_LINE} vertical={false} />
          <XAxis dataKey="t" tickFormatter={fmtTick} tick={AXIS_TICK} stroke={AXIS_LINE} minTickGap={40} />
          <YAxis domain={domain} tickFormatter={yFmt} tick={AXIS_TICK} stroke={AXIS_LINE} width={56} />
          <Tooltip {...TIP} labelFormatter={labelFmt} formatter={tipFmt} />
          {keys.map((k) => (
            <Area key={k} type="monotone" dataKey={k} name={k} stroke={LINE_COLORS[0]} fill={`url(#${gid})`} strokeWidth={2} dot={false} isAnimationActive={false} connectNulls />
          ))}
        </AreaChart>
      ) : (
        <LineChart data={data} margin={{ left: 4, right: 20, top: 6, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke={AXIS_LINE} vertical={false} />
          <XAxis dataKey="t" tickFormatter={fmtTick} tick={AXIS_TICK} stroke={AXIS_LINE} minTickGap={40} />
          <YAxis domain={domain} tickFormatter={yFmt} tick={AXIS_TICK} stroke={AXIS_LINE} width={56} />
          <Tooltip {...TIP} labelFormatter={labelFmt} formatter={tipFmt} />
          {keys.length > 1 && <Legend wrapperStyle={{ fontSize: 12 }} />}
          {keys.map((k, i) => (
            <Line key={k} type="monotone" dataKey={k} name={k} stroke={LINE_COLORS[i % LINE_COLORS.length]} strokeWidth={2} dot={false} isAnimationActive={false} connectNulls />
          ))}
        </LineChart>
      )}
    </ResponsiveContainer>
  )
}
