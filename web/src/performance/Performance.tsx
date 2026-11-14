import { useEffect, useMemo, useState } from 'react'
import {
  ResponsiveContainer, AreaChart, Area, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts'
import { fetchMetricHosts, fetchHostMetrics, type MetricSeries } from '../lib/api'
import { Page, Card, EmptyState, ErrorText } from '../components/ui'

// Performance: the Cacti-style board for hosts that run the DeusWatch agent. CPU / memory / disk /
// network over time, charted in the DW design. Data is agent-reported (POST /v1/metrics), not SNMP:
// SNMP stays for agentless gear on the Network board.

const RANGES: { hours: number; label: string }[] = [
  { hours: 1, label: '1h' }, { hours: 6, label: '6h' }, { hours: 24, label: '24h' }, { hours: 168, label: '7d' },
]
const LINE_COLORS = ['#6366f1', '#10b981', '#f43f5e', '#f59e0b', '#38bdf8', '#8b5cf6', '#fb923c']

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
// humanBps turns bytes/sec into a readable rate for the network panel.
function humanBps(v: number): string {
  const u = ['B/s', 'KB/s', 'MB/s', 'GB/s']
  let i = 0
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`
}

// toWide folds long (metric,label) series into the row-per-timestamp shape recharts wants.
function toWide(series: MetricSeries[], keyOf: (s: MetricSeries) => string) {
  const byT = new Map<string, Record<string, number | string>>()
  const keys: string[] = []
  for (const s of series) {
    const k = keyOf(s)
    if (!keys.includes(k)) keys.push(k)
    for (const p of s.points) {
      let row = byT.get(p.t)
      if (!row) { row = { t: p.t }; byT.set(p.t, row) }
      row[k] = p.v
    }
  }
  const data = [...byT.values()].sort((a, b) => (a.t < b.t ? -1 : 1))
  return { data, keys }
}

export default function Performance() {
  const [hosts, setHosts] = useState<string[] | null>(null)
  const [host, setHost] = useState('')
  const [hours, setHours] = useState(6)
  const [series, setSeries] = useState<MetricSeries[] | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchMetricHosts()
      .then((hs) => { setHosts(hs); setHost((cur) => cur || hs[0] || '') })
      .catch((e) => setError((e as Error).message))
  }, [])

  useEffect(() => {
    if (!host) { setSeries([]); return }
    setSeries(null)
    fetchHostMetrics(host, hours)
      .then((s) => { setSeries(s); setError('') })
      .catch((e) => setError((e as Error).message))
  }, [host, hours])

  const panels = useMemo(() => {
    const all = series ?? []
    const by = (m: string) => all.filter((s) => s.metric === m)
    return {
      cpu: toWide(by('cpu_pct'), () => 'CPU %'),
      load: toWide(by('load1'), () => 'Load (1m)'),
      mem: toWide(by('mem_pct'), () => 'Memory %'),
      net: toWide(
        all.filter((s) => s.metric === 'net_in_bps' || s.metric === 'net_out_bps'),
        (s) => `${s.label} ${s.metric === 'net_in_bps' ? 'in' : 'out'}`,
      ),
      disk: toWide(by('disk_used_pct'), (s) => s.label),
    }
  }, [series])

  return (
    <Page>
      <header className="mb-4 flex flex-wrap items-center gap-3">
        <label className="text-[13px] text-muted">Host</label>
        <select
          value={host}
          onChange={(e) => setHost(e.target.value)}
          className="rounded-[8px] border border-border bg-surface px-3 py-1.5 text-[13.5px] text-fg"
        >
          {(hosts ?? []).map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <div className="ml-auto inline-flex rounded-[8px] border border-border p-0.5 text-[13px]">
          {RANGES.map((r) => (
            <button
              key={r.hours}
              onClick={() => setHours(r.hours)}
              className={`rounded-md px-3 py-1 transition-colors ${hours === r.hours ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg'}`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </header>

      {error && <ErrorText>{error}</ErrorText>}

      {hosts !== null && hosts.length === 0 ? (
        <EmptyState
          title="No host metrics reported yet"
          hint="Agents on Linux sample CPU, memory, disk and network every 30s and ship them automatically (set METRICS=0 to disable). Once an agent reports, pick it above."
        />
      ) : series === null ? (
        <p className="text-[13px] text-dim">Loading…</p>
      ) : series.length === 0 ? (
        <EmptyState title="No samples in this window" hint="Try a wider time range, or check that the agent is online." />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="CPU" unit="%" {...panels.cpu} area domain={[0, 100]} />
          <Panel title="Memory" unit="%" {...panels.mem} area domain={[0, 100]} />
          <Panel title="Network throughput" {...panels.net} fmt={humanBps} />
          <Panel title="Disk usage" unit="%" {...panels.disk} domain={[0, 100]} />
          {panels.load.keys.length > 0 && <Panel title="Load average" {...panels.load} />}
        </div>
      )}
    </Page>
  )
}

function Panel({
  title, unit, data, keys, area, domain, fmt,
}: {
  title: string
  unit?: string
  data: Record<string, number | string>[]
  keys: string[]
  area?: boolean
  domain?: [number, number]
  fmt?: (v: number) => string
}) {
  const tipFmt = (v: unknown): string =>
    typeof v === 'number' ? (fmt ? fmt(v) : `${v.toFixed(1)}${unit ?? ''}`) : String(v ?? '')
  const yFmt = (v: number) => (fmt ? fmt(v) : `${v}${unit ?? ''}`)
  const labelFmt = (l: unknown) => fmtTime(String(l))

  return (
    <Card title={title}>
      {data.length === 0 ? (
        <p className="py-10 text-center text-[13px] text-dim">no data yet</p>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          {area ? (
            <AreaChart data={data} margin={{ left: 4, right: 20, top: 6, bottom: 0 }}>
              <defs>
                <linearGradient id={`g-${title}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={LINE_COLORS[0]} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={LINE_COLORS[0]} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={AXIS_LINE} vertical={false} />
              <XAxis dataKey="t" tickFormatter={fmtTick} tick={AXIS_TICK} stroke={AXIS_LINE} minTickGap={40} />
              <YAxis domain={domain} tickFormatter={yFmt} tick={AXIS_TICK} stroke={AXIS_LINE} width={48} />
              <Tooltip {...TIP} labelFormatter={labelFmt} formatter={tipFmt} />
              {keys.map((k) => (
                <Area key={k} type="monotone" dataKey={k} name={k} stroke={LINE_COLORS[0]} fill={`url(#g-${title})`} strokeWidth={2} dot={false} isAnimationActive={false} connectNulls />
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
      )}
    </Card>
  )
}
