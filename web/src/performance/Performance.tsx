import { useEffect, useMemo, useState } from 'react'
import { fetchMetricHosts, fetchHostMetrics, type MetricSeries, type TimeRange } from '../lib/api'
import { Page, Card, EmptyState, ErrorText } from '../components/ui'
import TimeChart, { humanBps, type ChartSeries } from '../components/TimeChart'
import TimeRangePicker from '../components/TimeRangePicker'

// Performance: the Cacti-style board for hosts that run the DeusWatch agent. CPU / memory / disk /
// network over time, charted in the DW design. Data is agent-reported (POST /v1/metrics), not SNMP:
// SNMP stays for agentless gear on the Network board.

// pick folds the long metric rows into the chart's (key, points) series for one panel.
function pick(series: MetricSeries[], metric: string, keyOf: (s: MetricSeries) => string): ChartSeries[] {
  return series.filter((s) => s.metric === metric).map((s) => ({ key: keyOf(s), points: s.points }))
}

export default function Performance() {
  const [hosts, setHosts] = useState<string[] | null>(null)
  const [host, setHost] = useState('')
  const [range, setRange] = useState<TimeRange>({ minutes: 360 })
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
    fetchHostMetrics(host, range)
      .then((s) => { setSeries(s); setError('') })
      .catch((e) => setError((e as Error).message))
  }, [host, range])

  const panels = useMemo(() => {
    const all = series ?? []
    return {
      cpu: pick(all, 'cpu_pct', () => 'CPU %'),
      mem: pick(all, 'mem_pct', () => 'Memory %'),
      net: [
        ...pick(all, 'net_in_bps', (s) => `${s.label} in`),
        ...pick(all, 'net_out_bps', (s) => `${s.label} out`),
      ],
      disk: pick(all, 'disk_used_pct', (s) => s.label),
      load: pick(all, 'load1', () => 'Load (1m)'),
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
        <div className="ml-auto">
          <TimeRangePicker value={range} onChange={setRange} />
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
          <Card title="CPU"><TimeChart series={panels.cpu} unit="%" area domain={[0, 100]} /></Card>
          <Card title="Memory"><TimeChart series={panels.mem} unit="%" area domain={[0, 100]} /></Card>
          <Card title="Network throughput"><TimeChart series={panels.net} fmt={humanBps} /></Card>
          <Card title="Disk usage"><TimeChart series={panels.disk} unit="%" domain={[0, 100]} /></Card>
          {panels.load.length > 0 && <Card title="Load average"><TimeChart series={panels.load} /></Card>}
        </div>
      )}
    </Page>
  )
}
