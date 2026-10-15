import { useEffect, useState } from 'react'
import { fetchTicketSLA, SEVERITY, type SLABucket, type SLADurations, type SLAStats } from '../lib/api'
import { Card, Select, StatCard } from '../components/ui'

// The ticket scorecard.
//
// The hospital IT team is judged on its queue: "jamnya awalnya ini masuk, nanti penyelesaiannya
// kayak gimana. Nanti bisa jadi rapot." So this reports two things side by side and never averages
// them together:
//
//   Response   — how long until somebody picked the ticket up.
//   Resolution — how long until it was actually finished.
//
// Medians and p90s, never means: one ticket left open over a long weekend drags a mean until the
// number describes nothing, while the p90 says how bad a bad week gets.

const WINDOWS = [7, 30, 90]

// secs renders a duration the way someone reads it out loud, not as a raw number of seconds.
function secs(v: number | null): string {
  if (v === null) return '—'
  const s = Math.round(v)
  if (s < 60) return `${s}s`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h}h ${m % 60}m`
  return `${Math.round(h / 24)}d`
}

function Pair({ d }: { d: SLADurations }) {
  return (
    <span className="tabular-nums">
      {secs(d.p50_secs)}
      <span className="text-dim"> / {secs(d.p90_secs)}</span>
    </span>
  )
}

function Breakdown({ title, rows, label }: { title: string; rows: SLABucket[]; label: (k: string) => string }) {
  if (rows.length === 0) return null
  return (
    <Card title={title} bodyClass="p-0">
      <table className="w-full text-left text-[13px]">
        <thead className="border-b border-border text-[11.5px] uppercase tracking-wider text-dim">
          <tr>
            <th className="px-4 py-2 font-medium">{title.includes('severity') ? 'Severity' : 'Picked up by'}</th>
            <th className="px-4 py-2 font-medium">Tickets</th>
            <th className="px-4 py-2 font-medium">Resolved</th>
            <th className="px-4 py-2 font-medium" title="median / p90">Response</th>
            <th className="px-4 py-2 font-medium" title="median / p90">Resolution</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {rows.map((r) => (
            <tr key={r.key}>
              <td className="px-4 py-2 text-fg">{label(r.key)}</td>
              <td className="px-4 py-2 tabular-nums text-muted">{r.total}</td>
              <td className="px-4 py-2 tabular-nums text-muted">{r.resolved}</td>
              <td className="px-4 py-2 text-fg"><Pair d={r.response} /></td>
              <td className="px-4 py-2 text-fg"><Pair d={r.resolution} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  )
}

export default function Scorecard() {
  const [days, setDays] = useState(30)
  const [stats, setStats] = useState<SLAStats | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let live = true
    fetchTicketSLA(days)
      .then((s) => live && (setStats(s), setError('')))
      .catch((e) => live && setError((e as Error).message))
    return () => {
      live = false
    }
  }, [days])

  if (error) return <p className="mb-4 text-[13px] text-critical">{error}</p>
  if (!stats) return null

  return (
    <section className="mb-5">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[14px] font-semibold text-fg">
          Scorecard <span className="font-normal text-dim">· median / p90</span>
        </h2>
        <Select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Scorecard window">
          {WINDOWS.map((d) => (
            <option key={d} value={d}>
              Last {d} days
            </option>
          ))}
        </Select>
      </div>

      <div className="mb-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Tickets"
          value={stats.total}
          hint={`${stats.auto_created} opened automatically`}
        />
        <StatCard
          label="Response"
          value={secs(stats.response.p50_secs)}
          hint={`p90 ${secs(stats.response.p90_secs)} · time until picked up`}
        />
        <StatCard
          label="Resolution"
          value={secs(stats.resolution.p50_secs)}
          hint={`p90 ${secs(stats.resolution.p90_secs)} · ${stats.resolved} resolved`}
        />
        {/* The number worth acting on today: live tickets nobody has touched at all. Not "late" —
            untouched, which is a different and worse thing. */}
        <StatCard
          label="Untouched"
          value={stats.never_acked}
          accentClass={stats.never_acked ? 'text-critical' : 'text-ok'}
          hint={`of ${stats.still_open} still open`}
        />
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <Breakdown
          title="By severity"
          rows={stats.by_severity}
          label={(k) => SEVERITY[Number(k)]?.label ?? k}
        />
        <Breakdown title="By responder" rows={stats.by_assignee} label={(k) => k} />
      </div>
    </section>
  )
}
