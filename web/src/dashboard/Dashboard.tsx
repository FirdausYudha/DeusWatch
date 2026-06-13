import { useEffect, useState } from 'react'
import { fetchHealth, type DepState, type Health } from '../lib/api'

type DotState = 'good' | 'bad' | 'unknown'

function Dot({ state }: { state: DotState }) {
  const color =
    state === 'good' ? 'bg-emerald-400' : state === 'bad' ? 'bg-rose-400' : 'bg-amber-400'
  const glow = state === 'good' ? 'shadow-[0_0_10px_2px] shadow-emerald-400/40' : ''
  return <span className={`inline-block h-2.5 w-2.5 rounded-full ${color} ${glow}`} />
}

function depDot(s: DepState): DotState {
  return s === 'reachable' ? 'good' : s === 'unreachable' ? 'bad' : 'unknown'
}

// Placeholder widget Fase 1 (design doc bagian 6: time-series, top-N, counter, pie).
const WIDGETS = [
  { title: 'Events over time', kind: 'Time-series' },
  { title: 'Top attacker IPs', kind: 'Top-N table' },
  { title: 'Alerts (24 jam)', kind: 'Counter' },
  { title: 'Severity breakdown', kind: 'Pie' },
]

export default function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null)
  const [updated, setUpdated] = useState<Date | null>(null)

  useEffect(() => {
    let active = true
    const tick = async () => {
      const h = await fetchHealth()
      if (!active) return
      setHealth(h)
      setUpdated(new Date())
    }
    void tick()
    const id = setInterval(tick, 5000)
    return () => {
      active = false
      clearInterval(id)
    }
  }, [])

  const services: { name: string; sub: string; state: DotState; detail: string }[] = [
    {
      name: 'API Server',
      sub: 'Go · :8080',
      state: health ? (health.api === 'alive' ? 'good' : 'bad') : 'unknown',
      detail: health?.api ?? 'memeriksa…',
    },
    {
      name: 'PostgreSQL + TimescaleDB',
      sub: 'penyimpanan log',
      state: health ? depDot(health.postgres) : 'unknown',
      detail: health?.postgres ?? 'memeriksa…',
    },
    {
      name: 'NATS JetStream',
      sub: 'message bus',
      state: health ? depDot(health.nats) : 'unknown',
      detail: health?.nats ?? 'memeriksa…',
    },
  ]

  const allReady = health?.ready ?? false

  return (
    <div className="mx-auto max-w-6xl px-8 py-8">
      {/* Header */}
      <header className="mb-8 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Dashboard</h1>
          <p className="mt-1 text-sm text-slate-500">
            Status fondasi DeusWatch · pembaruan tiap 5 detik
          </p>
        </div>
        <div
          className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium ${
            allReady
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
              : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
          }`}
        >
          <Dot state={allReady ? 'good' : 'unknown'} />
          {allReady ? 'Semua sistem siap' : 'Menunggu dependensi'}
        </div>
      </header>

      {/* System Health */}
      <section className="mb-8">
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
          System Health
        </h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {services.map((s) => (
            <div
              key={s.name}
              className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-200">{s.name}</span>
                <Dot state={s.state} />
              </div>
              <div className="mt-1 text-xs text-slate-500">{s.sub}</div>
              <div
                className={`mt-3 text-sm font-mono ${
                  s.state === 'good'
                    ? 'text-emerald-400'
                    : s.state === 'bad'
                      ? 'text-rose-400'
                      : 'text-amber-400'
                }`}
              >
                {s.detail}
              </div>
            </div>
          ))}
        </div>
        <p className="mt-3 text-xs text-slate-600">
          {updated
            ? `Terakhir diperbarui ${updated.toLocaleTimeString('id-ID')}`
            : 'Menghubungi API…'}
          {health?.api === 'down' && (
            <span className="ml-1 text-rose-400">
              — API tak terjangkau. Pastikan{' '}
              <code className="text-rose-300">docker compose up</code> berjalan.
            </span>
          )}
        </p>
      </section>

      {/* Widget grid (placeholder Fase 1) */}
      <section>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
          Widget (segera hadir)
        </h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {WIDGETS.map((w) => (
            <div
              key={w.title}
              className="flex h-36 flex-col rounded-xl border border-dashed border-slate-800 bg-slate-900/30 p-4"
            >
              <span className="text-sm font-medium text-slate-300">{w.title}</span>
              <span className="text-xs text-slate-600">{w.kind}</span>
              <div className="mt-auto text-xs text-slate-700">menunggu data log…</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
