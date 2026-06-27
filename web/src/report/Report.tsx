import { useEffect, useState } from 'react'
import {
  fetchReport, fetchReportMarkdown, fetchReportSummary, generateReportSummary,
  type SecurityReport, type ReportCount, type ReportSummary,
} from '../lib/api'

const PRINT_CSS = `@media print {
  body * { visibility: hidden; }
  #report-print, #report-print * { visibility: visible; }
  #report-print { position: absolute; inset: 0; padding: 16px; background: #fff; }
  #report-print, #report-print * { color: #111 !important; }
  #report-print .card-print { background: #fff !important; border: 1px solid #ddd !important; }
  .no-print { display: none !important; }
}`

const WINDOWS: { label: string; hours: number }[] = [
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
  { label: '30d', hours: 720 },
]

function StatCard({ label, value, accent }: { label: string; value: number | string; accent?: string }) {
  return (
    <div className="card-print rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-xs uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-1 text-3xl font-semibold ${accent ?? 'text-white'}`}>{value}</div>
    </div>
  )
}

function BarList({ title, rows }: { title: string; rows: ReportCount[] | null }) {
  const max = Math.max(1, ...(rows ?? []).map((r) => r.count))
  return (
    <div className="card-print rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">{title}</h2>
      {rows && rows.length > 0 ? (
        <ul className="space-y-2">
          {rows.map((r, i) => (
            <li key={i} className="flex items-center gap-3 text-sm">
              <span className="w-44 truncate text-slate-300" title={r.label}>{r.label || '(empty)'}</span>
              <div className="h-2 flex-1 overflow-hidden rounded bg-slate-800">
                <div className="h-full rounded bg-indigo-500" style={{ width: `${(r.count / max) * 100}%` }} />
              </div>
              <span className="w-8 text-right text-xs text-slate-400">{r.count}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-slate-600">no data yet</p>
      )}
    </div>
  )
}

export default function Report() {
  const [hours, setHours] = useState(24)
  const [report, setReport] = useState<SecurityReport | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [summary, setSummary] = useState<ReportSummary | null>(null)
  const [genBusy, setGenBusy] = useState(false)
  const [genError, setGenError] = useState('')

  useEffect(() => {
    setLoading(true)
    setError('')
    fetchReport(hours)
      .then(setReport)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false))
  }, [hours])

  // Load the latest stored AI summary once (cheap — no LLM call).
  useEffect(() => {
    fetchReportSummary().then(setSummary).catch(() => {})
  }, [])

  const generate = async () => {
    setGenBusy(true)
    setGenError('')
    try {
      setSummary(await generateReportSummary(hours))
    } catch (e) {
      setGenError((e as Error).message)
    } finally {
      setGenBusy(false)
    }
  }

  const download = async () => {
    try {
      const md = await fetchReportMarkdown(hours)
      const url = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `deuswatch-report-${hours}h.md`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div className="mx-auto max-w-5xl px-8 py-8" id="report-print">
      <style>{PRINT_CSS}</style>
      <header className="mb-6 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Report</h1>
          <p className="mt-1 text-sm text-slate-500">
            Security summary
            {report && <span className="ml-1 text-slate-600">· generated {new Date(report.generated).toLocaleString('en-US')}</span>}
          </p>
        </div>
        <div className="no-print flex gap-2">
          <button
            onClick={() => window.print()}
            className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 transition-colors hover:bg-slate-800"
            title="Print or save as PDF"
          >
            ⬇ PDF
          </button>
          <button
            onClick={download}
            className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 transition-colors hover:bg-slate-800"
          >
            Markdown
          </button>
        </div>
      </header>

      {/* AI executive summary — generated on demand or on a schedule */}
      <section className="card-print mb-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500">AI executive summary</h2>
          <button
            onClick={generate}
            disabled={genBusy}
            className="no-print rounded-md border border-indigo-500/40 px-2.5 py-1 text-xs text-indigo-300 transition-colors hover:bg-indigo-500/10 disabled:opacity-50"
          >
            {genBusy ? 'Generating…' : '✨ Generate now'}
          </button>
        </div>
        {summary?.summary ? (
          <>
            <p className="whitespace-pre-line text-sm leading-relaxed text-slate-200">{summary.summary}</p>
            <p className="mt-3 text-xs text-slate-600">
              {summary.model && <span>{summary.model} · </span>}
              {summary.period_hours ? `last ${summary.period_hours}h · ` : ''}
              {summary.generated_at ? new Date(summary.generated_at).toLocaleString('en-US') : ''}
            </p>
          </>
        ) : (
          <p className="text-sm text-slate-600">
            No AI summary yet. Click “Generate now” — needs an LLM integration (e.g. a free local Ollama). Runs on
            demand, so there’s no per-alert API cost.
          </p>
        )}
        {genError && <p className="mt-2 text-sm text-rose-400">{genError}</p>}
      </section>

      <div className="no-print mb-6 flex gap-2">
        {WINDOWS.map((wnd) => (
          <button
            key={wnd.hours}
            onClick={() => setHours(wnd.hours)}
            className={`rounded-lg px-3 py-1.5 text-sm transition-colors ${
              hours === wnd.hours
                ? 'bg-indigo-500/10 font-medium text-indigo-300'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            }`}
          >
            {wnd.label}
          </button>
        ))}
        {loading && <span className="self-center text-xs text-slate-600">loading…</span>}
      </div>

      {error && <p className="mb-4 text-sm text-rose-400">{error}</p>}

      <section className="mb-6 grid gap-3 sm:grid-cols-2">
        <StatCard label="Total events" value={report?.total_events ?? '—'} />
        <StatCard label="Total alerts" value={report?.total_alerts ?? '—'} accent="text-orange-300" />
      </section>

      <section className="grid gap-3 lg:grid-cols-2">
        <BarList title="Severity" rows={report?.by_severity ?? null} />
        <BarList title="LLM verdict" rows={report?.by_verdict ?? null} />
        <BarList title="Top source IP" rows={report?.top_source_ips ?? null} />
        <BarList title="Top rule" rows={report?.top_rules ?? null} />
        <BarList title="Top MITRE technique" rows={report?.top_techniques ?? null} />
      </section>
    </div>
  )
}
