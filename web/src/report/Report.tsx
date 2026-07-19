import { useEffect, useState } from 'react'
import {
  fetchReport, fetchReportMarkdown, fetchReportSummary, generateReportSummary,
  fetchReportAIConfig, saveReportAIConfig, exportReportToWebhook,
  fetchNotifyConfig, saveNotifyConfig,
  type SecurityReport, type ReportCount, type ReportSummary, type ReportAIConfig, type NotifyConfig,
} from '../lib/api'
import { usePersistedState } from '../lib/usePersistedState'

const SCHEDULE_PRESETS: { label: string; hours: number }[] = [
  { label: 'Auto: off', hours: 0 },
  { label: 'Every 24h', hours: 24 },
  { label: 'Every 3 days', hours: 72 },
  { label: 'Every 7 days', hours: 168 },
]

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
    <div className="card-print rounded-xl border border-border bg-surface p-4">
      <div className="text-xs uppercase tracking-wider text-dim">{label}</div>
      <div className={`mt-1 text-3xl font-semibold ${accent ?? 'text-fg'}`}>{value}</div>
    </div>
  )
}

function BarList({ title, rows }: { title: string; rows: ReportCount[] | null }) {
  const max = Math.max(1, ...(rows ?? []).map((r) => r.count))
  return (
    <div className="card-print rounded-xl border border-border bg-surface p-4">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-dim">{title}</h2>
      {rows && rows.length > 0 ? (
        <ul className="space-y-2">
          {rows.map((r, i) => (
            <li key={i} className="flex items-center gap-3 text-sm">
              <span className="w-44 truncate text-fg" title={r.label}>{r.label || '(empty)'}</span>
              <div className="h-2 flex-1 overflow-hidden rounded bg-surface-2">
                <div className="h-full rounded bg-accent" style={{ width: `${(r.count / max) * 100}%` }} />
              </div>
              <span className="w-8 text-right text-xs text-muted">{r.count}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-dim">no data yet</p>
      )}
    </div>
  )
}

export default function Report() {
  const [hours, setHours] = useState(24)
  // Optional explicit date range (YYYY-MM-DD). When `from` is set it replaces the rolling
  // last-N-hours window, so the page â€” and therefore the PDF/Markdown export â€” covers exactly
  // the dates you picked. Persisted so it survives leaving the page.
  const [rangeFrom, setRangeFrom] = usePersistedState('report.from', '')
  const [rangeTo, setRangeTo] = usePersistedState('report.to', '')
  const range = rangeFrom ? { from: rangeFrom, to: rangeTo || undefined } : undefined
  const [report, setReport] = useState<SecurityReport | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [summary, setSummary] = useState<ReportSummary | null>(null)
  const [genBusy, setGenBusy] = useState(false)
  const [genError, setGenError] = useState('')
  const [cfg, setCfg] = useState<ReportAIConfig>({ interval_hours: 0, period_hours: 24 })
  const [customMode, setCustomMode] = useState(false)
  const [customDays, setCustomDays] = useState('')

  useEffect(() => {
    setLoading(true)
    setError('')
    fetchReport(hours, rangeFrom ? { from: rangeFrom, to: rangeTo || undefined } : undefined)
      .then(setReport)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false))
  }, [hours, rangeFrom, rangeTo])

  // Scheduled report delivery to channels (Telegram/email) â€” separate from the AI schedule.
  const [delivery, setDelivery] = useState<NotifyConfig | null>(null)
  const [delivCustom, setDelivCustom] = useState(false)
  const [delivDays, setDelivDays] = useState('')
  const [delivMsg, setDelivMsg] = useState('')

  // Custom AI prompt template editor.
  const [promptOpen, setPromptOpen] = useState(false)
  const [promptText, setPromptText] = useState('')
  const [promptMsg, setPromptMsg] = useState('')
  const [promptBusy, setPromptBusy] = useState(false)
  const savePrompt = async (text: string) => {
    setPromptMsg(''); setPromptBusy(true)
    try {
      // at_hour must always be sent: the API treats an omitted value as "no fixed hour".
      const c = await saveReportAIConfig({ interval_hours: cfg.interval_hours, period_hours: cfg.period_hours || 24, summary_prompt: text, at_hour: cfg.at_hour ?? -1 })
      setCfg((prev) => ({ ...c, default_prompt: prev.default_prompt }))
      setPromptText(text)
      setPromptMsg(text ? 'Custom prompt saved.' : 'Reset to the default prompt.')
    } catch (e) {
      setPromptMsg((e as Error).message)
    } finally {
      setPromptBusy(false)
    }
  }

  // Load the latest stored AI summary + the schedule once.
  useEffect(() => {
    fetchReportSummary().then(setSummary).catch(() => {})
    fetchReportAIConfig().then((c) => { setCfg(c); setPromptText(c.summary_prompt ?? '') }).catch(() => {})
    fetchNotifyConfig().then(setDelivery).catch(() => {})
  }, [])

  const delivIsCustom =
    !!delivery && delivery.report_interval_hours > 0 &&
    !SCHEDULE_PRESETS.some((p) => p.hours === delivery.report_interval_hours)
  const saveDelivery = async (intervalHours: number) => {
    if (!delivery) return
    setDelivMsg('')
    const h = Math.max(0, intervalHours)
    const next = { ...delivery, report_interval_hours: h, report_period_hours: h > 0 ? h : delivery.report_period_hours }
    try {
      setDelivery(await saveNotifyConfig(next))
      setDelivMsg(h > 0 ? 'Delivery schedule saved.' : 'Delivery off.')
    } catch (e) {
      setDelivMsg((e as Error).message)
    }
  }
  const onDeliveryChange = (v: string) => {
    if (v === 'custom') {
      setDelivCustom(true)
      setDelivDays(String(Math.max(1, Math.round((delivery?.report_interval_hours || 24) / 24))))
    } else {
      setDelivCustom(false)
      void saveDelivery(Number(v))
    }
  }

  const isCustom = cfg.interval_hours > 0 && !SCHEDULE_PRESETS.some((p) => p.hours === cfg.interval_hours)
  const saveSchedule = async (hours: number, atHour?: number) => {
    try {
      setCfg(await saveReportAIConfig({
        interval_hours: Math.max(0, hours),
        period_hours: cfg.period_hours || 24,
        summary_prompt: cfg.summary_prompt ?? '',
        at_hour: atHour ?? cfg.at_hour ?? -1,
      }))
      setGenError('')
    } catch (e) {
      setGenError((e as Error).message)
    }
  }
  const onScheduleChange = (v: string) => {
    if (v === 'custom') {
      setCustomMode(true)
      setCustomDays(String(Math.max(1, Math.round((cfg.interval_hours || 24) / 24))))
    } else {
      setCustomMode(false)
      void saveSchedule(Number(v))
    }
  }

  const generate = async () => {
    setGenBusy(true)
    setGenError('')
    try {
      // Summarize the same window the page shows â€” the date range if one is set.
      setSummary(await generateReportSummary(hours, range))
    } catch (e) {
      setGenError((e as Error).message)
    } finally {
      setGenBusy(false)
    }
  }

  const [whMsg, setWhMsg] = useState('')
  const sendWebhook = async () => {
    setWhMsg('Sendingâ€¦')
    try {
      await exportReportToWebhook(hours)
      setWhMsg('Sent to webhook âœ“')
    } catch (e) {
      setWhMsg((e as Error).message)
    }
  }

  const download = async () => {
    try {
      const md = await fetchReportMarkdown(hours, range)
      const url = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      // Name the file after what it actually covers.
      a.download = range ? `deuswatch-report-${rangeFrom}_to_${rangeTo || 'now'}.md` : `deuswatch-report-${hours}h.md`
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
          <h1 className="text-2xl font-semibold tracking-tight text-fg">Report</h1>
          <p className="mt-1 text-sm text-dim">
            Security summary
            {report && <span className="ml-1 text-dim">Â· generated {new Date(report.generated).toLocaleString('en-US')}</span>}
          </p>
          {/* Explicit date range â€” what the PDF / Markdown export covers. Empty = the rolling
              window from the period picker below. */}
          <div className="no-print mt-2 flex flex-wrap items-center gap-2 text-xs text-muted">
            <span>Date range</span>
            <input
              type="date"
              value={rangeFrom}
              max={rangeTo || undefined}
              onChange={(e) => setRangeFrom(e.target.value)}
              className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-fg outline-none focus:border-accent [color-scheme:dark]"
            />
            <span className="text-dim">â†’</span>
            <input
              type="date"
              value={rangeTo}
              min={rangeFrom || undefined}
              onChange={(e) => setRangeTo(e.target.value)}
              className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-fg outline-none focus:border-accent [color-scheme:dark]"
            />
            {rangeFrom ? (
              <button
                onClick={() => { setRangeFrom(''); setRangeTo('') }}
                className="rounded-md border border-border px-2 py-1 text-xs text-muted hover:bg-surface-2"
              >
                Clear
              </button>
            ) : (
              <span className="text-dim">empty = rolling window</span>
            )}
          </div>
          {report?.until && (
            <p className="mt-1 text-xs text-dim">
              Covering {new Date(report.since).toLocaleDateString('en-US')} â†’ {new Date(report.until).toLocaleDateString('en-US')}
            </p>
          )}
        </div>
        <div className="no-print flex items-center gap-2">
          {whMsg && <span className="text-xs text-dim">{whMsg}</span>}
          <button
            onClick={sendWebhook}
            className="rounded-lg border border-border px-3 py-2 text-sm text-fg transition-colors hover:bg-surface-2"
            title="Send this report as JSON to the configured export webhook"
          >
            â†— Webhook
          </button>
          <button
            onClick={() => window.print()}
            className="rounded-lg border border-border px-3 py-2 text-sm text-fg transition-colors hover:bg-surface-2"
            title="Print or save as PDF"
          >
            â¬‡ PDF
          </button>
          <button
            onClick={download}
            className="rounded-lg border border-border px-3 py-2 text-sm text-fg transition-colors hover:bg-surface-2"
          >
            Markdown
          </button>
        </div>
      </header>

      {/* AI executive summary â€” generated on demand or on a schedule */}
      <section className="card-print mb-6 rounded-xl border border-border bg-surface p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-dim">AI executive summary</h2>
          <div className="no-print flex items-center gap-2">
            <select
              value={isCustom || customMode ? 'custom' : String(cfg.interval_hours)}
              onChange={(e) => onScheduleChange(e.target.value)}
              className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-fg outline-none focus:border-accent"
              title="Auto-generate the summary on a schedule"
            >
              {SCHEDULE_PRESETS.map((p) => (
                <option key={p.hours} value={p.hours}>{p.label}</option>
              ))}
              <option value="custom">Customâ€¦</option>
            </select>
            {(customMode || isCustom) && (
              <span className="flex items-center gap-1 text-xs text-muted">
                every
                <input
                  type="number"
                  min={1}
                  value={customMode ? customDays : String(Math.round(cfg.interval_hours / 24))}
                  onChange={(e) => setCustomDays(e.target.value)}
                  onBlur={() => customMode && customDays && saveSchedule(Number(customDays) * 24)}
                  onKeyDown={(e) => e.key === 'Enter' && customDays && saveSchedule(Number(customDays) * 24)}
                  className="w-14 rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-fg outline-none focus:border-accent"
                />
                days
              </span>
            )}
            {/* At a fixed hour â€” only meaningful for a daily-or-longer cadence. Without it the
                interval drifts: it fires N hours after the last run, whenever that happened. */}
            {cfg.interval_hours >= 24 && (
              <span className="flex items-center gap-1 text-xs text-muted">
                at
                <select
                  value={String(cfg.at_hour ?? -1)}
                  onChange={(e) => saveSchedule(cfg.interval_hours, Number(e.target.value))}
                  title={cfg.server_time ? `Server clock â€” now ${cfg.server_time} ${cfg.server_tz ?? ''}` : 'Server local time'}
                  className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-fg outline-none focus:border-accent"
                >
                  <option value="-1">any time</option>
                  {Array.from({ length: 24 }, (_, h) => (
                    <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>
                  ))}
                </select>
                {(cfg.at_hour ?? -1) >= 0 && cfg.server_time && (
                  <span className="text-dim">server now {cfg.server_time}{cfg.server_tz ? ` ${cfg.server_tz}` : ''}</span>
                )}
              </span>
            )}
            <button
              onClick={generate}
              disabled={genBusy}
              className="rounded-md border border-accent/40 px-2.5 py-1 text-xs text-accent transition-colors hover:bg-accent-soft disabled:opacity-50"
            >
              {genBusy ? 'Generatingâ€¦' : 'âœ¨ Generate now'}
            </button>
          </div>
        </div>

        {/* Custom AI prompt template */}
        <div className="no-print mb-3">
          <button onClick={() => setPromptOpen(!promptOpen)} className="text-xs text-dim hover:text-fg">
            {promptOpen ? 'â–¾' : 'â–¸'} Prompt template {cfg.summary_prompt ? '(custom)' : '(default)'}
          </button>
          {promptOpen && (
            <div className="mt-2 rounded-lg border border-border bg-surface p-3">
              <p className="mb-2 text-xs text-dim">
                The instruction sent to the model; the report data is appended automatically. Leave empty to use the built-in default.
              </p>
              <textarea
                value={promptText}
                onChange={(e) => setPromptText(e.target.value)}
                placeholder={cfg.default_prompt || 'Default promptâ€¦'}
                rows={5}
                className="w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-xs leading-relaxed text-fg outline-none focus:border-accent"
              />
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <button onClick={() => savePrompt(promptText)} disabled={promptBusy}
                  className="rounded-md border border-accent/40 px-2.5 py-1 text-xs text-accent hover:bg-accent-soft disabled:opacity-50">
                  {promptBusy ? 'Savingâ€¦' : 'Save prompt'}
                </button>
                <button onClick={() => savePrompt('')} disabled={promptBusy || !cfg.summary_prompt}
                  className="rounded-md border border-border px-2.5 py-1 text-xs text-fg hover:bg-surface-2 disabled:opacity-50">
                  Reset to default
                </button>
                {cfg.default_prompt && (
                  <button onClick={() => setPromptText(cfg.default_prompt || '')} className="text-xs text-dim hover:text-fg">
                    Load default text
                  </button>
                )}
                {promptMsg && <span className="text-xs text-dim">{promptMsg}</span>}
              </div>
            </div>
          )}
        </div>

        {summary?.summary ? (
          <>
            <p className="whitespace-pre-line text-sm leading-relaxed text-fg">{summary.summary}</p>
            <p className="mt-3 text-xs text-dim">
              {summary.model && <span>{summary.model} Â· </span>}
              {summary.period_hours ? `last ${summary.period_hours}h Â· ` : ''}
              {summary.generated_at ? new Date(summary.generated_at).toLocaleString('en-US') : ''}
            </p>
          </>
        ) : (
          <p className="text-sm text-dim">
            No AI summary yet. Click â€œGenerate nowâ€ â€” needs an LLM integration (e.g. a free local Ollama). Runs on
            demand, so thereâ€™s no per-alert API cost.
          </p>
        )}
        {genError && <p className="mt-2 text-sm text-rose-400">{genError}</p>}
      </section>

      {/* Scheduled delivery of the report to channels (Telegram/email) */}
      <section className="no-print card-print mb-6 rounded-xl border border-border bg-surface p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-xs font-semibold uppercase tracking-wider text-dim">Scheduled delivery</h2>
            <p className="mt-1 text-sm text-dim">
              Send this report to your channels (Telegram / email) on a schedule. Each report covers the
              period since the last one. Channels are configured via the server's environment variables.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={delivIsCustom || delivCustom ? 'custom' : String(delivery?.report_interval_hours ?? 0)}
              disabled={!delivery}
              onChange={(e) => onDeliveryChange(e.target.value)}
              className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-fg outline-none focus:border-accent disabled:opacity-50"
              title="Deliver the report on a schedule"
            >
              {SCHEDULE_PRESETS.map((p) => (
                <option key={p.hours} value={p.hours}>{p.label.replace('Auto: off', 'Delivery: off')}</option>
              ))}
              <option value="custom">Customâ€¦</option>
            </select>
            {(delivCustom || delivIsCustom) && (
              <span className="flex items-center gap-1 text-xs text-muted">
                every
                <input
                  type="number"
                  min={1}
                  value={delivCustom ? delivDays : String(Math.round((delivery?.report_interval_hours ?? 24) / 24))}
                  onChange={(e) => setDelivDays(e.target.value)}
                  onBlur={() => delivCustom && delivDays && saveDelivery(Number(delivDays) * 24)}
                  onKeyDown={(e) => e.key === 'Enter' && delivDays && saveDelivery(Number(delivDays) * 24)}
                  className="w-14 rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-fg outline-none focus:border-accent"
                />
                days
              </span>
            )}
          </div>
        </div>
        {delivMsg && <p className="mt-2 text-xs text-dim">{delivMsg}</p>}
      </section>

      <div className="no-print mb-6 flex gap-2">
        {WINDOWS.map((wnd) => (
          <button
            key={wnd.hours}
            onClick={() => setHours(wnd.hours)}
            className={`rounded-lg px-3 py-1.5 text-sm transition-colors ${
              hours === wnd.hours
                ? 'bg-accent-soft font-medium text-accent'
                : 'text-muted hover:bg-surface-2 hover:text-fg'
            }`}
          >
            {wnd.label}
          </button>
        ))}
        {loading && <span className="self-center text-xs text-dim">loadingâ€¦</span>}
      </div>

      {error && <p className="mb-4 text-sm text-rose-400">{error}</p>}

      <section className="mb-6 grid gap-3 sm:grid-cols-2">
        <StatCard label="Total events" value={report?.total_events ?? 'â€”'} />
        <StatCard label="Total alerts" value={report?.total_alerts ?? 'â€”'} accent="text-orange-300" />
      </section>

      <section className="grid gap-3 lg:grid-cols-2">
        <BarList title="Severity" rows={report?.by_severity ?? null} />
        <BarList title="LLM verdict" rows={report?.by_verdict ?? null} />
        <BarList title="Top source IP" rows={report?.top_source_ips ?? null} />
        <BarList title="Top agent (affected host)" rows={report?.top_agents ?? null} />
        <BarList title="Top rule" rows={report?.top_rules ?? null} />
        <BarList title="Top MITRE technique" rows={report?.top_techniques ?? null} />
      </section>
    </div>
  )
}
