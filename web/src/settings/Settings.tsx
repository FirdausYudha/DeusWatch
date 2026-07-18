import { useEffect, useState, type FormEvent } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { fetchMe, setup2FA, enable2FA, disable2FA, changePassword, exportConfig, importConfig, fetchNotifyConfig, saveNotifyConfig, fetchStorageStatus, saveRetention, fetchUpdateCheck, fetchScoreConfig, saveScoreConfig, type NotifyConfig, type StorageStatus, type UpdateInfo, type ScoreConfig } from '../lib/api'
import DocLink from '../components/DocLink'

const SEVERITY_LABELS = ['Info', 'Low', 'Medium', 'High', 'Critical']

// ScoringWeightsPanel tunes the two IP scorers. Each group's four weights are shown as their
// NORMALIZED share (they're divided by their sum on the server), so the operator reasons in
// percentages. Changes apply live — the worker re-reads the weights on its next scoring tick.
function ScoringWeightsPanel() {
  const [cfg, setCfg] = useState<ScoreConfig | null>(null)
  const [defaults, setDefaults] = useState<ScoreConfig | null>(null)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    fetchScoreConfig().then((r) => { setCfg(r.config); setDefaults(r.defaults) }).catch((e) => setErr((e as Error).message))
  }, [])

  const save = async (next: ScoreConfig) => {
    setBusy(true); setErr(''); setMsg('')
    try { setCfg(await saveScoreConfig(next)); setMsg('Saved — applies on the next scoring run.') }
    catch (e) { setErr((e as Error).message) }
    finally { setBusy(false) }
  }

  if (!cfg) return null

  // A row of weights that renders each as its share of the group's total.
  const WeightRow = ({ label, keys, group }: { label: string; keys: [string, string][]; group: 'composite' | 'suspicion' }) => {
    const vals = cfg[group] as unknown as Record<string, number>
    const sum = keys.reduce((n, [k]) => n + (vals[k] || 0), 0) || 1
    return (
      <div className="mb-3">
        <div className="mb-1 text-xs font-medium text-slate-400">{label}</div>
        <div className="grid gap-2 sm:grid-cols-2">
          {keys.map(([k, name]) => (
            <label key={k} className="flex items-center justify-between gap-2 rounded-md border border-slate-800 bg-slate-900 px-2 py-1.5 text-xs">
              <span className="text-slate-400">{name}</span>
              <span className="flex items-center gap-2">
                <input
                  type="number" min={0} step={0.05} value={vals[k]}
                  onChange={(e) => setCfg({ ...cfg, [group]: { ...vals, [k]: Math.max(0, Number(e.target.value)) } } as ScoreConfig)}
                  className="w-16 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-right text-slate-200 outline-none focus:border-indigo-500"
                />
                <span className="w-9 text-right text-slate-500">{Math.round(((vals[k] || 0) / sum) * 100)}%</span>
              </span>
            </label>
          ))}
        </div>
      </div>
    )
  }

  return (
    <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between text-left">
        <div>
          <h2 className="text-sm font-medium text-slate-200">Threat-scoring weights</h2>
          <p className="mt-1 text-sm text-slate-500">
            Tune how the composite IP score and the suspicious-IP watchlist weigh their signals. Applies live.
          </p>
        </div>
        <span className="text-slate-500">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="mt-4">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">Composite threat score</h3>
          <WeightRow group="composite" label="Signals" keys={[['abuse', 'AbuseIPDB'], ['fired_times', 'Fired times'], ['otx', 'OTX pulses'], ['severity', 'Worst severity']]} />
          <label className="mb-3 flex items-center gap-2 text-xs text-slate-400">
            Lookback window
            <input
              type="number" min={1} step={1} value={Math.round(cfg.composite_window_secs / 60)}
              onChange={(e) => setCfg({ ...cfg, composite_window_secs: Math.max(60, Number(e.target.value) * 60) })}
              className="w-20 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-right text-slate-200 outline-none focus:border-indigo-500"
            />
            minutes
            <span className="text-slate-600">— how long an event keeps its score doughnut (longer = stays visible on older alerts)</span>
          </label>

          <h3 className="mb-2 mt-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Suspicious-IP watchlist</h3>
          <WeightRow group="suspicion" label="Signals" keys={[['fanout', 'Fan-out (distinct targets)'], ['fail_ratio', 'Failure ratio'], ['spread', 'Time spread'], ['volume', 'Volume']]} />
          <label className="mb-1 flex items-center gap-2 text-xs text-slate-400">
            Lookback window
            <input
              type="number" min={1} step={1} value={Math.round(cfg.suspicious_window_secs / 3600)}
              onChange={(e) => setCfg({ ...cfg, suspicious_window_secs: Math.max(3600, Number(e.target.value) * 3600) })}
              className="w-20 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-right text-slate-200 outline-none focus:border-indigo-500"
            />
            hours
            <span className="text-slate-600">— how far back low-and-slow behaviour is measured</span>
          </label>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button onClick={() => save(cfg)} disabled={busy}
              className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50">
              {busy ? 'Saving…' : 'Save weights'}
            </button>
            {defaults && (
              <button onClick={() => { setCfg(defaults); save(defaults) }} disabled={busy}
                className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 disabled:opacity-50">
                Reset to defaults
              </button>
            )}
            {msg && <span className="text-xs text-emerald-400">{msg}</span>}
            {err && <span className="text-xs text-rose-400">{err}</span>}
          </div>
          <p className="mt-2 text-[11px] text-slate-600">
            Weights are relative — each is divided by its group's total, so only the ratios matter. The caps
            (e.g. how many fired-times saturate to 100) keep their built-in values. See docs/suspicious-ips.md.
          </p>
        </div>
      )}
    </section>
  )
}

export default function Settings() {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [setup, setSetup] = useState<{ secret: string; otpauth_url: string } | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  // Change password.
  const [curPw, setCurPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [pwError, setPwError] = useState('')
  const [pwMsg, setPwMsg] = useState('')
  const [pwBusy, setPwBusy] = useState(false)

  // Config profile export/import.
  const [cfgErr, setCfgErr] = useState('')
  const [cfgMsg, setCfgMsg] = useState('')
  const doExport = async () => {
    setCfgErr(''); setCfgMsg('')
    try {
      const url = URL.createObjectURL(await exportConfig())
      const a = document.createElement('a')
      a.href = url
      a.download = 'deuswatch-config.json'
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setCfgErr((e as Error).message)
    }
  }
  const doImport = async (file: File) => {
    setCfgErr(''); setCfgMsg('')
    try {
      const applied = await importConfig(await file.text())
      const parts = Object.entries(applied).map(([k, v]) => `${v} ${k}`).join(', ')
      setCfgMsg(`Imported: ${parts || 'nothing'} · re-enter integration secrets afterwards.`)
    } catch (e) {
      setCfgErr((e as Error).message)
    }
  }

  // Alert notification threshold (Telegram/email channels are configured via env).
  const [notify, setNotify] = useState<NotifyConfig | null>(null)
  const [notifyMsg, setNotifyMsg] = useState('')
  const [notifyErr, setNotifyErr] = useState('')
  useEffect(() => {
    fetchNotifyConfig().then(setNotify).catch(() => {})
  }, [])
  const saveSeverity = async (sev: number) => {
    if (!notify) return
    setNotifyMsg(''); setNotifyErr('')
    const next = { ...notify, min_severity: sev }
    try {
      setNotify(await saveNotifyConfig(next))
      setNotifyMsg('Alert threshold saved.')
    } catch (e) {
      setNotifyErr((e as Error).message)
    }
  }

  // Log-storage lifecycle (TimescaleDB retention + compression).
  const [storage, setStorage] = useState<StorageStatus | null>(null)
  const [retDays, setRetDays] = useState('')
  const [cmpDays, setCmpDays] = useState('')
  const [stMsg, setStMsg] = useState('')
  const [stErr, setStErr] = useState('')
  const [stBusy, setStBusy] = useState(false)
  useEffect(() => {
    fetchStorageStatus()
      .then((s) => {
        setStorage(s)
        setRetDays(String(s.retention_days ?? 30))
        setCmpDays(String(s.compression_days ?? 7))
      })
      .catch(() => {})
  }, [])
  const saveLifecycle = async (e: FormEvent) => {
    e.preventDefault()
    setStMsg(''); setStErr(''); setStBusy(true)
    try {
      const s = await saveRetention(Number(retDays), Number(cmpDays))
      setStorage(s)
      setStMsg('Storage lifecycle updated.')
    } catch (err) {
      setStErr((err as Error).message)
    } finally {
      setStBusy(false)
    }
  }


  // Software update check (read-only).
  const [upd, setUpd] = useState<UpdateInfo | null>(null)
  const [updBusy, setUpdBusy] = useState(false)
  const [updErr, setUpdErr] = useState('')
  const checkUpdate = async () => {
    setUpdBusy(true); setUpdErr('')
    try {
      setUpd(await fetchUpdateCheck())
    } catch (e) {
      setUpdErr((e as Error).message)
    } finally {
      setUpdBusy(false)
    }
  }

  const submitPassword = async (e: FormEvent) => {
    e.preventDefault()
    setPwError('')
    setPwMsg('')
    if (newPw !== confirmPw) {
      setPwError('New password confirmation does not match')
      return
    }
    setPwBusy(true)
    try {
      await changePassword(curPw, newPw)
      setCurPw('')
      setNewPw('')
      setConfirmPw('')
      setPwMsg('Password changed successfully.')
    } catch (err) {
      setPwError((err as Error).message)
    } finally {
      setPwBusy(false)
    }
  }

  const refresh = () => {
    fetchMe()
      .then((m) => setEnabled(!!m.twofa_enabled))
      .catch(() => {})
  }
  useEffect(refresh, [])

  const startSetup = async () => {
    setError('')
    setMsg('')
    try {
      setSetup(await setup2FA())
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const confirmEnable = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await enable2FA(setup!.secret, code)
      setSetup(null)
      setCode('')
      setMsg('2FA enabled successfully.')
      refresh()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const doDisable = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await disable2FA(code)
      setCode('')
      setMsg('2FA disabled.')
      refresh()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-3xl px-8 py-8">
      <header className="mb-8 flex items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Settings</h1>
          <p className="mt-1 text-sm text-slate-500">Account security</p>
        </div>
        <DocLink file="production.md" label="Production hardening" className="shrink-0" />
      </header>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-medium text-slate-200">Two-Factor Authentication (TOTP)</h2>
          <span
            className={`rounded px-2 py-0.5 text-xs font-medium ${
              enabled ? 'bg-emerald-500/15 text-emerald-300' : 'bg-slate-700/40 text-slate-400'
            }`}
          >
            {enabled === null ? '…' : enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        {enabled === false && !setup && (
          <button
            onClick={startSetup}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400"
          >
            Enable 2FA
          </button>
        )}

        {enabled === false && setup && (
          <form onSubmit={confirmEnable} className="space-y-3">
            <p className="text-sm text-slate-400">
              Scan this QR with your authenticator app (Google Authenticator, Authy, 1Password…),
              then enter the 6-digit code:
            </p>
            <div className="flex flex-wrap items-start gap-4">
              <div className="w-fit rounded-lg bg-white p-3">
                <QRCodeSVG value={setup.otpauth_url} size={160} level="M" />
              </div>
              <div className="rounded-lg border border-slate-700 bg-slate-800 p-3 text-xs">
                <div className="text-slate-500">Can't scan? Enter this secret manually:</div>
                <div className="mt-1 select-all break-all font-mono text-slate-200">{setup.secret}</div>
                <div className="mt-2 text-slate-500">otpauth URL</div>
                <div className="select-all break-all font-mono text-slate-300">{setup.otpauth_url}</div>
              </div>
            </div>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="6-digit code"
              inputMode="numeric"
              className="w-44 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm tracking-widest outline-none focus:border-indigo-500"
            />
            <button
              type="submit"
              disabled={busy || !code}
              className="ml-2 rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50"
            >
              Confirm
            </button>
          </form>
        )}

        {enabled === true && (
          <form onSubmit={doDisable} className="space-y-3">
            <p className="text-sm text-slate-400">Enter your current 2FA code to disable it:</p>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="6-digit code"
              inputMode="numeric"
              className="w-44 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm tracking-widest outline-none focus:border-indigo-500"
            />
            <button
              type="submit"
              disabled={busy || !code}
              className="ml-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-sm font-medium text-rose-300 hover:bg-rose-500/20 disabled:opacity-50"
            >
              Disable
            </button>
          </form>
        )}

        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
        {msg && <p className="mt-3 text-sm text-emerald-400">{msg}</p>}
      </section>

      <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-medium text-slate-200">Alert notifications</h2>
          <DocLink file="notifications.md" className="shrink-0" />
        </div>
        <p className="mb-4 mt-1 text-sm text-slate-500">
          Send an alert to your channels (Telegram / email) when an event's severity is at or above
          this level. Channels are configured via the server's environment variables.
        </p>
        <label className="flex items-center gap-3 text-sm text-slate-300">
          Notify at or above
          <select
            value={notify?.min_severity ?? 2}
            disabled={!notify}
            onChange={(e) => saveSeverity(Number(e.target.value))}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500 disabled:opacity-50"
          >
            {SEVERITY_LABELS.map((lbl, i) => (
              <option key={i} value={i}>
                {lbl}
              </option>
            ))}
          </select>
        </label>
        {notifyErr && <p className="mt-3 text-sm text-rose-400">{notifyErr}</p>}
        {notifyMsg && <p className="mt-3 text-sm text-emerald-400">{notifyMsg}</p>}
      </section>

      <ScoringWeightsPanel />

      <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-medium text-slate-200">Log storage lifecycle</h2>
          <DocLink file="storage.md" className="shrink-0" />
        </div>
        <p className="mb-4 mt-1 text-sm text-slate-500">
          How long logs are kept (TimescaleDB retention) and when they get compressed - the
          relational equivalent of an ILM policy. Data older than the retention window is
          dropped automatically. Compression must happen before retention.
          {storage && <span className="ml-1 text-slate-600">Current DB size: {storage.db_size_pretty}.</span>}
        </p>
        <form onSubmit={saveLifecycle} className="flex flex-wrap items-end gap-3">
          <label className="text-sm text-slate-300">
            <span className="mb-1 block text-xs text-slate-400">Keep logs for (days)</span>
            <input type="number" min={1} max={3650} value={retDays} onChange={(e) => setRetDays(e.target.value)}
              className="w-32 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500" />
          </label>
          <label className="text-sm text-slate-300">
            <span className="mb-1 block text-xs text-slate-400">Compress after (days)</span>
            <input type="number" min={0} value={cmpDays} onChange={(e) => setCmpDays(e.target.value)}
              className="w-32 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500" />
          </label>
          <button type="submit" disabled={stBusy || !retDays}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400 disabled:opacity-50">
            {stBusy ? 'Saving…' : 'Save lifecycle'}
          </button>
        </form>
        {stErr && <p className="mt-3 text-sm text-rose-400">{stErr}</p>}
        {stMsg && <p className="mt-3 text-sm text-emerald-400">{stMsg}</p>}
      </section>

      <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-medium text-slate-200">Software updates</h2>
        <p className="mb-4 mt-1 text-sm text-slate-500">
          Check whether a newer DeusWatch build is available on GitHub. Updates run on the host
          with <code className="rounded bg-slate-800 px-1 py-0.5 text-xs">./scripts/update.sh</code> —
          the web app never controls Docker, which keeps the attack surface small.
        </p>
        <button onClick={checkUpdate} disabled={updBusy}
          className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 transition-colors hover:bg-slate-800 disabled:opacity-50">
          {updBusy ? 'Checking…' : 'Check for update'}
        </button>
        {updErr && <p className="mt-3 text-sm text-rose-400">{updErr}</p>}
        {upd && (upd.update_available ? (
          <div className="mt-3 text-sm text-amber-300">
            Update available — running <span className="font-mono">{upd.current}</span>, latest <span className="font-mono">{upd.latest}</span>
            {upd.latest_date && <span className="text-slate-500"> ({new Date(upd.latest_date).toLocaleString('en-US')})</span>}.
            <div className="mt-1 text-slate-400">On the host run: <code className="rounded bg-slate-800 px-1 py-0.5 text-xs">{upd.update_command}</code></div>
          </div>
        ) : (
          <p className="mt-3 text-sm text-emerald-400">
            {upd.current === 'dev'
              ? `Latest on GitHub: ${upd.latest}. (This build has no version stamp — deploy via ./scripts/update.sh to enable comparison.)`
              : `Up to date (${upd.current}).`}
          </p>
        ))}
      </section>

      <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-4 text-sm font-medium text-slate-200">Change password</h2>
        <form onSubmit={submitPassword} className="space-y-3">
          <input
            type="password"
            value={curPw}
            onChange={(e) => setCurPw(e.target.value)}
            placeholder="Current password"
            autoComplete="current-password"
            className="block w-72 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          <input
            type="password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            placeholder="New password (min 8)"
            autoComplete="new-password"
            className="block w-72 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          <input
            type="password"
            value={confirmPw}
            onChange={(e) => setConfirmPw(e.target.value)}
            placeholder="Confirm new password"
            autoComplete="new-password"
            className="block w-72 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          <button
            type="submit"
            disabled={pwBusy || !curPw || newPw.length < 8 || !confirmPw}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400 disabled:opacity-50"
          >
            {pwBusy ? 'Saving…' : 'Change password'}
          </button>
        </form>
        {pwError && <p className="mt-3 text-sm text-rose-400">{pwError}</p>}
        {pwMsg && <p className="mt-3 text-sm text-emerald-400">{pwMsg}</p>}
      </section>

      <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-medium text-slate-200">Config profile</h2>
        <p className="mb-4 mt-1 text-sm text-slate-500">
          Export this server's settings — detection rules, ban policy, IP whitelist, the AI-report
          schedule, alert/notification settings (severity threshold + report delivery schedule), and
          integrations — as JSON to clone onto another DeusWatch server. Secrets (API keys /
          passwords) are not included; re-enter them after import.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={doExport}
            className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 transition-colors hover:bg-slate-800"
          >
            ⬇ Export config
          </button>
          <label className="cursor-pointer rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 transition-colors hover:bg-slate-800">
            ⬆ Import config
            <input
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={(e) => e.target.files?.[0] && doImport(e.target.files[0])}
            />
          </label>
        </div>
        {cfgErr && <p className="mt-3 text-sm text-rose-400">{cfgErr}</p>}
        {cfgMsg && <p className="mt-3 text-sm text-emerald-400">{cfgMsg}</p>}
      </section>
    </div>
  )
}
