import { useEffect, useState, type FormEvent } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { fetchMe, setup2FA, enable2FA, disable2FA, changePassword, exportConfig, importConfig, fetchNotifyConfig, saveNotifyConfig, fetchStorageStatus, saveRetention, fetchUpdateCheck, fetchScoreConfig, saveScoreConfig, can, fetchSubscriptions, createSubscription, toggleSubscription, deleteSubscription, type Me, type NotifyConfig, type StorageStatus, type UpdateInfo, type ScoreConfig, type Subscription } from '../lib/api'
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
        <div className="mb-1 text-[11px] font-medium text-muted">{label}</div>
        <div className="grid gap-2 sm:grid-cols-2">
          {keys.map(([k, name]) => (
            <label key={k} className="flex items-center justify-between gap-2 rounded-md border border-border bg-surface px-2 py-1.5 text-xs">
              <span className="text-muted">{name}</span>
              <span className="flex items-center gap-2">
                <input
                  type="number" min={0} step={0.05} value={vals[k]}
                  onChange={(e) => setCfg({ ...cfg, [group]: { ...vals, [k]: Math.max(0, Number(e.target.value)) } } as ScoreConfig)}
                  className="w-16 rounded border border-border bg-surface-2 px-2 py-1 text-right text-fg outline-none focus:border-accent"
                />
                <span className="w-9 text-right text-dim">{Math.round(((vals[k] || 0) / sum) * 100)}%</span>
              </span>
            </label>
          ))}
        </div>
      </div>
    )
  }

  return (
    <section className="mt-6 rounded-[12px] border border-border bg-surface p-5">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between text-left">
        <div>
          <h2 className="text-[12.5px] font-medium text-fg">Threat-scoring weights</h2>
          <p className="mt-0.5 text-[12px] text-muted">
            Tune how the composite IP score and the suspicious-IP watchlist weigh their signals. Applies live.
          </p>
        </div>
        <span className="text-dim">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="mt-4">
          <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-dim">Composite threat score</h3>
          <WeightRow group="composite" label="Signals" keys={[['abuse', 'AbuseIPDB'], ['fired_times', 'Fired times'], ['otx', 'OTX pulses'], ['severity', 'Worst severity'], ['anomaly', 'Anomaly (ML)'], ['fanout', 'Cross-agent fan-out']]} />
          <label className="mb-3 flex items-center gap-2 text-[11px] text-muted">
            Lookback window
            <input
              type="number" min={1} step={1} value={Math.round(cfg.composite_window_secs / 60)}
              onChange={(e) => setCfg({ ...cfg, composite_window_secs: Math.max(60, Number(e.target.value) * 60) })}
              className="w-20 rounded border border-border bg-surface-2 px-2 py-1 text-right text-fg outline-none focus:border-accent"
            />
            minutes
            <span className="text-dim">— how long an event keeps its score doughnut (longer = stays visible on older alerts)</span>
          </label>

          <h3 className="mb-2 mt-4 text-[11px] font-semibold uppercase tracking-wider text-dim">Suspicious-IP watchlist</h3>
          <WeightRow group="suspicion" label="Signals" keys={[['fanout', 'Fan-out (distinct targets)'], ['fail_ratio', 'Failure ratio'], ['spread', 'Time spread'], ['volume', 'Volume']]} />
          <label className="mb-1 flex items-center gap-2 text-[11px] text-muted">
            Lookback window
            <input
              type="number" min={1} step={1} value={Math.round(cfg.suspicious_window_secs / 3600)}
              onChange={(e) => setCfg({ ...cfg, suspicious_window_secs: Math.max(3600, Number(e.target.value) * 3600) })}
              className="w-20 rounded border border-border bg-surface-2 px-2 py-1 text-right text-fg outline-none focus:border-accent"
            />
            hours
            <span className="text-dim">— how far back low-and-slow behaviour is measured</span>
          </label>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button onClick={() => save(cfg)} disabled={busy}
              className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-50">
              {busy ? 'Saving…' : 'Save weights'}
            </button>
            {defaults && (
              <button onClick={() => { setCfg(defaults); save(defaults) }} disabled={busy}
                className="rounded-[8px] border border-border px-4 py-2 text-[12.5px] text-fg hover:bg-surface-2 disabled:opacity-50">
                Reset to defaults
              </button>
            )}
            {msg && <span className="text-[11px] text-emerald-400">{msg}</span>}
            {err && <span className="text-[11px] text-rose-400">{err}</span>}
          </div>
          <p className="mt-2 text-[11px] text-dim">
            Weights are relative — each is divided by its group's total, so only the ratios matter. The caps
            (e.g. how many fired-times saturate to 100) keep their built-in values. See docs/suspicious-ips.md.
          </p>
        </div>
      )}
    </section>
  )
}

// SubscriptionsPanel manages API keys for the sellable rich-log subscription product. Admin-only
// (manage_integrations); hidden for everyone else. A new key's plaintext is shown ONCE.
function SubscriptionsPanel() {
  const [me, setMe] = useState<Me | null>(null)
  const [subs, setSubs] = useState<Subscription[]>([])
  const [name, setName] = useState('')
  const [wantEvents, setWantEvents] = useState(true)
  const [wantIndicators, setWantIndicators] = useState(false)
  const [minSev, setMinSev] = useState(0)
  const [newKey, setNewKey] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(false)

  const load = () => fetchSubscriptions().then(setSubs).catch((e) => setErr((e as Error).message))
  useEffect(() => {
    fetchMe().then(setMe).catch(() => {})
  }, [])
  useEffect(() => {
    if (can(me, 'manage_integrations')) load()
  }, [me])

  if (!can(me, 'manage_integrations')) return null

  const create = async () => {
    setErr(''); setNewKey(''); setBusy(true)
    try {
      const scopes = [wantEvents && 'events', wantIndicators && 'indicators'].filter(Boolean) as string[]
      const res = await createSubscription(name.trim(), scopes.length ? scopes : ['events'], minSev)
      setNewKey(res.api_key)
      setName('')
      load()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  const toggle = async (s: Subscription) => {
    setErr('')
    try { await toggleSubscription(s.id, !s.enabled); load() } catch (e) { setErr((e as Error).message) }
  }
  const remove = async (s: Subscription) => {
    if (!confirm(`Revoke subscription "${s.name}"? Its API key stops working immediately.`)) return
    setErr('')
    try { await deleteSubscription(s.id); load() } catch (e) { setErr((e as Error).message) }
  }

  return (
    <section className="mt-6 rounded-[12px] border border-border bg-surface p-5">
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center justify-between gap-3 text-left">
        <h2 className="text-[12.5px] font-medium text-fg">Log subscriptions (API)</h2>
        <div className="flex items-center gap-3">
          <DocLink file="subscription-api.md" className="shrink-0" />
          <span className="text-dim">{open ? '▾' : '▸'}</span>
        </div>
      </button>
      <p className="mb-4 mt-0.5 text-[12px] text-muted">
        Issue per-subscriber API keys so external customers can PULL enriched events / threat
        indicators — the sellable rich-log product. Each key is shown once; usage is tracked.
      </p>

      {open && (
        <>
          <div className="mb-4 flex flex-wrap items-end gap-3 rounded-[8px] border border-border bg-surface p-3">
            <label className="text-[12.5px] text-fg">
              <span className="mb-1 block text-[11px] text-muted">Subscriber name</span>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme SOC"
                className="w-48 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent" />
            </label>
            <label className="text-[12.5px] text-fg">
              <span className="mb-1 block text-[11px] text-muted">Min severity</span>
              <select value={minSev} onChange={(e) => setMinSev(Number(e.target.value))}
                className="rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent">
                {SEVERITY_LABELS.map((l, i) => <option key={i} value={i}>{i} · {l}</option>)}
              </select>
            </label>
            <div className="text-[12.5px] text-fg">
              <span className="mb-1 block text-[11px] text-muted">Scopes</span>
              <div className="flex gap-3 py-2">
                <label className="flex items-center gap-1.5 text-xs">
                  <input type="checkbox" checked={wantEvents} onChange={(e) => setWantEvents(e.target.checked)} /> events
                </label>
                <label className="flex items-center gap-1.5 text-xs">
                  <input type="checkbox" checked={wantIndicators} onChange={(e) => setWantIndicators(e.target.checked)} /> indicators
                </label>
              </div>
            </div>
            <button onClick={create} disabled={busy || !name.trim()}
              className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white transition-colors hover:opacity-90 disabled:opacity-50">
              {busy ? 'Creating…' : 'Create key'}
            </button>
          </div>

          {newKey && (
            <div className="mb-4 rounded-[8px] border border-emerald-900/50 bg-emerald-500/5 p-3">
              <p className="text-[11px] text-emerald-200">New API key — copy it now, it is shown only once:</p>
              <code className="mt-1 block break-all rounded bg-bg px-2 py-1 font-mono text-[11px] text-emerald-300">{newKey}</code>
            </div>
          )}

          {subs.length > 0 ? (
            <table className="w-full text-left text-sm">
              <thead className="text-[11px] uppercase tracking-wider text-dim">
                <tr>
                  <th className="py-2 font-medium">Name</th>
                  <th className="py-2 font-medium">Scopes</th>
                  <th className="py-2 font-medium">Min sev</th>
                  <th className="py-2 font-medium">Requests</th>
                  <th className="py-2 font-medium">Last used</th>
                  <th className="py-2 font-medium">Status</th>
                  <th className="py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {subs.map((s) => (
                  <tr key={s.id}>
                    <td className="py-2 text-fg">{s.name}</td>
                    <td className="py-2 text-[11px] text-muted">{s.scopes.join(', ')}</td>
                    <td className="py-2 text-muted">{s.min_severity}</td>
                    <td className="py-2 text-muted">{s.request_count}</td>
                    <td className="py-2 text-[11px] text-dim">{s.last_used_at ? new Date(s.last_used_at).toLocaleString() : '—'}</td>
                    <td className="py-2">
                      <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${s.enabled ? 'bg-emerald-500/15 text-emerald-300' : 'bg-surface-2 text-muted'}`}>
                        {s.enabled ? 'enabled' : 'disabled'}
                      </span>
                    </td>
                    <td className="py-2 text-right">
                      <div className="flex justify-end gap-2">
                        <button onClick={() => toggle(s)} className="rounded-md border border-border px-2 py-1 text-[11px] text-fg hover:bg-surface-2">
                          {s.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button onClick={() => remove(s)} className="rounded-md border border-rose-500/40 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/10">
                          Revoke
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-[12.5px] text-dim">No subscribers yet.</p>
          )}
          {err && <p className="mt-3 text-[12.5px] text-rose-400">{err}</p>}
        </>
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
    <div className="mx-auto max-w-4xl px-6 py-5">
      <header className="mb-5 flex flex-wrap items-end justify-between gap-3 gap-3">
        <div>
          <h1 className="text-[16px] font-semibold tracking-tight text-fg">Settings</h1>
          <p className="mt-0.5 text-[12px] text-muted">Account security</p>
        </div>
        <DocLink file="production.md" label="Production hardening" className="shrink-0" />
      </header>

      <section className="rounded-[12px] border border-border bg-surface p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-[12.5px] font-medium text-fg">Two-Factor Authentication (TOTP)</h2>
          <span
            className={`rounded px-2 py-0.5 text-[11px] font-medium ${
              enabled ? 'bg-emerald-500/15 text-emerald-300' : 'bg-surface-2 text-muted'
            }`}
          >
            {enabled === null ? '…' : enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        {enabled === false && !setup && (
          <button
            onClick={startSetup}
            className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white transition-colors hover:opacity-90"
          >
            Enable 2FA
          </button>
        )}

        {enabled === false && setup && (
          <form onSubmit={confirmEnable} className="space-y-3">
            <p className="text-[12.5px] text-muted">
              Scan this QR with your authenticator app (Google Authenticator, Authy, 1Password…),
              then enter the 6-digit code:
            </p>
            <div className="flex flex-wrap items-start gap-4">
              <div className="w-fit rounded-[8px] bg-white p-3">
                <QRCodeSVG value={setup.otpauth_url} size={160} level="M" />
              </div>
              <div className="rounded-[8px] border border-border bg-surface-2 p-3 text-xs">
                <div className="text-dim">Can't scan? Enter this secret manually:</div>
                <div className="mt-1 select-all break-all font-mono text-fg">{setup.secret}</div>
                <div className="mt-2 text-dim">otpauth URL</div>
                <div className="select-all break-all font-mono text-fg">{setup.otpauth_url}</div>
              </div>
            </div>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="6-digit code"
              inputMode="numeric"
              className="w-44 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] tracking-widest outline-none focus:border-accent"
            />
            <button
              type="submit"
              disabled={busy || !code}
              className="ml-2 rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-50"
            >
              Confirm
            </button>
          </form>
        )}

        {enabled === true && (
          <form onSubmit={doDisable} className="space-y-3">
            <p className="text-[12.5px] text-muted">Enter your current 2FA code to disable it:</p>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="6-digit code"
              inputMode="numeric"
              className="w-44 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] tracking-widest outline-none focus:border-accent"
            />
            <button
              type="submit"
              disabled={busy || !code}
              className="ml-2 rounded-[8px] border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-[12.5px] font-medium text-rose-300 hover:bg-rose-500/20 disabled:opacity-50"
            >
              Disable
            </button>
          </form>
        )}

        {error && <p className="mt-3 text-[12.5px] text-rose-400">{error}</p>}
        {msg && <p className="mt-3 text-[12.5px] text-emerald-400">{msg}</p>}
      </section>

      <section className="mt-6 rounded-[12px] border border-border bg-surface p-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-[12.5px] font-medium text-fg">Alert notifications</h2>
          <DocLink file="notifications.md" className="shrink-0" />
        </div>
        <p className="mb-4 mt-0.5 text-[12px] text-muted">
          Send an alert to your channels (Telegram / email) when an event's severity is at or above
          this level. Channels are configured via the server's environment variables.
        </p>
        <label className="flex items-center gap-3 text-[12.5px] text-fg">
          Notify at or above
          <select
            value={notify?.min_severity ?? 2}
            disabled={!notify}
            onChange={(e) => saveSeverity(Number(e.target.value))}
            className="rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent disabled:opacity-50"
          >
            {SEVERITY_LABELS.map((lbl, i) => (
              <option key={i} value={i}>
                {lbl}
              </option>
            ))}
          </select>
        </label>
        {notifyErr && <p className="mt-3 text-[12.5px] text-rose-400">{notifyErr}</p>}
        {notifyMsg && <p className="mt-3 text-[12.5px] text-emerald-400">{notifyMsg}</p>}
      </section>

      <ScoringWeightsPanel />

      <SubscriptionsPanel />

      <section className="mt-6 rounded-[12px] border border-border bg-surface p-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-[12.5px] font-medium text-fg">Log storage lifecycle</h2>
          <DocLink file="storage.md" className="shrink-0" />
        </div>
        <p className="mb-4 mt-0.5 text-[12px] text-muted">
          How long logs are kept (TimescaleDB retention) and when they get compressed - the
          relational equivalent of an ILM policy. Data older than the retention window is
          dropped automatically. Compression must happen before retention.
          {storage && <span className="ml-1 text-dim">Current DB size: {storage.db_size_pretty}.</span>}
        </p>
        <form onSubmit={saveLifecycle} className="flex flex-wrap items-end gap-3">
          <label className="text-[12.5px] text-fg">
            <span className="mb-1 block text-[11px] text-muted">Keep logs for (days)</span>
            <input type="number" min={1} max={3650} value={retDays} onChange={(e) => setRetDays(e.target.value)}
              className="w-32 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent" />
          </label>
          <label className="text-[12.5px] text-fg">
            <span className="mb-1 block text-[11px] text-muted">Compress after (days)</span>
            <input type="number" min={0} value={cmpDays} onChange={(e) => setCmpDays(e.target.value)}
              className="w-32 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent" />
          </label>
          <button type="submit" disabled={stBusy || !retDays}
            className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white transition-colors hover:opacity-90 disabled:opacity-50">
            {stBusy ? 'Saving…' : 'Save lifecycle'}
          </button>
        </form>
        {stErr && <p className="mt-3 text-[12.5px] text-rose-400">{stErr}</p>}
        {stMsg && <p className="mt-3 text-[12.5px] text-emerald-400">{stMsg}</p>}
      </section>

      <section className="mt-6 rounded-[12px] border border-border bg-surface p-5">
        <h2 className="text-[12.5px] font-medium text-fg">Software updates</h2>
        <p className="mb-4 mt-0.5 text-[12px] text-muted">
          Check whether a newer DeusWatch build is available on GitHub. Updates run on the host
          with <code className="rounded bg-surface-2 px-1 py-0.5 text-xs">./scripts/update.sh</code> —
          the web app never controls Docker, which keeps the attack surface small.
        </p>
        <button onClick={checkUpdate} disabled={updBusy}
          className="rounded-[8px] border border-border px-3 py-2 text-[12.5px] text-fg transition-colors hover:bg-surface-2 disabled:opacity-50">
          {updBusy ? 'Checking…' : 'Check for update'}
        </button>
        {updErr && <p className="mt-3 text-[12.5px] text-rose-400">{updErr}</p>}
        {upd && (upd.update_available ? (
          <div className="mt-3 text-[12.5px] text-amber-300">
            Update available — running <span className="font-mono">{upd.current}</span>, latest <span className="font-mono">{upd.latest}</span>
            {upd.latest_date && <span className="text-dim"> ({new Date(upd.latest_date).toLocaleString('en-US')})</span>}.
            <div className="mt-1 text-muted">On the host run: <code className="rounded bg-surface-2 px-1 py-0.5 text-xs">{upd.update_command}</code></div>
          </div>
        ) : (
          <p className="mt-3 text-[12.5px] text-emerald-400">
            {upd.current === 'dev'
              ? `Latest on GitHub: ${upd.latest}. (This build has no version stamp — deploy via ./scripts/update.sh to enable comparison.)`
              : `Up to date (${upd.current}).`}
          </p>
        ))}
      </section>

      <section className="mt-6 rounded-[12px] border border-border bg-surface p-5">
        <h2 className="mb-4 text-[12.5px] font-medium text-fg">Change password</h2>
        <form onSubmit={submitPassword} className="space-y-3">
          <input
            type="password"
            value={curPw}
            onChange={(e) => setCurPw(e.target.value)}
            placeholder="Current password"
            autoComplete="current-password"
            className="block w-72 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent"
          />
          <input
            type="password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            placeholder="New password (min 8)"
            autoComplete="new-password"
            className="block w-72 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent"
          />
          <input
            type="password"
            value={confirmPw}
            onChange={(e) => setConfirmPw(e.target.value)}
            placeholder="Confirm new password"
            autoComplete="new-password"
            className="block w-72 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent"
          />
          <button
            type="submit"
            disabled={pwBusy || !curPw || newPw.length < 8 || !confirmPw}
            className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white transition-colors hover:opacity-90 disabled:opacity-50"
          >
            {pwBusy ? 'Saving…' : 'Change password'}
          </button>
        </form>
        {pwError && <p className="mt-3 text-[12.5px] text-rose-400">{pwError}</p>}
        {pwMsg && <p className="mt-3 text-[12.5px] text-emerald-400">{pwMsg}</p>}
      </section>

      <section className="mt-6 rounded-[12px] border border-border bg-surface p-5">
        <h2 className="text-[12.5px] font-medium text-fg">Config profile</h2>
        <p className="mb-4 mt-0.5 text-[12px] text-muted">
          Export this server's settings — detection rules, ban policy, IP whitelist, the AI-report
          schedule, alert/notification settings (severity threshold + report delivery schedule), and
          integrations — as JSON to clone onto another DeusWatch server. Secrets (API keys /
          passwords) are not included; re-enter them after import.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={doExport}
            className="rounded-[8px] border border-border px-3 py-2 text-[12.5px] text-fg transition-colors hover:bg-surface-2"
          >
            ⬇ Export config
          </button>
          <label className="cursor-pointer rounded-[8px] border border-border px-3 py-2 text-[12.5px] text-fg transition-colors hover:bg-surface-2">
            ⬆ Import config
            <input
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={(e) => e.target.files?.[0] && doImport(e.target.files[0])}
            />
          </label>
        </div>
        {cfgErr && <p className="mt-3 text-[12.5px] text-rose-400">{cfgErr}</p>}
        {cfgMsg && <p className="mt-3 text-[12.5px] text-emerald-400">{cfgMsg}</p>}
      </section>
    </div>
  )
}
