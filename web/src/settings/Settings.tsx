import { useEffect, useState, type FormEvent } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { fetchMe, setup2FA, enable2FA, disable2FA, changePassword, exportConfig, importConfig, fetchNotifyConfig, saveNotifyConfig, type NotifyConfig } from '../lib/api'

const SEVERITY_LABELS = ['Info', 'Low', 'Medium', 'High', 'Critical']

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
      <header className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight text-white">Settings</h1>
        <p className="mt-1 text-sm text-slate-500">Account security</p>
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
        <h2 className="text-sm font-medium text-slate-200">Alert notifications</h2>
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
