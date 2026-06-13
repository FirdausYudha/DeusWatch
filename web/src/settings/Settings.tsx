import { useEffect, useState, type FormEvent } from 'react'
import { fetchMe, setup2FA, enable2FA, disable2FA } from '../lib/api'

export default function Settings() {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [setup, setSetup] = useState<{ secret: string; otpauth_url: string } | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

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
      setMsg('2FA berhasil diaktifkan.')
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
      setMsg('2FA dinonaktifkan.')
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
        <p className="mt-1 text-sm text-slate-500">Keamanan akun</p>
      </header>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-medium text-slate-200">Autentikasi Dua Faktor (TOTP)</h2>
          <span
            className={`rounded px-2 py-0.5 text-xs font-medium ${
              enabled ? 'bg-emerald-500/15 text-emerald-300' : 'bg-slate-700/40 text-slate-400'
            }`}
          >
            {enabled === null ? '…' : enabled ? 'Aktif' : 'Nonaktif'}
          </span>
        </div>

        {enabled === false && !setup && (
          <button
            onClick={startSetup}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400"
          >
            Aktifkan 2FA
          </button>
        )}

        {enabled === false && setup && (
          <form onSubmit={confirmEnable} className="space-y-3">
            <p className="text-sm text-slate-400">
              Tambahkan ke aplikasi authenticator (scan / tempel URL), lalu masukkan kode 6 digit:
            </p>
            <div className="rounded-lg border border-slate-700 bg-slate-800 p-3 text-xs">
              <div className="text-slate-500">Secret</div>
              <div className="select-all break-all font-mono text-slate-200">{setup.secret}</div>
              <div className="mt-2 text-slate-500">otpauth URL</div>
              <div className="select-all break-all font-mono text-slate-300">{setup.otpauth_url}</div>
            </div>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Kode 6 digit"
              inputMode="numeric"
              className="w-44 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm tracking-widest outline-none focus:border-indigo-500"
            />
            <button
              type="submit"
              disabled={busy || !code}
              className="ml-2 rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50"
            >
              Konfirmasi
            </button>
          </form>
        )}

        {enabled === true && (
          <form onSubmit={doDisable} className="space-y-3">
            <p className="text-sm text-slate-400">Masukkan kode 2FA saat ini untuk menonaktifkan:</p>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Kode 6 digit"
              inputMode="numeric"
              className="w-44 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm tracking-widest outline-none focus:border-indigo-500"
            />
            <button
              type="submit"
              disabled={busy || !code}
              className="ml-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-sm font-medium text-rose-300 hover:bg-rose-500/20 disabled:opacity-50"
            >
              Nonaktifkan
            </button>
          </form>
        )}

        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
        {msg && <p className="mt-3 text-sm text-emerald-400">{msg}</p>}
      </section>
    </div>
  )
}
