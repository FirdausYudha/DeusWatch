import { useState, type FormEvent } from 'react'
import { login, type Me } from '../lib/api'

export default function Login({ onSuccess }: { onSuccess: (m: Me) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      onSuccess(await login(username, password))
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid h-screen place-items-center bg-slate-950 text-slate-200">
      <form onSubmit={submit} className="w-80 space-y-5 rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="grid h-9 w-9 place-items-center rounded-xl bg-indigo-500 text-lg font-bold text-white shadow-lg shadow-indigo-500/30">
            D
          </div>
          <div className="leading-tight">
            <div className="font-semibold tracking-tight text-white">DeusWatch</div>
            <div className="text-xs text-slate-500">Masuk untuk melanjutkan</div>
          </div>
        </div>

        <div className="space-y-3">
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username"
            autoFocus
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
        </div>

        {error && <p className="text-sm text-rose-400">{error}</p>}

        <button
          type="submit"
          disabled={busy || !username || !password}
          className="w-full rounded-lg bg-indigo-500 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400 disabled:opacity-50"
        >
          {busy ? 'Masuk…' : 'Masuk'}
        </button>
      </form>
    </div>
  )
}
