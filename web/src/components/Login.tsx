import { useEffect, useState, type FormEvent } from 'react'
import { login, register, fetchAuthConfig, TwoFactorRequired, type Me } from '../lib/api'

type Mode = 'login' | 'register'

export default function Login({ onSuccess }: { onSuccess: (m: Me) => void }) {
  const [mode, setMode] = useState<Mode>('login')
  const [canRegister, setCanRegister] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [totp, setTotp] = useState('')
  const [need2fa, setNeed2fa] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    fetchAuthConfig().then((c) => setCanRegister(c.registration_enabled))
  }, [])

  const switchMode = (m: Mode) => {
    setMode(m)
    setError('')
    setNeed2fa(false)
    setPassword('')
    setConfirm('')
    setTotp('')
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      if (mode === 'register') {
        if (password !== confirm) {
          throw new Error('Password confirmation does not match')
        }
        onSuccess(await register(username, password))
      } else {
        onSuccess(await login(username, password, need2fa ? totp : undefined))
      }
    } catch (err) {
      if (err instanceof TwoFactorRequired) {
        setNeed2fa(true)
        setError('')
      } else {
        setError((err as Error).message)
      }
    } finally {
      setBusy(false)
    }
  }

  const isRegister = mode === 'register'
  const canSubmit =
    !busy &&
    username.length >= 3 &&
    password.length >= (isRegister ? 8 : 1) &&
    (!isRegister || confirm.length > 0) &&
    (!need2fa || totp.length > 0)

  return (
    <div className="grid h-screen place-items-center bg-bg text-fg">
      <form onSubmit={submit} className="w-80 space-y-5 rounded-2xl border border-border bg-surface p-6 shadow-xl">
        <div className="flex flex-col items-center gap-2 text-center">
          <img src="/deuswatch-eye.png" alt="DeusWatch" className="h-12 w-auto" />
          <div className="text-lg font-semibold tracking-tight text-fg">
            <span className="text-accent">DEUS</span>WATCH
          </div>
          <div className="text-xs text-dim">{isRegister ? 'Create a new account' : 'Sign in to continue'}</div>
        </div>

        {canRegister && !need2fa && (
          <div className="flex rounded-lg border border-border bg-bg p-0.5 text-sm">
            <button
              type="button"
              onClick={() => switchMode('login')}
              className={`flex-1 rounded-md py-1.5 transition-colors ${
                mode === 'login' ? 'bg-surface-2 font-medium text-fg' : 'text-muted hover:text-fg'
              }`}
            >
              Sign in
            </button>
            <button
              type="button"
              onClick={() => switchMode('register')}
              className={`flex-1 rounded-md py-1.5 transition-colors ${
                mode === 'register' ? 'bg-surface-2 font-medium text-fg' : 'text-muted hover:text-fg'
              }`}
            >
              Sign up
            </button>
          </div>
        )}

        <div className="space-y-3">
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username"
            autoFocus
            disabled={need2fa}
            className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent disabled:opacity-60"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={isRegister ? 'Password (min 8)' : 'Password'}
            disabled={need2fa}
            className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent disabled:opacity-60"
          />
          {isRegister && !need2fa && (
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Confirm password"
              className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
            />
          )}
          {need2fa && (
            <input
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              placeholder="2FA code (6 digits)"
              inputMode="numeric"
              autoFocus
              className="w-full rounded-lg border border-indigo-700 bg-surface-2 px-3 py-2 text-sm tracking-widest outline-none focus:border-accent"
            />
          )}
        </div>

        {error && <p className="text-sm text-rose-400">{error}</p>}

        <button
          type="submit"
          disabled={!canSubmit}
          className="w-full rounded-lg bg-accent py-2 text-sm font-medium text-white transition-colors hover:opacity-90 disabled:opacity-50"
        >
          {busy ? 'Processingâ€¦' : need2fa ? 'Verify' : isRegister ? 'Sign up' : 'Sign in'}
        </button>

        {isRegister && (
          <p className="text-center text-xs text-dim">New accounts get the viewer role (read-only).</p>
        )}
      </form>
    </div>
  )
}
