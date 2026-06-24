import { useEffect, useState } from 'react'
import {
  fetchResponses,
  approveResponse,
  dismissResponse,
  fetchBanPolicy,
  saveBanPolicy,
  can,
  type ResponseAction,
  type ResponseStatus,
  type Me,
} from '../lib/api'

const STATUS_BADGE: Record<ResponseStatus, string> = {
  recommended: 'text-amber-300 bg-amber-500/15',
  approved: 'text-sky-300 bg-sky-500/15',
  executed: 'text-emerald-300 bg-emerald-500/15',
  dismissed: 'text-slate-400 bg-slate-700/40',
  failed: 'text-rose-300 bg-rose-500/15',
}

const FILTERS: { label: string; value: string }[] = [
  { label: 'All', value: '' },
  { label: 'Recommended', value: 'recommended' },
  { label: 'Executed', value: 'executed' },
  { label: 'Dismissed', value: 'dismissed' },
  { label: 'Failed', value: 'failed' },
]

function banLabel(seconds: number): string {
  if (seconds <= 0) return 'permanent'
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

export default function Response({ me }: { me: Me }) {
  const canApprove = me.role === 'analyst' || me.role === 'admin'
  const [actions, setActions] = useState<ResponseAction[]>([])
  const [filter, setFilter] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  const load = () => {
    fetchResponses(filter)
      .then(setActions)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(() => {
    load()
    const t = setInterval(load, 10_000)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter])

  const act = async (a: ResponseAction, kind: 'approve' | 'dismiss') => {
    if (kind === 'approve' && !confirm(`Approve block of ${a.source_ip} (${banLabel(a.ban_seconds)})?`)) return
    setBusy(a.id)
    setError('')
    try {
      if (kind === 'approve') await approveResponse(a.id)
      else await dismissResponse(a.id)
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  const pending = actions.filter((a) => a.status === 'recommended').length

  return (
    <div className="mx-auto max-w-5xl px-8 py-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-white">Response</h1>
        <p className="mt-1 text-sm text-slate-500">
          Block recommendations &amp; approval · progressive ban
          {pending > 0 && <span className="ml-2 text-amber-300">{pending} awaiting approval</span>}
        </p>
      </header>

      <BanPolicyEditor canManage={can(me, 'manage_settings')} />

      <div className="mb-4 flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setFilter(f.value)}
            className={`rounded-lg px-3 py-1.5 text-sm transition-colors ${
              filter === f.value
                ? 'bg-indigo-500/10 font-medium text-indigo-300'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {error && <p className="mb-4 text-sm text-rose-400">{error}</p>}

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2 font-medium">Time</th>
              <th className="px-4 py-2 font-medium">Source IP</th>
              <th className="px-4 py-2 font-medium">Reason</th>
              <th className="px-4 py-2 font-medium">Ban</th>
              <th className="px-4 py-2 font-medium">Offenses</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {actions.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                  No response actions yet. Alerts with a source IP will produce block recommendations.
                </td>
              </tr>
            )}
            {actions.map((a) => (
              <tr key={a.id} className="hover:bg-slate-800/40">
                <td className="px-4 py-2 text-slate-400">{new Date(a.created_at).toLocaleString('en-US')}</td>
                <td className="px-4 py-2 font-mono text-slate-300">{a.source_ip}</td>
                <td className="px-4 py-2 text-slate-300">{a.reason || a.rule_id || '—'}</td>
                <td className="px-4 py-2 text-slate-400">{banLabel(a.ban_seconds)}</td>
                <td className="px-4 py-2 text-slate-400">#{a.offense_count}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${STATUS_BADGE[a.status]}`}>{a.status}</span>
                  {a.responder && <span className="ml-1 text-xs text-slate-600">{a.responder}</span>}
                  {a.status === 'failed' && a.error && (
                    <div className="mt-0.5 text-xs text-rose-400" title={a.error}>{a.error.slice(0, 40)}…</div>
                  )}
                </td>
                <td className="px-4 py-2">
                  {a.status === 'recommended' && canApprove ? (
                    <div className="flex gap-2">
                      <button
                        onClick={() => act(a, 'approve')}
                        disabled={busy === a.id}
                        className="rounded-md border border-emerald-500/40 px-2 py-1 text-xs text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => act(a, 'dismiss')}
                        disabled={busy === a.id}
                        className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
                      >
                        Dismiss
                      </button>
                    </div>
                  ) : (
                    <span className="text-xs text-slate-600">{a.decided_by ? `by ${a.decided_by}` : '—'}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!canApprove && (
        <p className="mt-3 text-xs text-slate-600">Your role is view-only; approving/dismissing requires analyst or admin.</p>
      )}
    </div>
  )
}

// ── Ban-policy editor ───────────────────────────────────────
// Configures the progressive-ban ladder: a list of escalating durations
// applied per repeat offense, an optional cap/permanent step, and an
// observation window that limits how far back prior offenses are counted.

const UNITS: { u: string; secs: number; label: string }[] = [
  { u: 'm', secs: 60, label: 'minutes' },
  { u: 'h', secs: 3600, label: 'hours' },
  { u: 'd', secs: 86400, label: 'days' },
]

type Step = { value: number; unit: string }

function toStep(sec: number): Step {
  if (sec > 0 && sec % 86400 === 0) return { value: sec / 86400, unit: 'd' }
  if (sec > 0 && sec % 3600 === 0) return { value: sec / 3600, unit: 'h' }
  return { value: Math.max(1, Math.round(sec / 60)), unit: 'm' }
}

function stepSecs(s: Step): number {
  const u = UNITS.find((x) => x.u === s.unit) ?? UNITS[0]
  return Math.max(1, Math.round(s.value)) * u.secs
}

function BanPolicyEditor({ canManage }: { canManage: boolean }) {
  const [steps, setSteps] = useState<Step[]>([])
  const [permanent, setPermanent] = useState(true)
  const [win, setWin] = useState<Step>({ value: 0, unit: 'h' })
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    fetchBanPolicy()
      .then((p) => {
        setSteps((p.durations ?? []).map(toStep))
        setPermanent(p.permanent)
        setWin(p.window_secs > 0 ? toStep(p.window_secs) : { value: 0, unit: 'h' })
        setLoaded(true)
      })
      .catch((e) => {
        setError((e as Error).message)
        setLoaded(true)
      })
  }, [])

  const setStep = (i: number, patch: Partial<Step>) =>
    setSteps((s) => s.map((x, j) => (j === i ? { ...x, ...patch } : x)))
  const addStep = () =>
    setSteps((s) => [...s, s.length ? { ...s[s.length - 1] } : { value: 10, unit: 'm' }])
  const removeStep = (i: number) => setSteps((s) => s.filter((_, j) => j !== i))

  const save = async () => {
    setBusy(true)
    setError('')
    setMsg('')
    try {
      const durations = steps.map(stepSecs)
      if (durations.length === 0) {
        setError('Add at least one escalation step.')
        setBusy(false)
        return
      }
      const window_secs = win.value > 0 ? stepSecs(win) : 0
      const saved = await saveBanPolicy({ durations, permanent, window_secs })
      setSteps(saved.durations.map(toStep))
      setPermanent(saved.permanent)
      setWin(saved.window_secs > 0 ? toStep(saved.window_secs) : { value: 0, unit: 'h' })
      setMsg('Saved · the worker picks up the new policy within ~30s.')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (!loaded) return null

  const preview =
    steps.length === 0
      ? '—'
      : [...steps.map((s) => `${s.value}${s.unit}`), permanent ? 'permanent' : 'cap'].join(' → ')

  return (
    <div className="mb-6 overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-3 text-left hover:bg-slate-800/40"
      >
        <span className="text-sm font-medium text-slate-200">
          Progressive-ban policy
          <span className="ml-2 font-mono text-xs text-slate-500">{preview}</span>
        </span>
        <span className="text-xs text-slate-500">{open ? '▲ hide' : '▼ configure'}</span>
      </button>

      {open && (
        <div className="space-y-5 border-t border-slate-800 px-4 py-4">
          <p className="text-xs text-slate-500">
            Each repeat offense from the same source IP escalates one step down this ladder. The
            offense count is taken from prior executed blocks.
          </p>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500">
              Escalation ladder
            </label>
            <div className="space-y-2">
              {steps.map((s, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="w-16 text-xs text-slate-500">offense #{i + 1}</span>
                  <input
                    type="number"
                    min={1}
                    value={s.value}
                    disabled={!canManage}
                    onChange={(e) => setStep(i, { value: Number(e.target.value) })}
                    className="w-20 rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200 disabled:opacity-60"
                  />
                  <select
                    value={s.unit}
                    disabled={!canManage}
                    onChange={(e) => setStep(i, { unit: e.target.value })}
                    className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200 disabled:opacity-60"
                  >
                    {UNITS.map((u) => (
                      <option key={u.u} value={u.u}>
                        {u.label}
                      </option>
                    ))}
                  </select>
                  {canManage && (
                    <button
                      onClick={() => removeStep(i)}
                      className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-rose-300"
                    >
                      remove
                    </button>
                  )}
                </div>
              ))}
              {steps.length === 0 && (
                <p className="text-xs text-slate-600">No steps defined.</p>
              )}
            </div>
            {canManage && (
              <button
                onClick={addStep}
                className="mt-2 rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800"
              >
                + Add step
              </button>
            )}
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500">
              After the last step
            </label>
            <select
              value={permanent ? 'permanent' : 'cap'}
              disabled={!canManage}
              onChange={(e) => setPermanent(e.target.value === 'permanent')}
              className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200 disabled:opacity-60"
            >
              <option value="permanent">Permanent ban</option>
              <option value="cap">Keep the longest duration</option>
            </select>
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500">
              Observation window
            </label>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min={0}
                value={win.value}
                disabled={!canManage}
                onChange={(e) => setWin((w) => ({ ...w, value: Number(e.target.value) }))}
                className="w-20 rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200 disabled:opacity-60"
              />
              <select
                value={win.unit}
                disabled={!canManage}
                onChange={(e) => setWin((w) => ({ ...w, unit: e.target.value }))}
                className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200 disabled:opacity-60"
              >
                {UNITS.map((u) => (
                  <option key={u.u} value={u.u}>
                    {u.label}
                  </option>
                ))}
              </select>
              <span className="text-xs text-slate-500">0 = count all history</span>
            </div>
          </div>

          {error && <p className="text-sm text-rose-400">{error}</p>}
          {msg && <p className="text-sm text-emerald-400">{msg}</p>}

          {canManage ? (
            <button
              onClick={save}
              disabled={busy}
              className="rounded-lg bg-indigo-500/90 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
            >
              {busy ? 'Saving…' : 'Save policy'}
            </button>
          ) : (
            <p className="text-xs text-slate-600">Editing the ban policy requires the manage-settings permission.</p>
          )}
        </div>
      )}
    </div>
  )
}
