import { useEffect, useState } from 'react'
import {
  fetchResponses,
  fetchOffenders,
  approveResponse,
  dismissResponse,
  unbanResponse,
  dismissPendingForIP,
  fetchBanPolicy,
  saveBanPolicy,
  fetchWhitelist,
  addWhitelist,
  deleteWhitelist,
  fetchBlocklistConfig,
  regenerateBlocklistToken,
  fetchEnforcement,
  type Enforcement,
  fetchDecisionTable,
  type Decision,
  fetchContainments,
  approveContainment,
  dismissContainment,
  releaseContainment,
  listKillRequests,
  decideKill,
  type KillRequest,
  can,
  type ResponseAction,
  type ResponseStatus,
  type Offender,
  type WhitelistEntry,
  type Containment,
  type ContainmentStatus,
  type Me,
} from '../lib/api'
import DocLink from '../components/DocLink'

const STATUS_BADGE: Record<ResponseStatus, string> = {
  recommended: 'text-amber-300 bg-amber-500/15',
  approved: 'text-sky-300 bg-sky-500/15',
  executed: 'text-emerald-300 bg-emerald-500/15',
  dismissed: 'text-muted bg-surface-2',
  failed: 'text-rose-300 bg-rose-500/15',
  unbanned: 'text-fg bg-slate-600/30',
}

const FILTERS: { label: string; value: string }[] = [
  { label: 'All', value: '' },
  { label: 'Recommended', value: 'recommended' },
  { label: 'Executed', value: 'executed' },
  { label: 'Dismissed', value: 'dismissed' },
  { label: 'Unbanned', value: 'unbanned' },
  { label: 'Failed', value: 'failed' },
]

// An active block (executed or approved) can be unbanned.
const isActiveBlock = (a: ResponseAction) => a.action === 'block' && (a.status === 'executed' || a.status === 'approved')

function banLabel(seconds: number): string {
  if (seconds <= 0) return 'permanent'
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

type View = 'ip' | 'events'

export default function Response({ me }: { me: Me }) {
  const canApprove = me.role === 'analyst' || me.role === 'admin'
  const [view, setView] = useState<View>('ip')
  const [actions, setActions] = useState<ResponseAction[]>([])
  const [offenders, setOffenders] = useState<Offender[]>([])
  // Whether a ban can actually reach a firewall — drives the "blocked" vs "Dangerous IP" label.
  const [enforcement, setEnforcement] = useState<Enforcement | null>(null)
  const [filter, setFilter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  const load = () => {
    if (view === 'ip') {
      fetchOffenders()
        .then(setOffenders)
        .catch((e) => setError((e as Error).message))
    } else {
      fetchResponses(filter, search)
        .then(setActions)
        .catch((e) => setError((e as Error).message))
    }
  }
  useEffect(() => {
    load()
    const t = setInterval(load, 10_000)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, filter, search])

  // Enforcement rarely changes; fetch it once (a failure leaves the labels as-is).
  useEffect(() => {
    fetchEnforcement().then(setEnforcement).catch(() => {})
  }, [])

  // act approves/dismisses a single recommended action (by id), then refreshes.
  const act = async (id: string, ip: string, banSecs: number, kind: 'approve' | 'dismiss') => {
    if (kind === 'approve' && !confirm(`Approve block of ${ip} (${banLabel(banSecs)})?`)) return
    setBusy(id)
    setError('')
    try {
      if (kind === 'approve') await approveResponse(id)
      else await dismissResponse(id)
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  // dismissAll bulk-dismisses every pending recommendation for one IP (with confirm).
  const dismissAll = async (ip: string, count: number) => {
    if (!confirm(`Dismiss all ${count} pending recommendation${count === 1 ? '' : 's'} for ${ip}?`)) return
    setBusy(ip)
    setError('')
    try {
      await dismissPendingForIP(ip)
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  // unban lifts a single executed/approved block, then refreshes.
  const unban = async (id: string, ip: string) => {
    if (!confirm(`Unban ${ip}? This lifts the block on the enforcer.`)) return
    setBusy(id)
    setError('')
    try {
      await unbanResponse(id)
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  // selection helpers for bulk actions (events view).
  const toggleSel = (id: string) =>
    setSelected((s) => {
      const n = new Set(s)
      n.has(id) ? n.delete(id) : n.add(id)
      return n
    })
  const toggleAll = (ids: string[]) =>
    setSelected((s) => (ids.length > 0 && ids.every((i) => s.has(i)) ? new Set() : new Set(ids)))

  // bulk applies an action to every selected row that is in a valid state for it.
  const bulk = async (kind: 'approve' | 'dismiss' | 'unban') => {
    const ids = [...selected]
    if (ids.length === 0) return
    if (!confirm(`${kind} ${ids.length} selected action${ids.length === 1 ? '' : 's'}?`)) return
    setBusy('bulk')
    setError('')
    try {
      for (const id of ids) {
        const a = actions.find((x) => x.id === id)
        if (!a) continue
        if (kind === 'approve' && a.status === 'recommended') await approveResponse(id)
        else if (kind === 'dismiss' && a.status === 'recommended') await dismissResponse(id)
        else if (kind === 'unban' && isActiveBlock(a)) await unbanResponse(id)
      }
      setSelected(new Set())
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  const pending =
    view === 'ip'
      ? offenders.reduce((n, o) => n + o.pending, 0)
      : actions.filter((a) => a.status === 'recommended').length

  return (
    <div className="mx-auto max-w-[1400px] px-6 py-5">
      <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="mt-0.5 text-[12px] text-muted">
            Block recommendations &amp; approval · progressive ban
            {pending > 0 && <span className="ml-2 text-amber-300">{pending} awaiting approval</span>}
          </p>
        </div>
        <div className="flex rounded-[8px] border border-border p-0.5 text-sm">
          {(['ip', 'events'] as View[]).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={`rounded-md px-3 py-1 transition-colors ${
                view === v ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg'
              }`}
            >
              {v === 'ip' ? 'By IP' : 'Events'}
            </button>
          ))}
        </div>
      </header>

      <KillSwitchPanel canApprove={canApprove} />
      <ContainmentPanel canApprove={canApprove} />
      <DecisionTablePanel />
      <BanPolicyEditor canManage={can(me, 'manage_settings')} />
      <WhitelistEditor canManage={can(me, 'manage_settings')} />
      <BlocklistFeedPanel canManage={can(me, 'manage_settings')} />

      {view === 'events' && (
        <div className="mt-6 mb-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            {FILTERS.map((f) => (
              <button
                key={f.value}
                onClick={() => setFilter(f.value)}
                className={`rounded-[8px] px-3 py-1.5 text-[12.5px] transition-colors ${
                  filter === f.value
                    ? 'bg-accent-soft font-medium text-accent'
                    : 'text-muted hover:bg-surface-2 hover:text-fg'
                }`}
              >
                {f.label}
              </button>
            ))}
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IP, rule, reason…"
              className="ml-auto w-64 rounded-[8px] border border-border bg-surface-2 px-3 py-1.5 text-[12.5px] text-fg outline-none focus:border-accent"
            />
          </div>
          {canApprove && selected.size > 0 && (
            <div className="flex flex-wrap items-center gap-2 rounded-[8px] border border-border bg-surface px-3 py-2 text-sm">
              <span className="text-muted">{selected.size} selected</span>
              <button onClick={() => bulk('approve')} disabled={busy === 'bulk'}
                className="rounded-md border border-emerald-500/40 px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50">Approve</button>
              <button onClick={() => bulk('dismiss')} disabled={busy === 'bulk'}
                className="rounded-md border border-border px-2 py-1 text-[11px] text-fg hover:bg-surface-2 disabled:opacity-50">Dismiss</button>
              <button onClick={() => bulk('unban')} disabled={busy === 'bulk'}
                className="rounded-md border border-amber-500/40 px-2 py-1 text-[11px] text-amber-300 hover:bg-amber-500/10 disabled:opacity-50">Unban</button>
              <button onClick={() => setSelected(new Set())} className="ml-1 text-[11px] text-dim hover:text-fg">Clear</button>
            </div>
          )}
        </div>
      )}

      {error && <p className="mb-4 text-[12.5px] text-rose-400">{error}</p>}

      {/* Honesty guard: if nothing is wired up to enforce a ban, say so rather than badging
          IPs "blocked" — DeusWatch would be claiming an action it never performed. */}
      {enforcement && !enforcement.enforcing && (
        <div className="mt-4 rounded-[8px] border border-amber-900/50 bg-amber-500/5 p-3">
          <p className="text-[12.5px] text-amber-200">
            No enforcement configured — these IPs are <span className="font-medium">flagged, not blocked</span>.
          </p>
          <p className="mt-1 text-[11px] text-muted">
            DeusWatch is recording the decisions, but nothing pushes them to a firewall yet.
            {!enforcement.response_live && <> Set <span className="font-mono">RESPONSE_LIVE=1</span> and</>}
            {' '}connect a responder (MikroTik / CrowdSec / agent nftables) in Integrations, or enable the
            Blocklist feed below so your firewall pulls the list.{' '}
            <DocLink file="mikrotik.md" label="How to connect a firewall" />
          </p>
        </div>
      )}

      {view === 'ip' ? (
        <div className="mt-6">
          <OffendersTable offenders={offenders} canApprove={canApprove} busy={busy} act={act} dismissAll={dismissAll} enforcing={enforcement?.enforcing ?? true} />
        </div>
      ) : (
        <EventsTable actions={actions} canApprove={canApprove} busy={busy} act={act} unban={unban} selected={selected} toggleSel={toggleSel} toggleAll={toggleAll} />
      )}

      {!canApprove && (
        <p className="mt-3 text-[11px] text-dim">Your role is view-only; approving/dismissing requires analyst or admin.</p>
      )}
    </div>
  )
}

type ActFn = (id: string, ip: string, banSecs: number, kind: 'approve' | 'dismiss') => void

function OffendersTable({
  offenders,
  canApprove,
  busy,
  act,
  dismissAll,
  enforcing,
}: {
  offenders: Offender[]
  canApprove: boolean
  busy: string
  act: ActFn
  dismissAll: (ip: string, count: number) => void
  enforcing: boolean
}) {
  return (
    <div className="overflow-hidden rounded-[12px] border border-border">
      <table className="w-full text-left text-sm">
        <thead className="bg-surface text-[11px] uppercase tracking-wider text-dim">
          <tr>
            <th className="px-4 py-2 font-medium">Source IP</th>
            <th className="px-4 py-2 font-medium">Agent</th>
            <th className="px-4 py-2 font-medium">Offenses</th>
            <th className="px-4 py-2 font-medium">Last reason</th>
            <th className="px-4 py-2 font-medium">Current ban</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Last seen</th>
            <th className="px-4 py-2 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border bg-surface">
          {offenders.length === 0 && (
            <tr>
              <td colSpan={8} className="px-4 py-8 text-center text-dim">
                No offending IPs yet. Alerts with a source IP will appear here, one row per IP.
              </td>
            </tr>
          )}
          {offenders.map((o) => (
            <tr key={o.source_ip} className="hover:bg-surface-2">
              <td className="px-4 py-2 font-mono text-fg">{o.source_ip}</td>
              <td className="px-4 py-2 text-fg">{o.last_agent || '—'}</td>
              <td className="px-4 py-2 text-muted">
                {o.offenses}
                {o.pending > 0 && <span className="ml-1 text-amber-300">(+{o.pending})</span>}
              </td>
              <td className="px-4 py-2 text-fg">{o.last_reason || '—'}</td>
              <td className="px-4 py-2 text-muted">{banLabel(o.last_ban_secs)}</td>
              <td className="px-4 py-2">
                {o.blocked ? (
                  enforcing ? (
                    <span
                      className="rounded bg-rose-500/15 px-1.5 py-0.5 text-[11px] font-medium text-rose-300"
                      title={o.blocked_until ? `until ${new Date(o.blocked_until).toLocaleString('en-US')}` : 'permanent'}
                    >
                      blocked{o.blocked_until ? '' : ' · permanent'}
                    </span>
                  ) : (
                    // Nothing enforces the ban — the decision is recorded, the IP is not blocked.
                    <span
                      className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[11px] font-medium text-amber-300"
                      title="Flagged for blocking, but no firewall/responder is connected — the IP is NOT actually blocked. Connect a responder or enable the blocklist feed."
                    >
                      Dangerous IP
                    </span>
                  )
                ) : (
                  <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${STATUS_BADGE[o.last_status] ?? 'text-muted bg-surface-2'}`}>
                    {o.last_status}
                  </span>
                )}
              </td>
              <td className="px-4 py-2 text-muted">{new Date(o.last_seen).toLocaleString('en-US')}</td>
              <td className="px-4 py-2">
                {o.pending_id && canApprove ? (
                  <div className="flex gap-2">
                    <button
                      onClick={() => act(o.pending_id, o.source_ip, o.last_ban_secs, 'approve')}
                      disabled={busy === o.pending_id}
                      className="rounded-md border border-emerald-500/40 px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50"
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => act(o.pending_id, o.source_ip, o.last_ban_secs, 'dismiss')}
                      disabled={busy === o.pending_id || busy === o.source_ip}
                      className="rounded-md border border-border px-2 py-1 text-[11px] text-fg hover:bg-surface-2 disabled:opacity-50"
                    >
                      Dismiss
                    </button>
                    {o.pending > 1 && (
                      <button
                        onClick={() => dismissAll(o.source_ip, o.pending)}
                        disabled={busy === o.source_ip}
                        className="rounded-md border border-amber-600/40 px-2 py-1 text-[11px] text-amber-300 hover:bg-amber-500/10 disabled:opacity-50"
                        title={`Dismiss all ${o.pending} pending recommendations for this IP`}
                      >
                        Dismiss all ({o.pending})
                      </button>
                    )}
                  </div>
                ) : (
                  <span className="text-[11px] text-dim">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function EventsTable({
  actions,
  canApprove,
  busy,
  act,
  unban,
  selected,
  toggleSel,
  toggleAll,
}: {
  actions: ResponseAction[]
  canApprove: boolean
  busy: string
  act: ActFn
  unban: (id: string, ip: string) => void
  selected: Set<string>
  toggleSel: (id: string) => void
  toggleAll: (ids: string[]) => void
}) {
  // Rows eligible for a bulk action (so "select all" only ticks actionable ones).
  const selectableIds = actions.filter((a) => a.status === 'recommended' || isActiveBlock(a)).map((a) => a.id)
  const allChecked = selectableIds.length > 0 && selectableIds.every((id) => selected.has(id))
  return (
    <div className="overflow-hidden rounded-[12px] border border-border">
      <table className="w-full text-left text-sm">
        <thead className="bg-surface text-[11px] uppercase tracking-wider text-dim">
          <tr>
            {canApprove && (
              <th className="px-3 py-2">
                <input type="checkbox" checked={allChecked} onChange={() => toggleAll(selectableIds)}
                  disabled={selectableIds.length === 0} className="h-4 w-4 accent-indigo-500" title="Select all actionable" />
              </th>
            )}
            <th className="px-4 py-2 font-medium">Time</th>
            <th className="px-4 py-2 font-medium">Agent</th>
            <th className="px-4 py-2 font-medium">Source IP</th>
            <th className="px-4 py-2 font-medium">Reason</th>
            <th className="px-4 py-2 font-medium">Ban</th>
            <th className="px-4 py-2 font-medium">Offenses</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border bg-surface">
          {actions.length === 0 && (
            <tr>
              <td colSpan={canApprove ? 9 : 8} className="px-4 py-8 text-center text-dim">
                No response actions match. Alerts with a source IP produce block recommendations.
              </td>
            </tr>
          )}
          {actions.map((a) => {
            const selectable = a.status === 'recommended' || isActiveBlock(a)
            return (
              <tr key={a.id} className="hover:bg-surface-2">
                {canApprove && (
                  <td className="px-3 py-2">
                    <input type="checkbox" checked={selected.has(a.id)} disabled={!selectable}
                      onChange={() => toggleSel(a.id)} className="h-4 w-4 accent-indigo-500 disabled:opacity-30" />
                  </td>
                )}
                <td className="px-4 py-2 text-muted">{new Date(a.created_at).toLocaleString('en-US')}</td>
                <td className="px-4 py-2 text-fg">{a.agent_id || '—'}</td>
                <td className="px-4 py-2 font-mono text-fg">{a.source_ip}</td>
                <td className="px-4 py-2 text-fg">{a.reason || a.rule_id || '—'}</td>
                <td className="px-4 py-2 text-muted">{banLabel(a.ban_seconds)}</td>
                <td className="px-4 py-2 text-muted">#{a.offense_count}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${STATUS_BADGE[a.status]}`}>{a.status}</span>
                  {a.responder && <span className="ml-1 text-[11px] text-dim">{a.responder}</span>}
                  {a.status === 'failed' && a.error && (
                    <div className="mt-0.5 text-[11px] text-rose-400" title={a.error}>{a.error.slice(0, 40)}…</div>
                  )}
                </td>
                <td className="px-4 py-2">
                  {a.status === 'recommended' && canApprove ? (
                    <div className="flex gap-2">
                      <button
                        onClick={() => act(a.id, a.source_ip, a.ban_seconds, 'approve')}
                        disabled={busy === a.id}
                        className="rounded-md border border-emerald-500/40 px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => act(a.id, a.source_ip, a.ban_seconds, 'dismiss')}
                        disabled={busy === a.id}
                        className="rounded-md border border-border px-2 py-1 text-[11px] text-fg hover:bg-surface-2 disabled:opacity-50"
                      >
                        Dismiss
                      </button>
                    </div>
                  ) : isActiveBlock(a) && canApprove ? (
                    <button
                      onClick={() => unban(a.id, a.source_ip)}
                      disabled={busy === a.id}
                      className="rounded-md border border-amber-500/40 px-2 py-1 text-[11px] text-amber-300 hover:bg-amber-500/10 disabled:opacity-50"
                    >
                      Unban
                    </button>
                  ) : (
                    <span className="text-[11px] text-dim">{a.decided_by ? `by ${a.decided_by}` : '—'}</span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
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
  const [autoApprove, setAutoApprove] = useState(false)
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
        setAutoApprove(p.auto_approve)
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
      const saved = await saveBanPolicy({ durations, permanent, window_secs, auto_approve: autoApprove })
      setSteps(saved.durations.map(toStep))
      setPermanent(saved.permanent)
      setWin(saved.window_secs > 0 ? toStep(saved.window_secs) : { value: 0, unit: 'h' })
      setAutoApprove(saved.auto_approve)
      setMsg('Saved · the worker picks up the new policy within ~30s.')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (!loaded) return null

  const preview =
    (steps.length === 0
      ? '—'
      : [...steps.map((s) => `${s.value}${s.unit}`), permanent ? 'permanent' : 'cap'].join(' → ')) +
    (autoApprove ? ' · auto' : '')

  return (
    <div className="mb-6 overflow-hidden rounded-[12px] border border-border bg-surface">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-3 text-left hover:bg-surface-2"
      >
        <span className="text-[12.5px] font-medium text-fg">
          Progressive-ban policy
          <span className="ml-2 font-mono text-[11px] text-dim">{preview}</span>
        </span>
        <span className="text-[11px] text-dim">{open ? '▲ hide' : '▼ configure'}</span>
      </button>

      {open && (
        <div className="space-y-5 border-t border-border px-4 py-4">
          <p className="text-[11px] text-dim">
            Each repeat offense from the same source IP escalates one step down this ladder. The
            offense count is taken from prior executed blocks.
          </p>

          <label className="flex items-start gap-3 rounded-[8px] border border-border bg-bg px-3 py-2.5">
            <input
              type="checkbox"
              checked={autoApprove}
              disabled={!canManage}
              onChange={(e) => setAutoApprove(e.target.checked)}
              className="mt-0.5 h-4 w-4 accent-indigo-500 disabled:opacity-60"
            />
            <span className="text-[12.5px] text-fg">
              Automatic ban (no manual approval)
              <span className="mt-0.5 block text-[11px] text-dim">
                When on, the engine bans the IP automatically and escalates the duration on each
                repeat — no analyst approval needed. When off, every block waits for approval.
              </span>
            </span>
          </label>

          <div>
            <label className="mb-2 block text-[11px] font-medium uppercase tracking-wider text-dim">
              Escalation ladder
            </label>
            <div className="space-y-2">
              {steps.map((s, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="w-16 text-[11px] text-dim">offense #{i + 1}</span>
                  <input
                    type="number"
                    min={1}
                    value={s.value}
                    disabled={!canManage}
                    onChange={(e) => setStep(i, { value: Number(e.target.value) })}
                    className="w-20 rounded-md border border-border bg-bg px-2 py-1 text-[12.5px] text-fg disabled:opacity-60"
                  />
                  <select
                    value={s.unit}
                    disabled={!canManage}
                    onChange={(e) => setStep(i, { unit: e.target.value })}
                    className="rounded-md border border-border bg-bg px-2 py-1 text-[12.5px] text-fg disabled:opacity-60"
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
                      className="rounded-md border border-border px-2 py-1 text-[11px] text-muted hover:bg-surface-2 hover:text-rose-300"
                    >
                      remove
                    </button>
                  )}
                </div>
              ))}
              {steps.length === 0 && (
                <p className="text-[11px] text-dim">No steps defined.</p>
              )}
            </div>
            {canManage && (
              <button
                onClick={addStep}
                className="mt-2 rounded-md border border-border px-2.5 py-1 text-[11px] text-fg hover:bg-surface-2"
              >
                + Add step
              </button>
            )}
          </div>

          <div>
            <label className="mb-2 block text-[11px] font-medium uppercase tracking-wider text-dim">
              After the last step
            </label>
            <select
              value={permanent ? 'permanent' : 'cap'}
              disabled={!canManage}
              onChange={(e) => setPermanent(e.target.value === 'permanent')}
              className="rounded-md border border-border bg-bg px-2 py-1 text-[12.5px] text-fg disabled:opacity-60"
            >
              <option value="permanent">Permanent ban</option>
              <option value="cap">Keep the longest duration</option>
            </select>
          </div>

          <div>
            <label className="mb-2 block text-[11px] font-medium uppercase tracking-wider text-dim">
              Observation window
            </label>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min={0}
                value={win.value}
                disabled={!canManage}
                onChange={(e) => setWin((w) => ({ ...w, value: Number(e.target.value) }))}
                className="w-20 rounded-md border border-border bg-bg px-2 py-1 text-[12.5px] text-fg disabled:opacity-60"
              />
              <select
                value={win.unit}
                disabled={!canManage}
                onChange={(e) => setWin((w) => ({ ...w, unit: e.target.value }))}
                className="rounded-md border border-border bg-bg px-2 py-1 text-[12.5px] text-fg disabled:opacity-60"
              >
                {UNITS.map((u) => (
                  <option key={u.u} value={u.u}>
                    {u.label}
                  </option>
                ))}
              </select>
              <span className="text-[11px] text-dim">0 = count all history</span>
            </div>
          </div>

          {error && <p className="text-[12.5px] text-rose-400">{error}</p>}
          {msg && <p className="text-[12.5px] text-emerald-400">{msg}</p>}

          {canManage ? (
            <button
              onClick={save}
              disabled={busy}
              className="rounded-[8px] bg-accent/90 px-4 py-1.5 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-50"
            >
              {busy ? 'Saving…' : 'Save policy'}
            </button>
          ) : (
            <p className="text-[11px] text-dim">Editing the ban policy requires the manage-settings permission.</p>
          )}
        </div>
      )}
    </div>
  )
}

// ── Blocklist feed (external-firewall sync) ─────────────────
function BlocklistFeedPanel({ canManage }: { canManage: boolean }) {
  const [token, setToken] = useState('')
  const [enabled, setEnabled] = useState(false)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    if (!canManage) return
    fetchBlocklistConfig().then((c) => { setToken(c.token); setEnabled(c.enabled) }).catch(() => {})
  }, [canManage])

  if (!canManage) return null

  const url = enabled ? `${window.location.origin}/api/blocklist?token=${token}` : ''
  const regenerate = async () => {
    setBusy(true); setErr('')
    try { const c = await regenerateBlocklistToken(); setToken(c.token); setEnabled(true) }
    catch (e) { setErr((e as Error).message) }
    finally { setBusy(false) }
  }
  const copy = async () => {
    try { await navigator.clipboard.writeText(url); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* ignore */ }
  }

  return (
    <section className="mt-6 rounded-[12px] border border-border bg-surface p-5">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-[12.5px] font-semibold text-fg">Blocklist feed (external firewalls)</h2>
        <DocLink file="blocklist-feed.md" className="shrink-0" />
      </div>
      <p className="mb-3 mt-0.5 text-[12px] text-muted">
        A token-gated URL of the currently-banned IPs. Point a firewall's dynamic block list
        at it (Palo Alto EDL, OPNsense URL table, pfSense pfBlockerNG, MikroTik) to mirror your
        bans. Expired/unbanned IPs drop off automatically.
      </p>
      {enabled ? (
        <div className="flex flex-wrap items-center gap-2">
          <input readOnly value={url} onFocus={(e) => e.currentTarget.select()}
            className="min-w-0 flex-1 rounded-[8px] border border-border bg-bg px-3 py-2 font-mono text-[11px] text-fg outline-none" />
          <button onClick={copy} className="rounded-[8px] border border-border px-3 py-2 text-[12.5px] text-fg hover:bg-surface-2">{copied ? 'Copied ✓' : 'Copy'}</button>
          <button onClick={regenerate} disabled={busy}
            className="rounded-[8px] border border-amber-700/60 px-3 py-2 text-[12.5px] text-amber-300 hover:bg-amber-500/10 disabled:opacity-50">
            {busy ? 'Regenerating…' : 'Regenerate token'}
          </button>
        </div>
      ) : (
        <button onClick={regenerate} disabled={busy}
          className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-50">
          {busy ? 'Generating…' : 'Enable feed (generate token)'}
        </button>
      )}
      {enabled && (
        <p className="mt-2 text-[11px] text-dim">
          The token is in the URL - serve it over HTTPS / LAN. Regenerating invalidates the old URL.
          Add <span className="font-mono">&amp;format=json</span> for JSON.
        </p>
      )}
      {err && <p className="mt-2 text-[12.5px] text-rose-400">{err}</p>}
    </section>
  )
}

// ── IP whitelist editor ─────────────────────────────────────
// Trusted IPs/CIDRs that the response engine never bans. Detection, alerting
// and notifications still fire for them — only the ban is skipped.

function WhitelistEditor({ canManage }: { canManage: boolean }) {
  const [entries, setEntries] = useState<WhitelistEntry[]>([])
  const [cidr, setCidr] = useState('')
  const [note, setNote] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(false)

  const load = () => {
    fetchWhitelist()
      .then((e) => {
        setEntries(e)
        setLoaded(true)
      })
      .catch((e) => {
        setError((e as Error).message)
        setLoaded(true)
      })
  }
  useEffect(load, [])

  const add = async () => {
    if (!cidr.trim()) return
    setBusy(true)
    setError('')
    try {
      await addWhitelist(cidr.trim(), note.trim())
      setCidr('')
      setNote('')
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const remove = async (id: string) => {
    setError('')
    try {
      await deleteWhitelist(id)
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  if (!loaded) return null

  return (
    <div className="mb-6 overflow-hidden rounded-[12px] border border-border bg-surface">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-3 text-left hover:bg-surface-2"
      >
        <span className="text-[12.5px] font-medium text-fg">
          IP whitelist
          <span className="ml-2 text-[11px] text-dim">{entries.length} trusted · never banned</span>
        </span>
        <span className="text-[11px] text-dim">{open ? '▲ hide' : '▼ configure'}</span>
      </button>

      {open && (
        <div className="space-y-4 border-t border-border px-4 py-4">
          <p className="text-[11px] text-dim">
            A matching source IP is never banned (single IP like <code className="text-muted">192.168.81.10</code> or a
            range like <code className="text-muted">10.0.0.0/8</code>). Alerts and notifications still fire — only the
            block is skipped.
          </p>

          {canManage && (
            <div className="flex flex-wrap items-center gap-2">
              <input
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && add()}
                placeholder="IP or CIDR"
                className="w-44 rounded-md border border-border bg-bg px-2 py-1 text-[12.5px] text-fg outline-none focus:border-accent"
              />
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && add()}
                placeholder="note (optional)"
                className="min-w-0 flex-1 rounded-md border border-border bg-bg px-2 py-1 text-[12.5px] text-fg outline-none focus:border-accent"
              />
              <button
                onClick={add}
                disabled={busy || !cidr.trim()}
                className="rounded-[8px] bg-accent/90 px-3 py-1.5 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-50"
              >
                + Add
              </button>
            </div>
          )}

          {error && <p className="text-[12.5px] text-rose-400">{error}</p>}

          <div className="overflow-hidden rounded-[8px] border border-border">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface text-[11px] uppercase tracking-wider text-dim">
                <tr>
                  <th className="px-3 py-2 font-medium">IP / CIDR</th>
                  <th className="px-3 py-2 font-medium">Note</th>
                  <th className="px-3 py-2 font-medium">Added</th>
                  {canManage && <th className="px-3 py-2 font-medium"></th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-border bg-surface">
                {entries.length === 0 && (
                  <tr>
                    <td colSpan={canManage ? 4 : 3} className="px-3 py-6 text-center text-dim">
                      No whitelisted IPs.
                    </td>
                  </tr>
                )}
                {entries.map((e) => (
                  <tr key={e.id} className="hover:bg-surface-2">
                    <td className="px-3 py-2 font-mono text-fg">{e.cidr}</td>
                    <td className="px-3 py-2 text-muted">{e.note || '—'}</td>
                    <td className="px-3 py-2 text-dim">{new Date(e.created_at).toLocaleString('en-US')}</td>
                    {canManage && (
                      <td className="px-3 py-2 text-right">
                        <button
                          onClick={() => remove(e.id)}
                          className="rounded-md border border-rose-900/60 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/10"
                        >
                          remove
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {!canManage && (
            <p className="text-[11px] text-dim">Editing the whitelist requires the manage-settings permission.</p>
          )}
        </div>
      )}
    </div>
  )
}

const CONTAIN_BADGE: Record<ContainmentStatus, string> = {
  recommended: 'text-amber-300 bg-amber-500/15',
  contained: 'text-rose-300 bg-rose-500/15',
  released: 'text-fg bg-slate-600/30',
  dismissed: 'text-muted bg-surface-2',
  failed: 'text-rose-300 bg-rose-500/15',
}

// expiryLabel shows the time left before an isolated host auto-releases (or "manual").
function expiryLabel(c: Containment): string {
  if (c.status !== 'contained') return '—'
  if (!c.expires_at) return 'manual'
  const ms = new Date(c.expires_at).getTime() - Date.now()
  if (ms <= 0) return 'expiring…'
  const m = Math.round(ms / 60000)
  return m >= 60 ? `${Math.round(m / 60)}h left` : `${m}m left`
}

// ContainmentPanel lists isolated/recommended hosts and lets an analyst isolate (approve),
// dismiss a recommendation, or release an active containment. Self-contained (own polling).
// DecisionTablePanel shows the explicit entity_type → response policy (read-only). It is the
// same table the worker routes alerts by, so an operator can see exactly what DeusWatch does
// with each kind of entity and which actions are automatically enforced vs. alert-only.
function DecisionTablePanel() {
  const [rows, setRows] = useState<Decision[]>([])
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchDecisionTable()
      .then(setRows)
      .catch((e) => setError((e as Error).message))
  }, [])

  return (
    <section className="mb-6 overflow-hidden rounded-[12px] border border-border bg-surface">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-3 text-left hover:bg-surface-2/30"
      >
        <div>
          <h2 className="text-[12.5px] font-semibold text-fg">Decision table</h2>
          <p className="mt-0.5 text-[11px] text-dim">
            What DeusWatch does with each entity type — the policy alerts are routed by.
          </p>
        </div>
        <span className="text-dim">{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="border-t border-border">
          {error && <p className="px-4 py-2 text-[12.5px] text-rose-400">{error}</p>}
          <table className="w-full text-left text-sm">
            <thead className="bg-surface text-[11px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-4 py-2 font-medium">Entity</th>
                <th className="px-4 py-2 font-medium">Action</th>
                <th className="px-4 py-2 font-medium">Enforcement</th>
                <th className="px-4 py-2 font-medium">What happens</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((d) => (
                <tr key={d.entity_type} className="hover:bg-surface-2">
                  <td className="px-4 py-2 font-mono text-[11px] text-fg">{d.entity_type}</td>
                  <td className="px-4 py-2 text-fg">{d.action}</td>
                  <td className="px-4 py-2">
                    {d.enforced ? (
                      <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[11px] font-medium text-emerald-300">
                        auto · {d.engine}
                      </span>
                    ) : (
                      <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[11px] font-medium text-muted">
                        alert-only
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-[11px] text-muted">{d.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="px-4 py-2">
            <DocLink file="decision-table.md" label="About the decision table" />
          </div>
        </div>
      )}
    </section>
  )
}

// killOutcomeTone maps an agent-reported outcome to a colour. Only an actual kill is green:
// every "skipped_*" means the process is STILL RUNNING, and colouring those as success would be
// the single most dangerous lie this UI could tell.
function killOutcomeTone(result: string): string {
  const r = (result || '').toLowerCase()
  if (r.startsWith('killed')) return 'text-emerald-400'
  if (r.startsWith('dismissed')) return 'text-dim'
  if (r.startsWith('skipped_gone')) return 'text-dim'
  return 'text-amber-300' // skipped_protected / skipped_mismatch / failed - nothing was killed
}

// KillSwitchPanel lists proposed and executed ransomware process terminations.
//
// Killing a process is the most destructive action DeusWatch takes, so detection only ever
// PROPOSES one; an analyst with approve-remediation authorizes it here. Even after approval the
// agent independently re-verifies that the live process is still the one detected (a PID may have
// been recycled onto something innocent) and that it is not protected - and it may refuse. This
// panel therefore reports what actually happened, never what was intended.
function KillSwitchPanel({ canApprove }: { canApprove: boolean }) {
  const [items, setItems] = useState<KillRequest[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(0)

  const load = () => {
    listKillRequests(false, 50)
      .then(setItems)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(() => {
    load()
    const t = setInterval(load, 10_000)
    return () => clearInterval(t)
  }, [])

  const act = async (k: KillRequest, approve: boolean) => {
    const what = `${k.proc_name || 'process'} (pid ${k.pid}) on ${k.agent_name}`
    if (approve && !confirm(`Terminate ${what}?\n\nThis kills the process immediately. The agent will refuse if the PID no longer matches the detected process, or if it is a protected system process.`)) return
    if (!approve && !confirm(`Dismiss the kill recommendation for ${what}?`)) return
    setBusy(k.id)
    setError('')
    try {
      await decideKill(k.id, approve)
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(0)
    }
  }

  const pending = items.filter((k) => k.status === 'recommended').length

  return (
    <section className="mb-6 overflow-hidden rounded-[12px] border border-border bg-surface">
      <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
        <div>
        <h2 className="text-[12.5px] font-semibold text-fg">Ransomware kill-switch</h2>
        <p className="mt-0.5 text-[11px] text-dim">
          Processes proposed for termination after encryption was detected.{' '}
          {pending > 0 ? (
            <span className="text-amber-300">{pending} awaiting approval</span>
          ) : (
            'Nothing awaiting approval.'
          )}
        </p>
        </div>
        <DocLink file="ransomware.md" className="shrink-0" />
      </div>
      {error && <p className="px-4 py-2 text-[12.5px] text-rose-400">{error}</p>}
      {items.length === 0 && !error && (
        <p className="px-4 py-3 text-[12px] text-dim">
          No kill requests. A recommendation needs an attributed process, which on Linux requires
          auditd who-data to be enabled.
        </p>
      )}
      {items.length > 0 && (
        <table className="w-full text-left text-sm">
          <thead className="bg-surface text-[11px] uppercase tracking-wider text-dim">
            <tr>
              <th className="px-4 py-2 font-medium">Process</th>
              <th className="px-4 py-2 font-medium">Agent</th>
              <th className="px-4 py-2 font-medium">Why</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            {items.map((k) => (
              <tr key={k.id} className="border-t border-border align-top">
                <td className="px-4 py-2">
                  <span className="font-medium text-fg">{k.proc_name || '—'}</span>
                  <span className="text-dim"> pid {k.pid}</span>
                  {k.exe && <div className="truncate text-[11px] text-dim" title={k.exe}>{k.exe}</div>}
                </td>
                <td className="px-4 py-2 text-muted">{k.agent_name}</td>
                <td className="px-4 py-2 text-[11px] text-muted">{k.reason || '—'}</td>
                <td className="px-4 py-2">
                  {k.status === 'recommended' && <span className="text-amber-300">awaiting approval</span>}
                  {(k.status === 'requested' || k.status === 'delivered') && (
                    <span className="text-muted">approved, sent to agent</span>
                  )}
                  {(k.status === 'done' || k.status === 'failed') && (
                    <span className={killOutcomeTone(k.result || '')}>{k.result || k.status}</span>
                  )}
                </td>
                <td className="px-4 py-2 text-right whitespace-nowrap">
                  {k.status === 'recommended' && canApprove && (
                    <>
                      <button
                        onClick={() => act(k, true)}
                        disabled={busy === k.id}
                        className="rounded-[6px] bg-rose-600 px-2 py-1 text-[11px] font-medium text-white hover:opacity-90 disabled:opacity-50"
                      >
                        Kill process
                      </button>
                      <button
                        onClick={() => act(k, false)}
                        disabled={busy === k.id}
                        className="ml-2 rounded-[6px] border border-border px-2 py-1 text-[11px] text-muted hover:opacity-90 disabled:opacity-50"
                      >
                        Dismiss
                      </button>
                    </>
                  )}
                  {k.status === 'recommended' && !canApprove && (
                    <span className="text-[11px] text-dim">needs approve-remediation</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function ContainmentPanel({ canApprove }: { canApprove: boolean }) {
  const [items, setItems] = useState<Containment[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  const load = () => {
    fetchContainments()
      .then(setItems)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(() => {
    load()
    const t = setInterval(load, 10_000)
    return () => clearInterval(t)
  }, [])

  const act = async (id: string, host: string, kind: 'approve' | 'dismiss' | 'release') => {
    const verb = kind === 'approve' ? 'Isolate' : kind === 'release' ? 'Release' : 'Dismiss'
    if (!confirm(`${verb} ${host}?`)) return
    setBusy(id)
    setError('')
    try {
      if (kind === 'approve') await approveContainment(id)
      else if (kind === 'release') await releaseContainment(id)
      else await dismissContainment(id)
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  const active = items.filter((c) => c.status === 'contained').length
  const pending = items.filter((c) => c.status === 'recommended').length

  return (
    <section className="mb-6 overflow-hidden rounded-[12px] border border-border bg-surface">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-[12.5px] font-semibold text-fg">Network containment</h2>
        <p className="mt-0.5 text-[11px] text-dim">
          Isolated hosts (host firewall + edge block).{' '}
          {active > 0 && <span className="text-rose-300">{active} contained</span>}
          {active > 0 && pending > 0 && ' · '}
          {pending > 0 && <span className="text-amber-300">{pending} awaiting approval</span>}
          {active === 0 && pending === 0 && 'No active isolations.'}
        </p>
      </div>
      {error && <p className="px-4 py-2 text-[12.5px] text-rose-400">{error}</p>}
      {items.length > 0 && (
        <table className="w-full text-left text-sm">
          <thead className="bg-surface text-[11px] uppercase tracking-wider text-dim">
            <tr>
              <th className="px-4 py-2 font-medium">Host / Agent</th>
              <th className="px-4 py-2 font-medium">IP</th>
              <th className="px-4 py-2 font-medium">Reason</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Expiry</th>
              <th className="px-4 py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {items.map((c) => (
              <tr key={c.id} className="hover:bg-surface-2">
                <td className="px-4 py-2 text-fg">
                  {c.host_name || c.agent_id}
                  {c.auto && (
                    <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">auto</span>
                  )}
                </td>
                <td className="px-4 py-2 font-mono text-[11px] text-muted">{c.ip_address || '—'}</td>
                <td className="px-4 py-2 text-muted">{c.reason || '—'}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${CONTAIN_BADGE[c.status]}`}>{c.status}</span>
                </td>
                <td className="px-4 py-2 text-[11px] text-muted">{expiryLabel(c)}</td>
                <td className="px-4 py-2 text-right">
                  {canApprove && (
                    <div className="flex justify-end gap-2">
                      {c.status === 'recommended' && (
                        <>
                          <button
                            onClick={() => act(c.id, c.host_name || c.agent_id, 'approve')}
                            disabled={busy === c.id}
                            className="rounded-md border border-rose-500/40 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/10 disabled:opacity-50"
                          >
                            Isolate
                          </button>
                          <button
                            onClick={() => act(c.id, c.host_name || c.agent_id, 'dismiss')}
                            disabled={busy === c.id}
                            className="rounded-md border border-border px-2 py-1 text-[11px] text-fg hover:bg-surface-2 disabled:opacity-50"
                          >
                            Dismiss
                          </button>
                        </>
                      )}
                      {c.status === 'contained' && (
                        <button
                          onClick={() => act(c.id, c.host_name || c.agent_id, 'release')}
                          disabled={busy === c.id}
                          className="rounded-md border border-emerald-500/40 px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50"
                        >
                          Release
                        </button>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
