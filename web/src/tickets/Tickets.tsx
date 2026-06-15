import { useEffect, useState } from 'react'
import {
  fetchTickets,
  fetchTicket,
  createTicket,
  updateTicket,
  addTicketComment,
  can,
  SEVERITY,
  type Me,
  type Ticket,
  type TicketComment,
  type TicketStatus,
  type NewTicketInput,
} from '../lib/api'

const STATUSES: TicketStatus[] = ['open', 'in_progress', 'resolved', 'closed']
const STATUS_LABEL: Record<TicketStatus, string> = {
  open: 'Open',
  in_progress: 'In progress',
  resolved: 'Resolved',
  closed: 'Closed',
}
const STATUS_BADGE: Record<TicketStatus, string> = {
  open: 'text-sky-300 bg-sky-500/15',
  in_progress: 'text-amber-300 bg-amber-500/15',
  resolved: 'text-emerald-300 bg-emerald-500/15',
  closed: 'text-slate-400 bg-slate-700/40',
}

function SeverityBadge({ sev }: { sev: number }) {
  const m = SEVERITY[sev] ?? SEVERITY[0]
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${m.cls}`}>{m.label}</span>
}

function duration(fromISO: string, toISO: string): string {
  const ms = new Date(toISO).getTime() - new Date(fromISO).getTime()
  if (ms < 0) return '—'
  const m = Math.floor(ms / 60000)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${m % 60}m`
  return `${Math.floor(h / 24)}d ${h % 24}h`
}

export default function Tickets({
  me,
  prefill,
  onPrefillConsumed,
}: {
  me: Me
  prefill: NewTicketInput | null
  onPrefillConsumed: () => void
}) {
  const canManage = can(me, 'manage_tickets')
  const [tickets, setTickets] = useState<Ticket[]>([])
  const [filter, setFilter] = useState<'' | TicketStatus>('')
  const [error, setError] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showNew, setShowNew] = useState(false)
  const [newInput, setNewInput] = useState<NewTicketInput>({ title: '', description: '', severity: 2 })

  const load = () => {
    fetchTickets(filter)
      .then(setTickets)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(load, [filter])

  // Prefill from an alert → open the New ticket form.
  useEffect(() => {
    if (prefill) {
      setNewInput({ severity: 2, description: '', ...prefill })
      setShowNew(true)
      onPrefillConsumed()
    }
  }, [prefill, onPrefillConsumed])

  const submitNew = async () => {
    setError('')
    try {
      const t = await createTicket(newInput)
      setShowNew(false)
      setNewInput({ title: '', description: '', severity: 2 })
      load()
      setSelectedId(t.id)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const counts = STATUSES.reduce<Record<string, number>>((acc, s) => {
    acc[s] = tickets.filter((t) => t.status === s).length
    return acc
  }, {})

  return (
    <div className="mx-auto max-w-5xl px-8 py-8">
      <header className="mb-6 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Tickets</h1>
          <p className="mt-1 text-sm text-slate-500">Tier-2 DFIR case management · open → in progress → resolved → closed</p>
        </div>
        {canManage && (
          <button
            onClick={() => {
              setNewInput({ title: '', description: '', severity: 2 })
              setShowNew(true)
            }}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400"
          >
            + New ticket
          </button>
        )}
      </header>

      {/* Status filter */}
      <div className="mb-4 flex flex-wrap gap-2 text-sm">
        <button
          onClick={() => setFilter('')}
          className={`rounded-lg px-3 py-1.5 ${filter === '' ? 'bg-indigo-500/10 text-indigo-300' : 'text-slate-400 hover:bg-slate-800'}`}
        >
          All ({tickets.length})
        </button>
        {STATUSES.map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`rounded-lg px-3 py-1.5 ${filter === s ? 'bg-indigo-500/10 text-indigo-300' : 'text-slate-400 hover:bg-slate-800'}`}
          >
            {STATUS_LABEL[s]}
            {filter === '' && counts[s] ? <span className="ml-1 text-slate-600">{counts[s]}</span> : ''}
          </button>
        ))}
      </div>

      {error && <p className="mb-4 text-sm text-rose-400">{error}</p>}

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2 font-medium">Title</th>
              <th className="px-4 py-2 font-medium">Severity</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Assignee</th>
              <th className="px-4 py-2 font-medium">Created</th>
              <th className="px-4 py-2 font-medium">Resolve time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {tickets.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  No tickets. Raise one from an alert on the Dashboard, or create a new one.
                </td>
              </tr>
            )}
            {tickets.map((t) => (
              <tr key={t.id} className="cursor-pointer hover:bg-slate-800/40" onClick={() => setSelectedId(t.id)}>
                <td className="px-4 py-2 font-medium text-slate-200">{t.title}</td>
                <td className="px-4 py-2"><SeverityBadge sev={t.severity} /></td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${STATUS_BADGE[t.status]}`}>
                    {STATUS_LABEL[t.status]}
                  </span>
                </td>
                <td className="px-4 py-2 text-slate-400">{t.assignee || <span className="text-slate-600">unassigned</span>}</td>
                <td className="px-4 py-2 text-slate-400">{new Date(t.created_at).toLocaleString('en-US')}</td>
                <td className="px-4 py-2 text-slate-400">
                  {t.resolved_at ? duration(t.created_at, t.resolved_at) : <span className="text-slate-600">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showNew && (
        <NewTicketModal
          value={newInput}
          onChange={setNewInput}
          onClose={() => setShowNew(false)}
          onSubmit={submitNew}
        />
      )}
      {selectedId && (
        <TicketDetail
          id={selectedId}
          me={me}
          canManage={canManage}
          onClose={() => setSelectedId(null)}
          onChanged={load}
        />
      )}
    </div>
  )
}

function NewTicketModal({
  value,
  onChange,
  onClose,
  onSubmit,
}: {
  value: NewTicketInput
  onChange: (v: NewTicketInput) => void
  onClose: () => void
  onSubmit: () => void
}) {
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    await onSubmit()
    setBusy(false)
  }
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h2 className="mb-4 text-lg font-semibold text-white">New ticket</h2>
        <div className="space-y-3">
          <input
            value={value.title}
            onChange={(e) => onChange({ ...value, title: e.target.value })}
            placeholder="Title"
            autoFocus
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          <textarea
            value={value.description ?? ''}
            onChange={(e) => onChange({ ...value, description: e.target.value })}
            placeholder="Report / case details…"
            rows={6}
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          <div className="flex gap-3">
            <label className="flex-1">
              <span className="mb-1 block text-xs font-medium text-slate-400">Severity</span>
              <select
                value={value.severity ?? 2}
                onChange={(e) => onChange({ ...value, severity: Number(e.target.value) })}
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
              >
                {[0, 1, 2, 3, 4].map((s) => (
                  <option key={s} value={s}>
                    {SEVERITY[s].label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex-1">
              <span className="mb-1 block text-xs font-medium text-slate-400">Assignee (optional)</span>
              <input
                value={value.assignee ?? ''}
                onChange={(e) => onChange({ ...value, assignee: e.target.value })}
                placeholder="username"
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
              />
            </label>
          </div>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={busy || !value.title}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50"
          >
            {busy ? 'Creating…' : 'Create ticket'}
          </button>
        </div>
      </div>
    </div>
  )
}

function TicketDetail({
  id,
  me,
  canManage,
  onClose,
  onChanged,
}: {
  id: string
  me: Me
  canManage: boolean
  onClose: () => void
  onChanged: () => void
}) {
  const [ticket, setTicket] = useState<Ticket | null>(null)
  const [comments, setComments] = useState<TicketComment[]>([])
  const [comment, setComment] = useState('')
  const [error, setError] = useState('')

  const load = () => {
    fetchTicket(id)
      .then((d) => {
        setTicket(d.ticket)
        setComments(d.comments)
      })
      .catch((e) => setError((e as Error).message))
  }
  useEffect(load, [id])

  const patch = async (p: Partial<{ status: TicketStatus; assignee: string; severity: number }>) => {
    setError('')
    try {
      await updateTicket(id, p)
      load()
      onChanged()
    } catch (e) {
      setError((e as Error).message)
    }
  }
  const postComment = async () => {
    if (!comment.trim()) return
    setError('')
    try {
      await addTicketComment(id, comment.trim())
      setComment('')
      load()
      onChanged()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {!ticket ? (
          <p className="text-slate-500">Loading…</p>
        ) : (
          <>
            <div className="mb-3 flex items-start justify-between gap-4">
              <h2 className="text-lg font-semibold text-white">{ticket.title}</h2>
              <button onClick={onClose} className="text-slate-500 hover:text-slate-300">✕</button>
            </div>

            <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span className={`rounded px-1.5 py-0.5 font-medium ${STATUS_BADGE[ticket.status]}`}>{STATUS_LABEL[ticket.status]}</span>
              <SeverityBadge sev={ticket.severity} />
              <span>· opened by {ticket.created_by}</span>
              <span>· {new Date(ticket.created_at).toLocaleString('en-US')}</span>
              {ticket.resolved_at && <span>· resolved in {duration(ticket.created_at, ticket.resolved_at)}</span>}
            </div>

            {(ticket.source_ip || ticket.rule_id) && (
              <div className="mb-3 flex flex-wrap gap-2 text-xs">
                {ticket.source_ip && <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-slate-300">{ticket.source_ip}</span>}
                {ticket.rule_id && <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">{ticket.rule_id}</span>}
              </div>
            )}

            {ticket.description && (
              <pre className="mb-4 whitespace-pre-wrap rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-300">
                {ticket.description}
              </pre>
            )}

            {canManage && (
              <div className="mb-5 space-y-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-medium text-slate-500">Status:</span>
                  {STATUSES.map((s) => (
                    <button
                      key={s}
                      onClick={() => patch({ status: s })}
                      disabled={ticket.status === s}
                      className={`rounded-md border px-2 py-1 text-xs transition-colors ${
                        ticket.status === s
                          ? 'border-indigo-500 bg-indigo-500/10 text-indigo-300'
                          : 'border-slate-700 text-slate-300 hover:bg-slate-800'
                      }`}
                    >
                      {STATUS_LABEL[s]}
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-medium text-slate-500">Assignee:</span>
                  <span className="text-xs text-slate-300">{ticket.assignee || 'unassigned'}</span>
                  {ticket.assignee !== me.username && (
                    <button
                      onClick={() => patch({ assignee: me.username })}
                      className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
                    >
                      Assign to me
                    </button>
                  )}
                  {ticket.assignee && (
                    <button
                      onClick={() => patch({ assignee: '' })}
                      className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:bg-slate-800"
                    >
                      Unassign
                    </button>
                  )}
                  <span className="ml-2 text-xs font-medium text-slate-500">Severity:</span>
                  <select
                    value={ticket.severity}
                    onChange={(e) => patch({ severity: Number(e.target.value) })}
                    className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1 text-xs outline-none focus:border-indigo-500"
                  >
                    {[0, 1, 2, 3, 4].map((s) => (
                      <option key={s} value={s}>
                        {SEVERITY[s].label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            )}

            {/* Case notes */}
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">Case notes ({comments.length})</h3>
            <div className="space-y-2">
              {comments.length === 0 && <p className="text-xs text-slate-600">No notes yet.</p>}
              {comments.map((c) => (
                <div key={c.id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="font-medium text-slate-300">{c.author}</span>
                    <span className="text-slate-600">{new Date(c.created_at).toLocaleString('en-US')}</span>
                  </div>
                  <p className="whitespace-pre-wrap text-sm text-slate-300">{c.body}</p>
                </div>
              ))}
            </div>

            {canManage && (
              <div className="mt-3 flex gap-2">
                <input
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && postComment()}
                  placeholder="Add a case note…"
                  className="flex-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
                />
                <button
                  onClick={postComment}
                  disabled={!comment.trim()}
                  className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50"
                >
                  Add
                </button>
              </div>
            )}
            {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
          </>
        )}
      </div>
    </div>
  )
}
