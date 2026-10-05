import { useEffect, useRef, useState } from 'react'
import {
  addWhitelist, askAssistant, banIP, can, clearAssistantHistory, createRule,
  deleteAssistantMessage, fetchAssistantHistory, fetchAssistantStatus,
  type AssistantProposal, type ChatTurn, type Me,
} from '../lib/api'
import type { AssistantQuery } from '../lib/api'
import { usePersistedState } from '../lib/usePersistedState'
import { useDictation, useSpeaker } from './useSpeech'

// Conversational assistant (ADR 0003, phase 1): a launcher and a slide-over panel, mounted beside
// every view. Read-only by construction, so the panel says so rather than letting an operator
// discover it the hard way by asking for a ban that never happens.

const SUGGESTIONS = [
  'What happened in the last 24 hours?',
  'Which source IP should I look at first?',
  'Is anything wrong with DeusWatch itself?',
]

// Shown under the suggestions, because the command phrasings are parsed literally and an operator
// has no way to guess that from a chat box that otherwise accepts free text.
const COMMAND_HINT = 'To act, say it with an address: “block 45.134.26.9 for 2 hours” or “whitelist 10.0.0.0/8”. You confirm before anything happens.'

// ProposalCard is the whole of the assistant's write capability: it shows exactly what will happen
// and calls the ORDINARY ban/whitelist endpoint under the operator's own session when they confirm.
// The assistant's own API has no write path at all, so the permission enforced here is the real
// one (execute_block / manage_settings), not the weaker view_dashboard that lets someone chat.
function ProposalCard({ me, p, onDone }: { me: Me; p: AssistantProposal; onDone: (msg: string) => void }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [done, setDone] = useState(false)
  const perm = p.kind === 'ban' ? 'execute_block' : p.kind === 'rule' ? 'manage_rules' : 'manage_settings'
  const allowed = can(me, perm)

  const confirm = async () => {
    setBusy(true)
    setErr('')
    try {
      if (p.kind === 'rule') {
        await createRule(p.target, p.yaml ?? '')
        onDone(`Saved the rule "${p.target}". It is enabled and will apply on the worker's next reload.`)
      } else if (p.kind === 'ban') {
        await banIP(p.target, p.minutes)
        onDone(`Blocked ${p.target}.`)
      } else {
        await addWhitelist(p.target, 'added from the assistant', 'internal')
        onDone(`Whitelisted ${p.target}.`)
      }
      setDone(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const duration = p.minutes > 0 ? `${p.minutes} minute${p.minutes === 1 ? '' : 's'}` : 'per the configured ban ladder'

  return (
    <div className="rounded-[10px] border border-border bg-surface-2 p-3">
      <p className="text-[12px] font-semibold uppercase tracking-wide text-dim">
        {p.kind === 'ban' ? 'Block an IP' : p.kind === 'rule' ? 'New detection rule' : 'Add to whitelist'}
      </p>
      <p className="mt-1 break-all font-mono text-[13.5px] text-fg">{p.target}</p>
      {p.kind === 'rule' ? (
        <>
          {/* The whole rule, not a summary. The operator is approving code that will run against
              every event, and nobody can approve code they have not been shown. */}
          <pre className="mt-1.5 max-h-72 overflow-auto rounded-[6px] bg-bg p-2 font-mono text-[11.5px] leading-relaxed text-muted">
            {p.yaml}
          </pre>
          <p className="mt-1 text-[12px] text-dim">
            Parsed by the detection engine already. Read it before saving: a keyword that is an
            ordinary word will fire all day.
          </p>
        </>
      ) : (
        <p className="mt-0.5 text-[12.5px] text-muted">
          {p.kind === 'ban'
            ? `Duration: ${duration}.`
            : 'The response engine will never ban anything matching this.'}
        </p>
      )}
      {done ? (
        <p className="mt-2 text-[12.5px] text-success">Applied.</p>
      ) : !allowed ? (
        // Say which permission is missing rather than showing a button that fails on click.
        <p className="mt-2 text-[12.5px] text-dim">
          You do not have the <span className="font-mono">{perm}</span> permission, so this needs an admin.
        </p>
      ) : (
        <button
          onClick={confirm}
          disabled={busy}
          className="mt-2 rounded-[8px] bg-accent px-3 py-1.5 text-[12.5px] font-semibold text-white transition-opacity disabled:opacity-40"
        >
          {busy ? 'Applying…' : p.kind === 'ban' ? 'Confirm block' : p.kind === 'rule' ? 'Save rule' : 'Confirm whitelist'}
        </button>
      )}
      {err && <p className="mt-2 text-[12.5px] text-critical">{err}</p>}
    </div>
  )
}

// The opening line, before any model call. It stays local because a greeting that costs a round
// trip and three seconds is worse than one that is instant, but the wording rotates: an identical
// sentence every single time is most of what made the panel feel like a vending machine. Once the
// conversation starts, the model takes over and it knows the name and the clock.
const OPENERS = [
  'What are we looking at?',
  'Anything you want me to check?',
  'What do you need?',
  'Where do you want to start?',
]

// MaxHistoryResultChars caps how much of a query result is carried back into the conversation.
// Fifty rows of wide columns would crowd out the prompt it is meant to inform.
const MAX_HISTORY_RESULT = 1500

// historyText is what a turn contributes to the NEXT request's history.
//
// A query result is rendered as a table for the operator and, separately, folded back into the
// conversation as text so the model can reason about it on the following turn. That is what makes
// "so which of those is worst?" answerable: the rows are in the context by then.
//
// It is done this way rather than by calling the model a second time with the rows, because on a
// local CPU a second call costs minutes. The analysis happens when the operator actually asks for
// it, and costs nothing until then.
function historyText(t: Msg): string {
  if (!t.query || t.query.error || !t.query.rows?.length) return t.content
  const head = (t.query.columns ?? []).join(' | ')
  const body = t.query.rows.map((r) => r.join(' | ')).join('\n')
  let table = `${head}\n${body}`
  if (table.length > MAX_HISTORY_RESULT) {
    table = `${table.slice(0, MAX_HISTORY_RESULT)}\n...(truncated)`
  }
  return `${t.content}\n\n[Query result, ${t.query.rows.length} row(s)]\n${table}`
}

// QueryResult shows the SQL and the rows the server actually returned.
//
// The SQL is shown, not hidden, and that is the point: the operator is reading data the model asked
// for, so they need to see what was asked. A result they cannot check is a number they have to take
// on trust from a component that has already invented hostnames.
function QueryResult({ q }: { q: AssistantQuery }) {
  const [showSQL, setShowSQL] = useState(false)
  return (
    <div className="rounded-[10px] border border-border bg-surface-2 p-3">
      <div className="flex items-center gap-2">
        <p className="text-[12px] font-semibold uppercase tracking-wide text-dim">Database query</p>
        <button
          onClick={() => setShowSQL(!showSQL)}
          className="ml-auto rounded-[6px] border border-border px-2 py-0.5 text-[11.5px] text-dim transition-colors hover:bg-surface hover:text-fg"
        >
          {showSQL ? 'Hide SQL' : 'Show SQL'}
        </button>
      </div>
      {showSQL && (
        <pre className="mt-2 max-h-40 overflow-auto rounded-[6px] bg-bg p-2 font-mono text-[11px] leading-relaxed text-muted">
          {q.sql}
        </pre>
      )}
      {q.error ? (
        <p className="mt-2 text-[12.5px] text-critical">{q.error}</p>
      ) : !q.rows || q.rows.length === 0 ? (
        <p className="mt-2 text-[12.5px] text-muted">No rows matched.</p>
      ) : (
        <>
          <div className="mt-2 max-h-72 overflow-auto rounded-[6px] border border-border">
            <table className="w-full text-left text-[11.5px]">
              <thead className="sticky top-0 bg-surface">
                <tr>
                  {(q.columns ?? []).map((c) => (
                    <th key={c} className="whitespace-nowrap px-2 py-1.5 font-semibold text-dim">{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {q.rows.map((row, i) => (
                  <tr key={i} className="border-t border-border">
                    {row.map((cell, j) => (
                      <td key={j} className="px-2 py-1 align-top font-mono text-fg">
                        <div className="max-w-[16rem] truncate" title={cell}>{cell || '-'}</div>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-1.5 text-[11.5px] text-dim">
            {q.rows.length} row{q.rows.length === 1 ? '' : 's'}
            {q.capped ? ' (capped)' : ''}
            {q.ms !== undefined ? ` in ${q.ms} ms` : ''}. These come straight from the database, not
            from the model.
          </p>
        </>
      )}
    </div>
  )
}

function greeting(name: string): string {
  const h = new Date().getHours()
  const part =
    h < 5 ? 'Still up' : h < 11 ? 'Morning' : h < 15 ? 'Afternoon' : h < 19 ? 'Evening' : 'Working late'
  return `${part}, ${name}. ${OPENERS[Math.floor(Math.random() * OPENERS.length)]}`
}

// Msg is a rendered turn. It carries the optional proposal card, which is view state only: the
// history sent back to the model is role + content, so a card never becomes part of the prompt.
type Msg = ChatTurn & {
  proposal?: AssistantProposal
  query?: AssistantQuery
  /** Server id, present once the turn has been stored. Absent on a turn still in flight. */
  id?: number
}

export default function Assistant({ me, onEditPersona }: { me: Me; onEditPersona?: () => void }) {
  const [enabled, setEnabled] = useState(false)
  const [open, setOpen] = useState(false)
  const [turns, setTurns] = useState<Msg[]>([])
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  // Index of the turn being edited, and its working text. Index rather than id, because a turn
  // still in flight has no id yet and must still be editable once it lands.
  const [editing, setEditing] = useState<number | null>(null)
  const [editDraft, setEditDraft] = useState('')
  const endRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  // Reading replies aloud is remembered; the microphone is not. Synthesis stays in the browser,
  // while recognition streams audio to Google in Chrome, and a setting that silently reopens a
  // microphone on the next login is not a default worth persisting on a security console.
  const [speakReplies, setSpeakReplies] = usePersistedState('assistant.speak', false)
  // Which voice and how fast are per-viewer taste, and the available voices differ by OS, so both
  // are remembered in the browser rather than stored server-side.
  const [voiceURI, setVoiceURI] = usePersistedState('assistant.voice', '')
  const [rate, setRate] = usePersistedState('assistant.rate', 0.95)
  const speaker = useSpeaker(voiceURI, rate)
  const mic = useDictation(setDraft)

  // Ask once on mount. A deployment that never enabled the assistant shows no launcher at all,
  // rather than a button that explains itself only after being clicked.
  useEffect(() => {
    fetchAssistantStatus()
      .then((s) => {
        setEnabled(s.enabled)
        if (!s.enabled) return
        // Stored turns carry no proposal card or result table: those are live views of state that
        // may have changed since, and re-rendering a stale "Confirm block" button would invite the
        // operator to approve something they already approved.
        return fetchAssistantHistory().then((rows) =>
          setTurns(rows.map((r) => ({ id: r.id, role: r.role, content: r.content }))),
        )
      })
      .catch(() => setEnabled(false))
  }, [])

  useEffect(() => {
    if (open) {
      endRef.current?.scrollIntoView({ behavior: 'smooth' })
      inputRef.current?.focus()
    }
  }, [open, turns, busy])

  // Closing the panel must silence it and release the microphone. A security console that keeps
  // talking, or keeps listening, after you dismissed it is the kind of thing operators disable
  // permanently and never turn back on.
  const close = () => {
    mic.stop()
    speaker.cancel()
    setOpen(false)
  }

  if (!enabled) return null

  // `base` is the conversation to continue from, defaulting to everything so far. An edit passes a
  // shorter one: the turns up to the message being rewritten.
  const send = async (text: string, base?: Msg[]) => {
    const msg = text.trim()
    if (!msg || busy) return
    const prior = base ?? turns
    setError('')
    setDraft('')
    mic.stop() // nothing left to dictate into; holding the microphone open past Send is rude
    // The user's turn is appended before the call so the conversation never looks frozen, and the
    // history sent along is the state BEFORE this message (the server appends it as the new turn).
    const history = prior.map((t) => ({ role: t.role, content: historyText(t) }))
    setTurns([...prior, { role: 'user', content: msg }])
    setBusy(true)
    try {
      const { reply, proposal, query } = await askAssistant(msg, history)
      setTurns((t) => [...t, { role: 'assistant', content: reply, proposal, query }])
      if (speakReplies) speaker.speak(reply)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  // Removing one turn leaves a question with no answer, or an answer with no question. Both read as
  // the assistant having lost the thread, so a turn is deleted together with the one it pairs with.
  const removeTurn = async (i: number) => {
    const t = turns[i]
    if (!t || busy) return
    const partner = t.role === 'user' ? turns[i + 1] : turns[i - 1]
    const keep = turns.filter((_, j) => j !== i && !(partner && j === (t.role === 'user' ? i + 1 : i - 1)))
    setTurns(keep)
    try {
      for (const m of [t, partner]) {
        if (m?.id) await deleteAssistantMessage(m.id)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  // Editing a question discards everything after it before asking again. Keeping the old answer
  // under a rewritten question would show the assistant saying something it never said.
  const startEdit = (i: number) => {
    setEditing(i)
    setEditDraft(turns[i].content)
  }

  const commitEdit = async () => {
    if (editing === null || busy) return
    const i = editing
    const text = editDraft.trim()
    const original = turns[i]
    setEditing(null)
    if (!text || text === original.content) return
    const base = turns.slice(0, i)
    try {
      if (original.id) await deleteAssistantMessage(original.id, true)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      return // the server still holds the old turns; asking now would duplicate them
    }
    await send(text, base)
  }

  const clearAll = async () => {
    setTurns([])
    setEditing(null)
    try {
      await clearAssistantHistory()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <>
      {!open && (
        <button
          onClick={() => setOpen(true)}
          title="Ask the assistant"
          aria-label="Ask the assistant"
          className="fixed bottom-5 right-5 z-40 flex h-12 w-12 items-center justify-center rounded-full bg-accent text-white shadow-lg transition-transform hover:scale-105"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M21 11.5a8.4 8.4 0 0 1-9 8.4L3 21l1.1-4.6A8.4 8.4 0 1 1 21 11.5zM8 11h.01M12 11h.01M16 11h.01"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
      )}

      {open && (
        <aside
          role="dialog"
          aria-label="DeusWatch assistant"
          className="fixed inset-y-0 right-0 z-40 flex w-full max-w-[26rem] flex-col border-l border-border bg-surface shadow-2xl"
        >
          <header className="flex h-[60px] flex-none items-center gap-2 border-b border-border px-4">
            <span className="text-[14.5px] font-semibold text-fg">Assistant</span>
            {/* It stopped being read-only the moment it could prepare a block, so the badge that
                used to say so is gone. The honest version of that promise is in the footer. */}
            {/* One ml-auto on the group, not one per button: with three optional controls, deciding
                which of them is currently first is a bug waiting to happen. */}
            <div className="ml-auto flex items-center gap-1">
            {/* The persona is what you are talking to, so the way to change it belongs here rather
                than only in Settings. Hidden without manage_settings: an operator who cannot edit
                it gains nothing from a link to a read-only field. */}
            {turns.length > 0 && (
              <button
                onClick={() => void clearAll()}
                title="Clear this conversation"
                aria-label="Clear this conversation"
                className="rounded-[8px] p-1.5 text-dim transition-colors hover:bg-surface-2 hover:text-fg"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M3 3v6h6M3.5 13a9 9 0 1 0 2.2-6.4L3 9" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
            )}
            {onEditPersona && can(me, 'manage_settings') && (
              <button
                onClick={() => {
                  // The hash is what makes the panel on the other end open itself and scroll into
                  // view, so this lands on the field rather than the top of a long page.
                  window.location.hash = 'assistant-persona'
                  close()
                  onEditPersona()
                }}
                title="Edit the assistant's persona"
                aria-label="Edit the assistant's persona"
                className="rounded-[8px] p-1.5 text-dim transition-colors hover:bg-surface-2 hover:text-fg"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path
                    d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </button>
            )}
            {speaker.supported && (
              <button
                onClick={() => {
                  if (speakReplies) speaker.cancel()
                  setSpeakReplies(!speakReplies)
                }}
                title={speakReplies ? 'Stop reading replies aloud' : 'Read replies aloud'}
                aria-label={speakReplies ? 'Stop reading replies aloud' : 'Read replies aloud'}
                aria-pressed={speakReplies}
                className={`rounded-[8px] p-1.5 transition-colors hover:bg-surface-2 ${
                  speakReplies ? 'text-accent' : 'text-dim hover:text-fg'
                }`}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M11 5 6 9H3v6h3l5 4z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
                  {speakReplies ? (
                    <path d="M15.5 8.5a5 5 0 0 1 0 7M18.5 5.5a9 9 0 0 1 0 13" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
                  ) : (
                    <path d="M16 9l5 6M21 9l-5 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
                  )}
                </svg>
              </button>
            )}
            <button
              onClick={close}
              aria-label="Close assistant"
              className="rounded-[8px] px-2 py-1 text-dim transition-colors hover:bg-surface-2 hover:text-fg"
            >
              ✕
            </button>
            </div>
          </header>

          <div className="flex-1 space-y-3 overflow-y-auto p-4">
            {turns.length === 0 && (
              <>
                <p className="text-[13.5px] text-muted">{greeting(me.username)}</p>
                <div className="flex flex-col gap-1.5 pt-1">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      onClick={() => send(s)}
                      className="rounded-[8px] border border-border px-3 py-2 text-left text-[13px] text-muted transition-colors hover:bg-surface-2 hover:text-fg"
                    >
                      {s}
                    </button>
                  ))}
                </div>
                <p className="pt-1 text-[12px] text-dim">{COMMAND_HINT}</p>
              </>
            )}
            {turns.map((t, i) => (
              // `group` so the controls stay out of the way until the turn is hovered: a delete
              // button sitting permanently beside every message is an invitation to misclick.
              <div key={t.id ?? `pending-${i}`} className="group space-y-2">
                {editing === i ? (
                  <div className="rounded-[10px] border border-accent bg-bg p-2">
                    <textarea
                      value={editDraft}
                      onChange={(e) => setEditDraft(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault()
                          void commitEdit()
                        }
                        if (e.key === 'Escape') setEditing(null)
                      }}
                      rows={2}
                      autoFocus
                      className="w-full resize-none bg-transparent text-[13.5px] text-fg focus:outline-none"
                    />
                    <div className="mt-1 flex items-center gap-2">
                      <p className="text-[11.5px] text-dim">Everything after this is discarded and asked again.</p>
                      <button
                        onClick={() => void commitEdit()}
                        className="ml-auto rounded-[6px] bg-accent px-2 py-0.5 text-[11.5px] font-semibold text-white"
                      >
                        Ask again
                      </button>
                      <button
                        onClick={() => setEditing(null)}
                        className="rounded-[6px] border border-border px-2 py-0.5 text-[11.5px] text-muted hover:text-fg"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className={`flex items-start gap-1.5 ${t.role === 'user' ? 'justify-end' : ''}`}>
                    {t.role === 'user' && (
                      <div className="flex shrink-0 gap-1 pt-1.5 opacity-0 transition-opacity group-hover:opacity-100">
                        <button
                          onClick={() => startEdit(i)}
                          disabled={busy}
                          title="Edit and ask again"
                          aria-label="Edit and ask again"
                          className="rounded-[6px] p-1 text-dim hover:bg-surface-2 hover:text-fg disabled:opacity-40"
                        >
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                            <path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                          </svg>
                        </button>
                        <button
                          onClick={() => void removeTurn(i)}
                          disabled={busy}
                          title="Delete this exchange"
                          aria-label="Delete this exchange"
                          className="rounded-[6px] p-1 text-dim hover:bg-surface-2 hover:text-critical disabled:opacity-40"
                        >
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                            <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                          </svg>
                        </button>
                      </div>
                    )}
                    <div
                      className={`max-w-[92%] whitespace-pre-wrap rounded-[10px] px-3 py-2 text-[13.5px] ${
                        t.role === 'user' ? 'bg-accent-soft text-accent' : 'bg-surface-2 text-fg'
                      }`}
                    >
                      {t.content}
                    </div>
                    {t.role === 'assistant' && (
                      <button
                        onClick={() => void removeTurn(i)}
                        disabled={busy}
                        title="Delete this exchange"
                        aria-label="Delete this exchange"
                        className="mt-1.5 shrink-0 rounded-[6px] p-1 text-dim opacity-0 transition-opacity hover:bg-surface-2 hover:text-critical group-hover:opacity-100 disabled:opacity-40"
                      >
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                          <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      </button>
                    )}
                  </div>
                )}
                {t.query && <QueryResult q={t.query} />}
                {t.proposal && (
                  <ProposalCard
                    me={me}
                    p={t.proposal}
                    onDone={(m) => setTurns((prev) => [...prev, { role: 'assistant', content: m }])}
                  />
                )}
              </div>
            ))}
            {busy && <p className="text-[13px] text-dim">thinking…</p>}
            {error && (
              <p className="rounded-[8px] border border-critical/40 bg-critical/10 px-3 py-2 text-[13px] text-critical">
                {error}
              </p>
            )}
            <div ref={endRef} />
          </div>

          {speakReplies && speaker.voices.length > 0 && (
            // Only while reading aloud is on. The default voice is a guess ranked by name and
            // network-vs-local; whether it actually sounds human is something only the person
            // listening can judge, so they get to pick.
            <div className="flex-none items-center gap-2 border-t border-border px-3 py-2 text-[11.5px] text-dim sm:flex">
              <select
                value={voiceURI || speaker.voices[0]?.voiceURI || ''}
                onChange={(e) => {
                  setVoiceURI(e.target.value)
                  speaker.cancel()
                }}
                aria-label="Voice"
                className="min-w-0 flex-1 rounded-[6px] border border-border bg-bg px-2 py-1 text-[11.5px] text-fg focus:border-accent focus:outline-none"
              >
                {speaker.voices.map((v) => (
                  <option key={v.voiceURI} value={v.voiceURI}>{v.name} ({v.lang})</option>
                ))}
              </select>
              <input
                type="range"
                min={0.7}
                max={1.3}
                step={0.05}
                value={rate}
                onChange={(e) => setRate(Number(e.target.value))}
                aria-label="Speech rate"
                title={`Speed ${rate.toFixed(2)}x`}
                className="w-20 shrink-0 accent-[var(--color-accent)]"
              />
              <button
                onClick={() => (speaker.speaking ? speaker.cancel() : speaker.speak('Oke, suara ini yang akan kupakai. This is how I will sound.'))}
                className="shrink-0 rounded-[6px] border border-border px-2 py-1 transition-colors hover:bg-surface-2 hover:text-fg"
              >
                {speaker.speaking ? 'Stop' : 'Test'}
              </button>
            </div>
          )}

          <div className="flex-none border-t border-border p-3">
            <textarea
              ref={inputRef}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              // Enter sends, Shift+Enter breaks the line: this is a chat box, not a text editor.
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  void send(draft)
                }
              }}
              rows={2}
              placeholder="Ask about the last 24 hours…"
              className="w-full resize-none rounded-[8px] border border-border bg-bg px-3 py-2 text-[13.5px] text-fg placeholder:text-dim focus:border-accent focus:outline-none"
            />
            <div className="mt-2 flex items-center gap-2">
              {!mic.blocker && (
                <button
                  onClick={mic.toggle}
                  title={mic.listening ? 'Stop listening' : 'Dictate a message (audio goes to the browser vendor)'}
                  aria-label={mic.listening ? 'Stop listening' : 'Dictate a message'}
                  aria-pressed={mic.listening}
                  className={`rounded-[8px] border p-1.5 transition-colors ${
                    mic.listening
                      ? 'border-critical bg-critical/10 text-critical'
                      : 'border-border text-dim hover:bg-surface-2 hover:text-fg'
                  }`}
                >
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path
                      d="M12 3a3 3 0 0 1 3 3v6a3 3 0 0 1-6 0V6a3 3 0 0 1 3-3zM5 11a7 7 0 0 0 14 0M12 18v3"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </button>
              )}
              <p className="text-[11.5px] text-dim">
                {mic.listening
                  ? 'Listening… your browser sends this audio to its speech service. Check what it heard before sending.'
                  : 'Answers come from your own data. It never changes anything without your confirmation.'}
              </p>
              <button
                onClick={() => void send(draft)}
                disabled={busy || !draft.trim()}
                className="ml-auto rounded-[8px] bg-accent px-3 py-1.5 text-[13px] font-semibold text-white transition-opacity disabled:opacity-40"
              >
                Send
              </button>
            </div>
            {mic.error && <p className="mt-1.5 text-[11.5px] text-critical">{mic.error}</p>}
          </div>
        </aside>
      )}
    </>
  )
}
