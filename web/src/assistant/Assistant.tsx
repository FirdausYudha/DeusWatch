import { useEffect, useRef, useState } from 'react'
import {
  addWhitelist, askAssistant, banIP, can, fetchAssistantStatus,
  type AssistantProposal, type ChatTurn, type Me,
} from '../lib/api'
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
  const perm = p.kind === 'ban' ? 'execute_block' : 'manage_settings'
  const allowed = can(me, perm)

  const confirm = async () => {
    setBusy(true)
    setErr('')
    try {
      if (p.kind === 'ban') {
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
        {p.kind === 'ban' ? 'Block an IP' : 'Add to whitelist'}
      </p>
      <p className="mt-1 break-all font-mono text-[13.5px] text-fg">{p.target}</p>
      <p className="mt-0.5 text-[12.5px] text-muted">
        {p.kind === 'ban'
          ? `Duration: ${duration}.`
          : 'The response engine will never ban anything matching this.'}
      </p>
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
          {busy ? 'Applying…' : p.kind === 'ban' ? 'Confirm block' : 'Confirm whitelist'}
        </button>
      )}
      {err && <p className="mt-2 text-[12.5px] text-critical">{err}</p>}
    </div>
  )
}

function greeting(name: string): string {
  const h = new Date().getHours()
  const part = h < 11 ? 'Good morning' : h < 15 ? 'Good afternoon' : h < 19 ? 'Good evening' : 'Working late'
  return `${part}, ${name}. Ask me about the last 24 hours, a source IP, or the health of the platform itself.`
}

// Msg is a rendered turn. It carries the optional proposal card, which is view state only: the
// history sent back to the model is role + content, so a card never becomes part of the prompt.
type Msg = ChatTurn & { proposal?: AssistantProposal }

export default function Assistant({ me }: { me: Me }) {
  const [enabled, setEnabled] = useState(false)
  const [open, setOpen] = useState(false)
  const [turns, setTurns] = useState<Msg[]>([])
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const endRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  // Reading replies aloud is remembered; the microphone is not. Synthesis stays in the browser,
  // while recognition streams audio to Google in Chrome, and a setting that silently reopens a
  // microphone on the next login is not a default worth persisting on a security console.
  const [speakReplies, setSpeakReplies] = usePersistedState('assistant.speak', false)
  const speaker = useSpeaker()
  const mic = useDictation(setDraft)

  // Ask once on mount. A deployment that never enabled the assistant shows no launcher at all,
  // rather than a button that explains itself only after being clicked.
  useEffect(() => {
    fetchAssistantStatus()
      .then((s) => setEnabled(s.enabled))
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

  const send = async (text: string) => {
    const msg = text.trim()
    if (!msg || busy) return
    setError('')
    setDraft('')
    mic.stop() // nothing left to dictate into; holding the microphone open past Send is rude
    // The user's turn is appended before the call so the conversation never looks frozen, and the
    // history sent along is the state BEFORE this message (the server appends it as the new turn).
    const history = turns.map(({ role, content }) => ({ role, content }))
    setTurns([...turns, { role: 'user', content: msg }])
    setBusy(true)
    try {
      const { reply, proposal } = await askAssistant(msg, history)
      setTurns((t) => [...t, { role: 'assistant', content: reply, proposal }])
      if (speakReplies) speaker.speak(reply)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
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
            {speaker.supported && (
              <button
                onClick={() => {
                  if (speakReplies) speaker.cancel()
                  setSpeakReplies(!speakReplies)
                }}
                title={speakReplies ? 'Stop reading replies aloud' : 'Read replies aloud'}
                aria-label={speakReplies ? 'Stop reading replies aloud' : 'Read replies aloud'}
                aria-pressed={speakReplies}
                className={`ml-auto rounded-[8px] p-1.5 transition-colors hover:bg-surface-2 ${
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
              className={`rounded-[8px] px-2 py-1 text-dim transition-colors hover:bg-surface-2 hover:text-fg ${
                speaker.supported ? '' : 'ml-auto'
              }`}
            >
              ✕
            </button>
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
              <div key={i} className="space-y-2">
                <div className={t.role === 'user' ? 'flex justify-end' : ''}>
                  <div
                    className={`max-w-[92%] whitespace-pre-wrap rounded-[10px] px-3 py-2 text-[13.5px] ${
                      t.role === 'user' ? 'bg-accent-soft text-accent' : 'bg-surface-2 text-fg'
                    }`}
                  >
                    {t.content}
                  </div>
                </div>
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
