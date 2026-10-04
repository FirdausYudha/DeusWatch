import { useEffect, useRef, useState } from 'react'
import { askAssistant, fetchAssistantStatus, type ChatTurn, type Me } from '../lib/api'

// Conversational assistant (ADR 0003, phase 1): a launcher and a slide-over panel, mounted beside
// every view. Read-only by construction, so the panel says so rather than letting an operator
// discover it the hard way by asking for a ban that never happens.

const SUGGESTIONS = [
  'What happened in the last 24 hours?',
  'Which source IP should I look at first?',
  'Is anything wrong with DeusWatch itself?',
]

function greeting(name: string): string {
  const h = new Date().getHours()
  const part = h < 11 ? 'Good morning' : h < 15 ? 'Good afternoon' : h < 19 ? 'Good evening' : 'Working late'
  return `${part}, ${name}. Ask me about the last 24 hours, a source IP, or the health of the platform itself.`
}

export default function Assistant({ me }: { me: Me }) {
  const [enabled, setEnabled] = useState(false)
  const [open, setOpen] = useState(false)
  const [turns, setTurns] = useState<ChatTurn[]>([])
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const endRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

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

  if (!enabled) return null

  const send = async (text: string) => {
    const msg = text.trim()
    if (!msg || busy) return
    setError('')
    setDraft('')
    // The user's turn is appended before the call so the conversation never looks frozen, and the
    // history sent along is the state BEFORE this message (the server appends it as the new turn).
    const history = turns
    setTurns([...history, { role: 'user', content: msg }])
    setBusy(true)
    try {
      const reply = await askAssistant(msg, history)
      setTurns((t) => [...t, { role: 'assistant', content: reply }])
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
            <span className="rounded-full bg-surface-2 px-2 py-0.5 text-[11.5px] text-dim">read-only</span>
            <button
              onClick={() => setOpen(false)}
              aria-label="Close assistant"
              className="ml-auto rounded-[8px] px-2 py-1 text-dim transition-colors hover:bg-surface-2 hover:text-fg"
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
              </>
            )}
            {turns.map((t, i) => (
              <div key={i} className={t.role === 'user' ? 'flex justify-end' : ''}>
                <div
                  className={`max-w-[92%] whitespace-pre-wrap rounded-[10px] px-3 py-2 text-[13.5px] ${
                    t.role === 'user' ? 'bg-accent-soft text-accent' : 'bg-surface-2 text-fg'
                  }`}
                >
                  {t.content}
                </div>
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
              <p className="text-[11.5px] text-dim">Answers come from your own data. It cannot change anything.</p>
              <button
                onClick={() => void send(draft)}
                disabled={busy || !draft.trim()}
                className="ml-auto rounded-[8px] bg-accent px-3 py-1.5 text-[13px] font-semibold text-white transition-opacity disabled:opacity-40"
              >
                Send
              </button>
            </div>
          </div>
        </aside>
      )}
    </>
  )
}
