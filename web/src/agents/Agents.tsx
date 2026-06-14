import { useEffect, useState } from 'react'
import {
  fetchAgents,
  createEnrollToken,
  revokeAgent,
  setAgentConfig,
  agentOnline,
  type AgentInfo,
  type Me,
} from '../lib/api'

function relative(ts: string | null): string {
  if (!ts) return 'never'
  const diff = Date.now() - new Date(ts).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return new Date(ts).toLocaleString('en-US')
}

function StatusBadge({ a }: { a: AgentInfo }) {
  if (a.revoked) return <span className="rounded px-1.5 py-0.5 text-xs font-medium text-rose-300 bg-rose-500/15">revoked</span>
  if (agentOnline(a)) return <span className="rounded px-1.5 py-0.5 text-xs font-medium text-emerald-300 bg-emerald-500/15">online</span>
  return <span className="rounded px-1.5 py-0.5 text-xs font-medium text-slate-400 bg-slate-700/40">offline</span>
}

export default function Agents({ me }: { me: Me }) {
  const isAdmin = me.role === 'admin'
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [error, setError] = useState('')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState<AgentInfo | null>(null)

  const load = () => {
    fetchAgents()
      .then(setAgents)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(() => {
    load()
    const t = setInterval(load, 15_000)
    return () => clearInterval(t)
  }, [])

  const genToken = async () => {
    setBusy(true)
    setError('')
    try {
      const { token } = await createEnrollToken()
      setToken(token)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const doRevoke = async (a: AgentInfo) => {
    if (!confirm(`Revoke agent "${a.name}"? Its connection will be rejected by the gateway.`)) return
    setError('')
    try {
      await revokeAgent(a.id)
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div className="mx-auto max-w-5xl px-8 py-8">
      <header className="mb-8 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Agents</h1>
          <p className="mt-1 text-sm text-slate-500">Registered agents, heartbeat status &amp; config push</p>
        </div>
        {isAdmin && (
          <button
            onClick={genToken}
            disabled={busy}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400 disabled:opacity-50"
          >
            {busy ? 'Creating…' : 'Create enrollment token'}
          </button>
        )}
      </header>

      {token && (
        <section className="mb-6 rounded-xl border border-indigo-500/30 bg-indigo-500/5 p-5">
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-indigo-300">Enrollment token (one-time, 1 hour)</h2>
          <code className="block break-all rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-emerald-300">{token}</code>
          <p className="mt-2 text-xs text-slate-500">
            On the agent host, run:&nbsp;
            <code className="text-slate-300">deuswatch-agent -enroll -token {token.slice(0, 8)}… -name &lt;name&gt; -manager http://host:8080</code>
          </p>
        </section>
      )}

      {error && <p className="mb-4 text-sm text-rose-400">{error}</p>}

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2 font-medium">Name</th>
              <th className="px-4 py-2 font-medium">OS</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Heartbeat</th>
              <th className="px-4 py-2 font-medium">Config</th>
              {isAdmin && <th className="px-4 py-2 font-medium">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {agents.length === 0 && (
              <tr>
                <td colSpan={isAdmin ? 6 : 5} className="px-4 py-8 text-center text-slate-500">
                  No agents yet. Create an enrollment token, then register an agent.
                </td>
              </tr>
            )}
            {agents.map((a) => (
              <tr key={a.id} className="hover:bg-slate-800/40">
                <td className="px-4 py-2 font-medium text-slate-200">{a.name}</td>
                <td className="px-4 py-2 text-slate-400">{a.os || '—'}</td>
                <td className="px-4 py-2"><StatusBadge a={a} /></td>
                <td className="px-4 py-2 text-slate-400">{relative(a.last_seen_at)}</td>
                <td className="px-4 py-2 text-slate-400">
                  v{a.config_version}
                  {a.sources && a.sources.length > 0 && (
                    <span className="ml-1 text-slate-600">({a.sources.length} source{a.sources.length > 1 ? 's' : ''})</span>
                  )}
                </td>
                {isAdmin && (
                  <td className="px-4 py-2">
                    <div className="flex gap-2">
                      <button
                        onClick={() => setEditing(a)}
                        className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
                      >
                        Config
                      </button>
                      {!a.revoked && (
                        <button
                          onClick={() => doRevoke(a)}
                          className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {editing && (
        <ConfigEditor
          agent={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            load()
          }}
        />
      )}
    </div>
  )
}

function ConfigEditor({
  agent,
  onClose,
  onSaved,
}: {
  agent: AgentInfo
  onClose: () => void
  onSaved: () => void
}) {
  const [text, setText] = useState(JSON.stringify(agent.sources ?? [], null, 2))
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const save = async () => {
    setBusy(true)
    setError('')
    try {
      const sources = JSON.parse(text)
      if (!Array.isArray(sources)) throw new Error('sources must be an array')
      await setAgentConfig(agent.id, sources)
      onSaved()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-lg font-semibold text-white">Config push — {agent.name}</h2>
        <p className="mb-3 text-xs text-slate-500">
          Source list (JSON). Fields: <code className="text-slate-300">dataset</code>,{' '}
          <code className="text-slate-300">type</code> (file/journald/wineventlog/fim),{' '}
          <code className="text-slate-300">path</code>. Saving bumps the version and triggers an agent restart.
        </p>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
          rows={10}
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-indigo-500"
          placeholder='[{"dataset":"sshd","type":"file","path":"/var/log/auth.log"},{"dataset":"fim","type":"fim","path":"/etc/passwd,/etc/ssh/sshd_config"}]'
        />
        {error && <p className="mt-2 text-sm text-rose-400">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">
            Cancel
          </button>
          <button
            onClick={save}
            disabled={busy}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50"
          >
            {busy ? 'Saving…' : 'Save & push'}
          </button>
        </div>
      </div>
    </div>
  )
}
