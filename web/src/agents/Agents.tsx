import { useState, useEffect } from 'react'
import {
  fetchAgents,
  createEnrollToken,
  fetchInstallInfo,
  revokeAgent,
  setAgentConfig,
  agentOnline,
  can,
  type AgentInfo,
  type AgentSource,
  type Me,
} from '../lib/api'

const SOURCE_TYPES = ['file', 'journald', 'wineventlog', 'fim']
const POLL_TYPES = new Set(['fim', 'wineventlog']) // types where the interval applies

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

// StatusBadge blends the live heartbeat check (fresh last_seen) with the worker-
// maintained health state: degraded/stale come from the server-side checker, while
// online/disconnected stay accurate even between checker ticks.
function StatusBadge({ a }: { a: AgentInfo }) {
  const badge = (cls: string, label: string, title?: string) => (
    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${cls}`} title={title}>{label}</span>
  )
  if (a.revoked) return badge('text-rose-300 bg-rose-500/15', 'revoked')
  const live = agentOnline(a)
  if (live && a.status === 'degraded')
    return badge('text-amber-300 bg-amber-500/15', 'degraded', a.health_detail || 'agent reports a problem')
  if (live) return badge('text-emerald-300 bg-emerald-500/15', 'online')
  if (!a.last_seen_at) return badge('text-slate-400 bg-slate-700/40', 'never connected')
  if (a.status === 'stale') return badge('text-slate-400 bg-slate-700/40', 'stale', 'offline for more than 24h')
  return badge('text-orange-300 bg-orange-500/15', 'disconnected', 'heartbeats missed - a high selfhealth alert was raised')
}

export default function Agents({ me }: { me: Me }) {
  const isAdmin = can(me, 'manage_agents')
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<AgentInfo | null>(null)
  const [wizard, setWizard] = useState(false)
  const [uninstalling, setUninstalling] = useState<AgentInfo | null>(null)

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
          <p className="mt-1 text-sm text-slate-500">Registered agents, heartbeat status &amp; centrally-pushed config</p>
        </div>
        {isAdmin && (
          <button
            onClick={() => setWizard(true)}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400"
          >
            + Add agent
          </button>
        )}
      </header>

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
                  No agents yet. Click “Add agent” to enroll one.
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
                        Monitoring
                      </button>
                      <button
                        onClick={() => setUninstalling(a)}
                        className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
                        title="Show commands to uninstall this agent from its endpoint"
                      >
                        Uninstall
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

      {wizard && <EnrollWizard onClose={() => setWizard(false)} />}
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
      {uninstalling && <UninstallHelp agent={uninstalling} onClose={() => setUninstalling(null)} />}
    </div>
  )
}

// UninstallHelp shows the OS-specific commands to remove an agent from its endpoint.
// The clean path is Revoke (agent self-uninstalls on next heartbeat); these commands
// are for a manual/forced cleanup. Mirrors docs/features/05-agents.md.
function UninstallHelp({ agent, onClose }: { agent: AgentInfo; onClose: () => void }) {
  const isWindows = (agent.os || '').toLowerCase().includes('win')
  const linux = [
    'sudo deuswatch-agent -uninstall     # clean removal (service, binary, certs, buffer)',
    '',
    '# ...or force it manually if the service is stuck:',
    'sudo systemctl disable --now deuswatch-agent',
    'sudo rm -f /etc/systemd/system/deuswatch-agent.service && sudo systemctl daemon-reload',
    'sudo rm -f /usr/local/bin/deuswatch-agent',
    'sudo rm -rf /etc/deuswatch /var/lib/deuswatch',
  ].join('\n')
  const windows = [
    '& "C:\\Program Files\\DeusWatch\\deuswatch-agent.exe" -uninstall   # clean removal',
    '',
    '# ...or force it manually (elevated PowerShell):',
    'Stop-Service DeusWatchAgent -Force -ErrorAction SilentlyContinue',
    'sc.exe delete DeusWatchAgent',
    "Remove-Item -Recurse -Force 'C:\\Program Files\\DeusWatch','C:\\ProgramData\\DeusWatch'",
    "Remove-NetFirewallRule -DisplayName 'DeusWatch agent (outbound)' -ErrorAction SilentlyContinue",
  ].join('\n')

  return (
    <div className="fixed inset-0 z-20 grid place-items-center bg-black/50 p-4" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h3 className="mb-1 text-sm font-semibold text-white">
          Uninstall agent — <span className="text-indigo-300">{agent.name}</span>
          <span className="ml-2 rounded bg-slate-700/40 px-1.5 py-0.5 text-[10px] uppercase text-slate-400">{agent.os || 'linux'}</span>
        </h3>
        <p className="mb-4 text-xs text-slate-500">
          Cleanest way: <span className="text-slate-300">Revoke</span> this agent — it self-uninstalls on its
          next heartbeat. Run the commands below on the endpoint for a manual or forced cleanup.
        </p>
        <div className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-500">
          Run on the {isWindows ? 'Windows endpoint (elevated PowerShell)' : 'Linux endpoint'}
        </div>
        <Copyable text={isWindows ? windows : linux} />
        <p className="mt-3 text-xs text-slate-600">
          Removing the certs de-enrolls the host; re-installing later issues a fresh certificate.
        </p>
        <div className="mt-5 flex justify-end">
          <button onClick={onClose} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">Close</button>
        </div>
      </div>
    </div>
  )
}

// Copyable shows a command in a code block with a copy-to-clipboard button.
function Copyable({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <div className="relative">
      <button
        onClick={copy}
        className="absolute right-2 top-2 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-indigo-300 hover:bg-slate-700"
      >
        {copied ? 'copied ✓' : 'copy'}
      </button>
      <code className="block whitespace-pre-wrap break-all rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 pr-14 text-xs text-emerald-300">
        {text}
      </code>
    </div>
  )
}

// EnrollWizard — Wazuh-style: pick OS, auto-generate a one-time token, and get a
// single copy-paste command that downloads, enrolls, installs the service and connects.
function EnrollWizard({ onClose }: { onClose: () => void }) {
  const [os, setOs] = useState('linux')
  const [name, setName] = useState('')
  const [host, setHost] = useState(`${location.hostname}:8080`)
  const [gwPort, setGwPort] = useState('8443')
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // Learn the manager's host-published ports so the command points at the right ones even
  // when they're remapped in docker-compose (DEUSWATCH_API_PORT / DEUSWATCH_GATEWAY_PORT).
  useEffect(() => {
    fetchInstallInfo()
      .then((info) => {
        setHost(`${location.hostname}:${info.api_port}`)
        setGwPort(info.gateway_port)
      })
      .catch(() => {})
  }, [])

  const managerIP = host.replace(/:\d+$/, '')
  const apiPort = host.match(/:(\d+)$/)?.[1] ?? '8080' // follow the (editable) host field
  const tok = token || '<TOKEN>'
  const nm = name || '<name>'
  // One copy-paste command that downloads, enrolls, installs the service and connects.
  // API_PORT/GW_PORT are passed so the agent reaches the manager on its remapped ports.
  const install =
    os === 'windows'
      ? `$env:MANAGER='${managerIP}'; $env:TOKEN='${tok}'; $env:NAME='${nm}'; $env:API_PORT='${apiPort}'; $env:GW_PORT='${gwPort}'; iwr http://${host}/api/agent/install.ps1 -UseBasicParsing | iex`
      : `curl -fsSL http://${host}/api/agent/install.sh | sudo MANAGER=${managerIP} TOKEN=${tok} NAME=${nm} API_PORT=${apiPort} GW_PORT=${gwPort} sh`
  // Firewall command to run once on the manager host (Windows) so agents can reach it.
  const managerFw = `New-NetFirewallRule -DisplayName "DeusWatch" -Direction Inbound -Action Allow -Protocol TCP -LocalPort ${apiPort},${gwPort}`

  const gen = async () => {
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

  // Auto-generate a one-time token when the wizard opens, so the command is ready to copy.
  useEffect(() => {
    void gen()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-xl rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-lg font-semibold text-white">Add agent</h2>
        <p className="mb-4 text-xs text-slate-500">Pick the endpoint’s platform, then run the generated command on it.</p>

        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-400">Operating system</span>
            <select
              value={os}
              onChange={(e) => setOs(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
            >
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
            </select>
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-400">Agent name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. web01"
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-400">Manager host</span>
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
            />
          </label>
        </div>

        <div className="mt-5 space-y-4">
          <div>
            <div className="mb-1 text-xs font-medium text-slate-400">
              1 · On the manager — open the firewall <span className="text-slate-600">(elevated PowerShell, once)</span>
            </div>
            <Copyable text={managerFw} />
          </div>
          <div>
            <div className="mb-1 text-xs font-medium text-slate-400">
              2 · On the endpoint — paste &amp; run{' '}
              <span className="text-slate-600">{os === 'windows' ? '(elevated PowerShell)' : '(root; sudo is included)'}</span>
            </div>
            <Copyable text={install} />
            {!token && (
              <p className="mt-1 text-xs text-amber-400/80">{busy ? 'Generating token…' : 'No token yet — click “Generate token”.'}</p>
            )}
            <p className="mt-1 text-[11px] text-slate-600">
              Downloads the agent, opens its firewall, enrolls with the token, installs an auto-start service, and connects to the gateway.
            </p>
          </div>
        </div>

        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}

        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">
            Close
          </button>
          <button
            onClick={gen}
            disabled={busy}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50"
          >
            {busy ? 'Generating…' : token ? 'Regenerate token' : 'Generate token'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ConfigEditor — central monitoring config: which sources each agent collects and,
// for poll-based collectors, how often (intensity).
function ConfigEditor({
  agent,
  onClose,
  onSaved,
}: {
  agent: AgentInfo
  onClose: () => void
  onSaved: () => void
}) {
  const [sources, setSources] = useState<AgentSource[]>(
    (agent.sources ?? []).map((s) => ({ ...s })),
  )
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const update = (i: number, patch: Partial<AgentSource>) =>
    setSources((prev) => prev.map((s, idx) => (idx === i ? { ...s, ...patch } : s)))
  const addRow = () => setSources((prev) => [...prev, { dataset: '', type: 'file', path: '', interval: 0 }])
  const removeRow = (i: number) => setSources((prev) => prev.filter((_, idx) => idx !== i))

  const save = async () => {
    setBusy(true)
    setError('')
    try {
      for (const s of sources) {
        if (!s.dataset || !s.type) throw new Error('each source needs a dataset and a type')
      }
      const clean = sources.map((s) => ({
        dataset: s.dataset.trim(),
        type: s.type,
        path: s.path.trim(),
        interval: POLL_TYPES.has(s.type) && s.interval ? Number(s.interval) : 0,
      }))
      await setAgentConfig(agent.id, clean)
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
        className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-lg font-semibold text-white">Monitoring — {agent.name}</h2>
        <p className="mb-4 text-xs text-slate-500">
          Choose what this agent collects. For <code className="text-slate-300">fim</code> &amp;{' '}
          <code className="text-slate-300">wineventlog</code> set a scan interval (seconds) to control intensity.
          Saving bumps the version &amp; the agent re-applies on its next poll.
        </p>

        <div className="space-y-2">
          <div className="grid grid-cols-[1fr_8rem_1.6fr_6rem_2rem] gap-2 px-1 text-[11px] uppercase tracking-wider text-slate-500">
            <span>Dataset</span>
            <span>Type</span>
            <span>Path</span>
            <span>Interval</span>
            <span></span>
          </div>
          {sources.length === 0 && (
            <p className="rounded-lg border border-dashed border-slate-800 px-3 py-4 text-center text-xs text-slate-600">
              No sources. Add one below (or save empty to clear).
            </p>
          )}
          {sources.map((s, i) => (
            <div key={i} className="grid grid-cols-[1fr_8rem_1.6fr_6rem_2rem] gap-2">
              <input
                value={s.dataset}
                onChange={(e) => update(i, { dataset: e.target.value })}
                placeholder="sshd"
                className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm outline-none focus:border-indigo-500"
              />
              <select
                value={s.type}
                onChange={(e) => update(i, { type: e.target.value })}
                className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm outline-none focus:border-indigo-500"
              >
                {SOURCE_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <input
                value={s.path}
                onChange={(e) => update(i, { path: e.target.value })}
                placeholder={s.type === 'fim' ? '/etc/passwd,/etc/ssh' : s.type === 'wineventlog' ? 'Security' : '/var/log/auth.log'}
                className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm outline-none focus:border-indigo-500"
              />
              {POLL_TYPES.has(s.type) ? (
                <input
                  type="number"
                  min={1}
                  value={s.interval || ''}
                  onChange={(e) => update(i, { interval: Number(e.target.value) })}
                  placeholder={s.type === 'fim' ? '60' : '5'}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm outline-none focus:border-indigo-500"
                />
              ) : (
                <span className="grid place-items-center text-[11px] text-slate-600">live</span>
              )}
              <button
                onClick={() => removeRow(i)}
                className="grid place-items-center rounded-lg border border-slate-700 text-slate-400 hover:bg-slate-800"
                title="Remove"
              >
                ✕
              </button>
            </div>
          ))}
        </div>

        <button
          onClick={addRow}
          className="mt-3 rounded-lg border border-dashed border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800"
        >
          + Add source
        </button>

        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
        <div className="mt-5 flex justify-end gap-2">
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
