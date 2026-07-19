import { useState, useEffect, Fragment } from 'react'
import {
  fetchAgents,
  createEnrollToken,
  fetchInstallInfo,
  revokeAgent,
  setAgentConfig,
  agentOnline,
  can,
  fetchSnapshotPaths,
  fetchSnapshots,
  fetchFileActions,
  snapshotNow,
  quarantineFile,
  restoreVersion,
  type AgentInfo,
  type AgentSource,
  type FIMSnapshot,
  type FIMSnapshotPath,
  type FileAction,
  type Me,
} from '../lib/api'
import DocLink from '../components/DocLink'

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
  const [snapshotsFor, setSnapshotsFor] = useState<AgentInfo | null>(null)
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
          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1">
            <DocLink file="new-log-source.md" label="Add a log source" />
            <DocLink file="whodata.md" label="FIM who-data" />
            <DocLink file="modsecurity.md" label="ModSecurity / WAF" />
            <DocLink file="syslog.md" label="Syslog (agentless)" />
            <DocLink file="suspicious-ips.md" label="Suspicious IPs" />
            <DocLink file="archive.md" label="Raw log archive" />
            <DocLink file="clickhouse.md" label="ClickHouse analytics" />
          </div>
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
                        onClick={() => setSnapshotsFor(a)}
                        className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
                        title="Browse the dated FIM snapshot timeline of this agent's watched files"
                      >
                        Snapshots
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
      {snapshotsFor && <SnapshotViewer agent={snapshotsFor} me={me} onClose={() => setSnapshotsFor(null)} />}
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
      const clean = sources.map((s) => {
        const base: AgentSource = {
          dataset: s.dataset.trim(),
          type: s.type,
          path: s.path.trim(),
          interval: POLL_TYPES.has(s.type) && s.interval ? Number(s.interval) : 0,
        }
        if (s.type === 'fim') {
          if (s.snapshot_mode && s.snapshot_mode !== 'baseline') base.snapshot_mode = s.snapshot_mode
          if (s.snapshot_storage) base.snapshot_storage = s.snapshot_storage
          if (s.snapshot_retention) base.snapshot_retention = Number(s.snapshot_retention)
        }
        return base
      })
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
              {s.type === 'fim' && (
                <div className="col-span-5 mb-1 grid grid-cols-[auto_1fr_auto_1fr_auto_5rem] items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/40 px-2 py-1.5 text-xs">
                  <span className="text-slate-500">Snapshots</span>
                  <select
                    value={s.snapshot_mode || 'baseline'}
                    onChange={(e) => update(i, { snapshot_mode: e.target.value })}
                    title="How dated versions are captured"
                    className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1 outline-none focus:border-indigo-500"
                  >
                    <option value="baseline">baseline only (single)</option>
                    <option value="on_change">on every change</option>
                    <option value="scheduled">scheduled (daily)</option>
                    <option value="both">both</option>
                  </select>
                  <span className="text-slate-500">Store</span>
                  <select
                    value={s.snapshot_storage || 'agent'}
                    onChange={(e) => update(i, { snapshot_storage: e.target.value })}
                    title="Where version content is kept"
                    className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1 outline-none focus:border-indigo-500"
                  >
                    <option value="agent">on agent</option>
                    <option value="manager">on manager</option>
                  </select>
                  <span className="text-slate-500">Keep</span>
                  <input
                    type="number"
                    min={0}
                    value={s.snapshot_retention || ''}
                    onChange={(e) => update(i, { snapshot_retention: Number(e.target.value) })}
                    placeholder="∞"
                    title="Versions kept per file (0 = unlimited)"
                    className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1 outline-none focus:border-indigo-500"
                  />
                </div>
              )}
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

// SnapshotViewer — read-only browser of an agent's dated FIM snapshot timeline (ADR 0002,
// Phase 1-3). Browse a watched file's dated versions, see the old-vs-new diff per version, take a
// snapshot on demand, and quarantine the current (possibly infected) file for blue-team analysis.
function SnapshotViewer({ agent, me, onClose }: { agent: AgentInfo; me: Me; onClose: () => void }) {
  const [paths, setPaths] = useState<FIMSnapshotPath[]>([])
  const [selected, setSelected] = useState<string>('')
  const [versions, setVersions] = useState<FIMSnapshot[]>([])
  const [actions, setActions] = useState<FileAction[]>([])
  const [expanded, setExpanded] = useState<number | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState('')
  const [loading, setLoading] = useState(true)

  const canSnapshot = can(me, 'manage_agents')
  const canQuarantine = can(me, 'approve_remediation')

  const loadPaths = () =>
    fetchSnapshotPaths(agent.name)
      .then((p) => {
        setPaths(p)
        setSelected((cur) => cur || (p.length > 0 ? p[0].path : ''))
      })
      .catch((e) => setError((e as Error).message))

  useEffect(() => {
    loadPaths().finally(() => setLoading(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agent.name])

  const loadFile = () => {
    if (!selected) {
      setVersions([])
      setActions([])
      return
    }
    fetchSnapshots(agent.name, selected).then(setVersions).catch((e) => setError((e as Error).message))
    fetchFileActions(agent.name, selected).then(setActions).catch(() => {})
  }
  useEffect(loadFile, [agent.name, selected])

  const act = async (kind: 'snapshot' | 'quarantine') => {
    if (!selected) return
    if (kind === 'quarantine' && !confirm(`Quarantine ${selected} on ${agent.name}?\n\nThe current file is MOVED into the agent's quarantine dir (read-only) for analysis. Restore a good version afterwards if needed.`)) return
    setBusy(kind)
    setError('')
    setMsg('')
    try {
      if (kind === 'snapshot') {
        await snapshotNow(agent.name, selected)
        setMsg('Snapshot requested — the agent captures it on its next poll (~10s).')
      } else {
        await quarantineFile(agent.name, selected)
        setMsg('Quarantine requested — the agent moves the file on its next poll (~10s). Refresh to see the result.')
      }
      setTimeout(() => {
        loadFile()
        loadPaths()
      }, 3000)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  const restore = async (v: FIMSnapshot) => {
    if (!confirm(`Restore ${selected} to the version from ${new Date(v.captured_at).toLocaleString()}?\n\nThe current file is snapshotted first (nothing is lost), then overwritten with this version.`)) return
    setBusy('restore-' + v.id)
    setError('')
    setMsg('')
    try {
      await restoreVersion(agent.name, selected, v.sha256)
      setMsg('Restore requested — the agent applies it on its next poll (~10s).')
      setTimeout(() => {
        loadFile()
        loadPaths()
      }, 3000)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  const fmtBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`)

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="max-h-[90vh] w-full max-w-4xl overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-white">FIM snapshots — {agent.name}</h2>
          <DocLink file="adr/0002-versioned-fim-snapshots.md" label="About snapshots" className="shrink-0" />
        </div>
        <p className="mb-4 text-xs text-slate-500">
          Dated version timeline of watched files. Expand a version to see the old-vs-new diff.
        </p>

        {loading ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : paths.length === 0 ? (
          <p className="rounded-lg border border-dashed border-slate-800 px-3 py-6 text-center text-sm text-slate-600">
            No snapshots recorded for this agent yet. Enable a snapshot mode on a <code className="text-slate-400">fim</code> source
            (Monitoring → Snapshots) and the agent will start capturing versions.
          </p>
        ) : (
          <div className="grid grid-cols-[15rem_1fr] gap-4">
            <div className="space-y-1 border-r border-slate-800 pr-3">
              {paths.map((p) => (
                <button
                  key={p.path}
                  onClick={() => { setSelected(p.path); setExpanded(null) }}
                  className={`block w-full truncate rounded-md px-2 py-1.5 text-left text-xs ${
                    selected === p.path ? 'bg-indigo-500/15 text-indigo-300' : 'text-slate-400 hover:bg-slate-800'
                  }`}
                  title={p.path}
                >
                  <span className="block truncate font-mono">{p.path}</span>
                  <span className="text-[10px] text-slate-600">{p.versions} version{p.versions === 1 ? '' : 's'}</span>
                </button>
              ))}
            </div>
            <div>
              {selected && (
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="mr-auto truncate font-mono text-[11px] text-slate-500" title={selected}>{selected}</span>
                  {canSnapshot && (
                    <button
                      onClick={() => act('snapshot')}
                      disabled={busy !== ''}
                      className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800 disabled:opacity-50"
                    >
                      {busy === 'snapshot' ? 'Requesting…' : 'Snapshot now'}
                    </button>
                  )}
                  {canQuarantine && (
                    <button
                      onClick={() => act('quarantine')}
                      disabled={busy !== ''}
                      title="Move the current file into the agent's quarantine dir for blue-team analysis"
                      className="rounded-md border border-amber-500/40 px-2 py-1 text-xs text-amber-300 hover:bg-amber-500/10 disabled:opacity-50"
                    >
                      {busy === 'quarantine' ? 'Requesting…' : 'Quarantine infected/old file'}
                    </button>
                  )}
                </div>
              )}
              {versions.length === 0 ? (
                <p className="text-sm text-slate-600">Select a file.</p>
              ) : (
                <table className="w-full text-left text-xs">
                  <thead className="uppercase tracking-wider text-slate-500">
                    <tr>
                      <th className="py-1 font-medium">Captured</th>
                      <th className="py-1 font-medium">Trigger</th>
                      <th className="py-1 font-medium">Size</th>
                      <th className="py-1 font-medium">SHA-256</th>
                      <th className="py-1 font-medium"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {versions.map((v) => (
                      <Fragment key={v.id}>
                        <tr>
                          <td className="py-1.5 text-slate-300">{new Date(v.captured_at).toLocaleString()}</td>
                          <td className="py-1.5 text-slate-400">{v.trigger}</td>
                          <td className="py-1.5 text-slate-400">{fmtBytes(v.size)}</td>
                          <td className="py-1.5 font-mono text-slate-500">{v.sha256.slice(0, 12)}…</td>
                          <td className="whitespace-nowrap py-1.5 text-right">
                            {v.diff && (
                              <button
                                onClick={() => setExpanded(expanded === v.id ? null : v.id)}
                                className="text-indigo-300 hover:underline"
                              >
                                {expanded === v.id ? 'hide diff' : 'old vs new'}
                              </button>
                            )}
                            {canQuarantine && (
                              <button
                                onClick={() => restore(v)}
                                disabled={busy !== ''}
                                title="Restore the file to this version (current content is snapshotted first)"
                                className="ml-3 text-amber-300 hover:underline disabled:opacity-50"
                              >
                                {busy === 'restore-' + v.id ? '…' : 'restore'}
                              </button>
                            )}
                            {!v.diff && !canQuarantine && <span className="text-slate-700">—</span>}
                          </td>
                        </tr>
                        {expanded === v.id && v.diff && (
                          <tr>
                            <td colSpan={5} className="pb-2">
                              <pre className="max-h-64 overflow-auto rounded-md bg-slate-950/70 p-2 font-mono text-[11px] leading-relaxed">
                                {v.diff.split('\n').map((line, i) => (
                                  <div
                                    key={i}
                                    className={line.startsWith('+') ? 'text-emerald-400' : line.startsWith('-') ? 'text-rose-400' : 'text-slate-400'}
                                  >
                                    {line || ' '}
                                  </div>
                                ))}
                              </pre>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              )}

              {actions.length > 0 && (
                <div className="mt-4">
                  <h3 className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Recent actions</h3>
                  <ul className="space-y-1 text-xs">
                    {actions.map((a) => (
                      <li key={a.id} className="flex flex-wrap items-center gap-2">
                        <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">{a.action}</span>
                        <span className={a.status === 'done' ? 'text-emerald-400' : a.status === 'failed' ? 'text-rose-400' : 'text-slate-500'}>{a.status}</span>
                        {a.result && <span className="truncate font-mono text-slate-500" title={a.result}>{a.result}</span>}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}

        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
        {msg && <p className="mt-3 text-sm text-emerald-400">{msg}</p>}
        <div className="mt-5 flex justify-end">
          <button onClick={onClose} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
