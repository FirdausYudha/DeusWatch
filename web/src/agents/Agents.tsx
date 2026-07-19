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
  bulkRestore,
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
  if (!a.last_seen_at) return badge('text-muted bg-surface-2', 'never connected')
  if (a.status === 'stale') return badge('text-muted bg-surface-2', 'stale', 'offline for more than 24h')
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
          <h1 className="text-2xl font-semibold tracking-tight text-fg">Agents</h1>
          <p className="mt-1 text-sm text-dim">Registered agents, heartbeat status &amp; centrally-pushed config</p>
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
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:opacity-90"
          >
            + Add agent
          </button>
        )}
      </header>

      {error && <p className="mb-4 text-sm text-rose-400">{error}</p>}

      <div className="overflow-hidden rounded-xl border border-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-surface text-xs uppercase tracking-wider text-dim">
            <tr>
              <th className="px-4 py-2 font-medium">Name</th>
              <th className="px-4 py-2 font-medium">OS</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Heartbeat</th>
              <th className="px-4 py-2 font-medium">Config</th>
              {isAdmin && <th className="px-4 py-2 font-medium">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-surface">
            {agents.length === 0 && (
              <tr>
                <td colSpan={isAdmin ? 6 : 5} className="px-4 py-8 text-center text-dim">
                  No agents yet. Click â€œAdd agentâ€ to enroll one.
                </td>
              </tr>
            )}
            {agents.map((a) => (
              <tr key={a.id} className="hover:bg-surface-2">
                <td className="px-4 py-2 font-medium text-fg">{a.name}</td>
                <td className="px-4 py-2 text-muted">{a.os || 'â€”'}</td>
                <td className="px-4 py-2"><StatusBadge a={a} /></td>
                <td className="px-4 py-2 text-muted">{relative(a.last_seen_at)}</td>
                <td className="px-4 py-2 text-muted">
                  v{a.config_version}
                  {a.sources && a.sources.length > 0 && (
                    <span className="ml-1 text-dim">({a.sources.length} source{a.sources.length > 1 ? 's' : ''})</span>
                  )}
                </td>
                {isAdmin && (
                  <td className="px-4 py-2">
                    <div className="flex gap-2">
                      <button
                        onClick={() => setEditing(a)}
                        className="rounded-md border border-border px-2 py-1 text-xs text-fg hover:bg-surface-2"
                      >
                        Monitoring
                      </button>
                      <button
                        onClick={() => setSnapshotsFor(a)}
                        className="rounded-md border border-border px-2 py-1 text-xs text-fg hover:bg-surface-2"
                        title="Browse the dated FIM snapshot timeline of this agent's watched files"
                      >
                        Snapshots
                      </button>
                      <button
                        onClick={() => setUninstalling(a)}
                        className="rounded-md border border-border px-2 py-1 text-xs text-fg hover:bg-surface-2"
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
      <div className="w-full max-w-2xl rounded-xl border border-border bg-surface p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h3 className="mb-1 text-sm font-semibold text-fg">
          Uninstall agent â€” <span className="text-accent">{agent.name}</span>
          <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase text-muted">{agent.os || 'linux'}</span>
        </h3>
        <p className="mb-4 text-xs text-dim">
          Cleanest way: <span className="text-fg">Revoke</span> this agent â€” it self-uninstalls on its
          next heartbeat. Run the commands below on the endpoint for a manual or forced cleanup.
        </p>
        <div className="mb-2 text-xs font-medium uppercase tracking-wider text-dim">
          Run on the {isWindows ? 'Windows endpoint (elevated PowerShell)' : 'Linux endpoint'}
        </div>
        <Copyable text={isWindows ? windows : linux} />
        <p className="mt-3 text-xs text-dim">
          Removing the certs de-enrolls the host; re-installing later issues a fresh certificate.
        </p>
        <div className="mt-5 flex justify-end">
          <button onClick={onClose} className="rounded-lg border border-border px-4 py-2 text-sm text-fg hover:bg-surface-2">Close</button>
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
        className="absolute right-2 top-2 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-accent hover:bg-surface-2"
      >
        {copied ? 'copied âœ“' : 'copy'}
      </button>
      <code className="block whitespace-pre-wrap break-all rounded-lg border border-border bg-bg px-3 py-2 pr-14 text-xs text-emerald-300">
        {text}
      </code>
    </div>
  )
}

// EnrollWizard â€” Wazuh-style: pick OS, auto-generate a one-time token, and get a
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
        className="w-full max-w-xl rounded-xl border border-border bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-lg font-semibold text-fg">Add agent</h2>
        <p className="mb-4 text-xs text-dim">Pick the endpointâ€™s platform, then run the generated command on it.</p>

        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted">Operating system</span>
            <select
              value={os}
              onChange={(e) => setOs(e.target.value)}
              className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
            >
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
            </select>
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted">Agent name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. web01"
              className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted">Manager host</span>
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
            />
          </label>
        </div>

        <div className="mt-5 space-y-4">
          <div>
            <div className="mb-1 text-xs font-medium text-muted">
              1 Â· On the manager â€” open the firewall <span className="text-dim">(elevated PowerShell, once)</span>
            </div>
            <Copyable text={managerFw} />
          </div>
          <div>
            <div className="mb-1 text-xs font-medium text-muted">
              2 Â· On the endpoint â€” paste &amp; run{' '}
              <span className="text-dim">{os === 'windows' ? '(elevated PowerShell)' : '(root; sudo is included)'}</span>
            </div>
            <Copyable text={install} />
            {!token && (
              <p className="mt-1 text-xs text-amber-400/80">{busy ? 'Generating tokenâ€¦' : 'No token yet â€” click â€œGenerate tokenâ€.'}</p>
            )}
            <p className="mt-1 text-[11px] text-dim">
              Downloads the agent, opens its firewall, enrolls with the token, installs an auto-start service, and connects to the gateway.
            </p>
          </div>
        </div>

        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}

        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-border px-4 py-2 text-sm text-fg hover:bg-surface-2">
            Close
          </button>
          <button
            onClick={gen}
            disabled={busy}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            {busy ? 'Generatingâ€¦' : token ? 'Regenerate token' : 'Generate token'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ConfigEditor â€” central monitoring config: which sources each agent collects and,
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
        className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-border bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-lg font-semibold text-fg">Monitoring â€” {agent.name}</h2>
        <p className="mb-4 text-xs text-dim">
          Choose what this agent collects. For <code className="text-fg">fim</code> &amp;{' '}
          <code className="text-fg">wineventlog</code> set a scan interval (seconds) to control intensity.
          Saving bumps the version &amp; the agent re-applies on its next poll.
        </p>

        <div className="space-y-2">
          <div className="grid grid-cols-[1fr_8rem_1.6fr_6rem_2rem] gap-2 px-1 text-[11px] uppercase tracking-wider text-dim">
            <span>Dataset</span>
            <span>Type</span>
            <span>Path</span>
            <span>Interval</span>
            <span></span>
          </div>
          {sources.length === 0 && (
            <p className="rounded-lg border border-dashed border-border px-3 py-4 text-center text-xs text-dim">
              No sources. Add one below (or save empty to clear).
            </p>
          )}
          {sources.map((s, i) => (
            <div key={i} className="grid grid-cols-[1fr_8rem_1.6fr_6rem_2rem] gap-2">
              <input
                value={s.dataset}
                onChange={(e) => update(i, { dataset: e.target.value })}
                placeholder="sshd"
                className="rounded-lg border border-border bg-surface-2 px-2 py-1.5 text-sm outline-none focus:border-accent"
              />
              <select
                value={s.type}
                onChange={(e) => update(i, { type: e.target.value })}
                className="rounded-lg border border-border bg-surface-2 px-2 py-1.5 text-sm outline-none focus:border-accent"
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
                className="rounded-lg border border-border bg-surface-2 px-2 py-1.5 text-sm outline-none focus:border-accent"
              />
              {POLL_TYPES.has(s.type) ? (
                <input
                  type="number"
                  min={1}
                  value={s.interval || ''}
                  onChange={(e) => update(i, { interval: Number(e.target.value) })}
                  placeholder={s.type === 'fim' ? '60' : '5'}
                  className="rounded-lg border border-border bg-surface-2 px-2 py-1.5 text-sm outline-none focus:border-accent"
                />
              ) : (
                <span className="grid place-items-center text-[11px] text-dim">live</span>
              )}
              <button
                onClick={() => removeRow(i)}
                className="grid place-items-center rounded-lg border border-border text-muted hover:bg-surface-2"
                title="Remove"
              >
                âœ•
              </button>
              {s.type === 'fim' && (
                <div className="col-span-5 mb-1 grid grid-cols-[auto_1fr_auto_1fr_auto_5rem] items-center gap-2 rounded-lg border border-border bg-surface px-2 py-1.5 text-xs">
                  <span className="text-dim">Snapshots</span>
                  <select
                    value={s.snapshot_mode || 'baseline'}
                    onChange={(e) => update(i, { snapshot_mode: e.target.value })}
                    title="How dated versions are captured"
                    className="rounded-md border border-border bg-surface-2 px-2 py-1 outline-none focus:border-accent"
                  >
                    <option value="baseline">baseline only (single)</option>
                    <option value="on_change">on every change</option>
                    <option value="scheduled">scheduled (daily)</option>
                    <option value="both">both</option>
                  </select>
                  <span className="text-dim">Store</span>
                  <select
                    value={s.snapshot_storage || 'agent'}
                    onChange={(e) => {
                      const v = e.target.value
                      if (
                        v === 'manager' &&
                        !confirm(
                          'Store snapshot CONTENT on the manager?\n\n' +
                            'The full file content of each version will be uploaded to and kept on the DeusWatch server (survives host loss, viewable/restorable centrally). ' +
                            'Choose "on agent" to keep content on the host and upload only metadata.',
                        )
                      ) {
                        return // keep the current choice
                      }
                      update(i, { snapshot_storage: v })
                    }}
                    title="Where version content is kept â€” the admin's choice (agent = host only; manager = central copy)"
                    className="rounded-md border border-border bg-surface-2 px-2 py-1 outline-none focus:border-accent"
                  >
                    <option value="agent">on agent</option>
                    <option value="manager">on manager</option>
                  </select>
                  <span className="text-dim">Keep</span>
                  <input
                    type="number"
                    min={0}
                    value={s.snapshot_retention || ''}
                    onChange={(e) => update(i, { snapshot_retention: Number(e.target.value) })}
                    placeholder="âˆž"
                    title="Versions kept per file (0 = unlimited)"
                    className="rounded-md border border-border bg-surface-2 px-2 py-1 outline-none focus:border-accent"
                  />
                </div>
              )}
            </div>
          ))}
        </div>

        <button
          onClick={addRow}
          className="mt-3 rounded-lg border border-dashed border-border px-3 py-1.5 text-xs text-fg hover:bg-surface-2"
        >
          + Add source
        </button>

        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-border px-4 py-2 text-sm text-fg hover:bg-surface-2">
            Cancel
          </button>
          <button
            onClick={save}
            disabled={busy}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            {busy ? 'Savingâ€¦' : 'Save & push'}
          </button>
        </div>
      </div>
    </div>
  )
}

// SnapshotViewer â€” read-only browser of an agent's dated FIM snapshot timeline (ADR 0002,
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
  const [bulkAt, setBulkAt] = useState('')

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
        setMsg('Snapshot requested â€” the agent captures it on its next poll (~10s).')
      } else {
        await quarantineFile(agent.name, selected)
        setMsg('Quarantine requested â€” the agent moves the file on its next poll (~10s). Refresh to see the result.')
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
      setMsg('Restore requested â€” the agent applies it on its next poll (~10s).')
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

  const doBulkRestore = async () => {
    if (!bulkAt) return
    const asOf = new Date(bulkAt)
    if (isNaN(asOf.getTime())) {
      setError('Pick a valid date/time')
      return
    }
    if (!confirm(`Roll back ALL of ${agent.name}'s watched files to their versions as of ${asOf.toLocaleString()}?\n\nThis is the ransomware recovery action: each file's current content is snapshotted first, then overwritten with its as-of version. Only files stored on the manager can be restored if the agent's copies were lost.`)) return
    setBusy('bulk'); setError(''); setMsg('')
    try {
      const n = await bulkRestore(agent.name, '', asOf.toISOString())
      setMsg(`Point-in-time revert requested for ${n} file(s) â€” the agent applies them on its next polls.`)
      setTimeout(() => { loadFile(); loadPaths() }, 3000)
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
        className="max-h-[90vh] w-full max-w-4xl overflow-y-auto rounded-xl border border-border bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-fg">FIM snapshots â€” {agent.name}</h2>
          <DocLink file="adr/0002-versioned-fim-snapshots.md" label="About snapshots" className="shrink-0" />
        </div>
        <p className="mb-3 text-xs text-dim">
          Dated version timeline of watched files. Expand a version to see the old-vs-new diff.
        </p>

        {canQuarantine && !loading && paths.length > 0 && (
          <div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-amber-900/40 bg-amber-500/5 px-3 py-2">
            <span className="text-xs font-medium text-amber-200">Ransomware recovery â€” roll all files back to:</span>
            <input
              type="datetime-local"
              value={bulkAt}
              onChange={(e) => setBulkAt(e.target.value)}
              className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-fg outline-none focus:border-accent"
            />
            <button
              onClick={doBulkRestore}
              disabled={busy !== '' || !bulkAt}
              className="rounded-md border border-amber-500/40 px-2 py-1 text-xs text-amber-300 hover:bg-amber-500/10 disabled:opacity-50"
            >
              {busy === 'bulk' ? 'Requestingâ€¦' : 'Restore all to this time'}
            </button>
            <span className="text-[10px] text-dim">Point-in-time revert of every watched file to its version as of the chosen time.</span>
          </div>
        )}

        {loading ? (
          <p className="text-sm text-dim">Loadingâ€¦</p>
        ) : paths.length === 0 ? (
          <p className="rounded-lg border border-dashed border-border px-3 py-6 text-center text-sm text-dim">
            No snapshots recorded for this agent yet. Enable a snapshot mode on a <code className="text-muted">fim</code> source
            (Monitoring â†’ Snapshots) and the agent will start capturing versions.
          </p>
        ) : (
          <div className="grid grid-cols-[15rem_1fr] gap-4">
            <div className="space-y-1 border-r border-border pr-3">
              {paths.map((p) => (
                <button
                  key={p.path}
                  onClick={() => { setSelected(p.path); setExpanded(null) }}
                  className={`block w-full truncate rounded-md px-2 py-1.5 text-left text-xs ${
                    selected === p.path ? 'bg-accent-soft text-accent' : 'text-muted hover:bg-surface-2'
                  }`}
                  title={p.path}
                >
                  <span className="block truncate font-mono">{p.path}</span>
                  <span className="text-[10px] text-dim">{p.versions} version{p.versions === 1 ? '' : 's'}</span>
                </button>
              ))}
            </div>
            <div>
              {selected && (
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="mr-auto truncate font-mono text-[11px] text-dim" title={selected}>{selected}</span>
                  {canSnapshot && (
                    <button
                      onClick={() => act('snapshot')}
                      disabled={busy !== ''}
                      className="rounded-md border border-border px-2 py-1 text-xs text-fg hover:bg-surface-2 disabled:opacity-50"
                    >
                      {busy === 'snapshot' ? 'Requestingâ€¦' : 'Snapshot now'}
                    </button>
                  )}
                  {canQuarantine && (
                    <button
                      onClick={() => act('quarantine')}
                      disabled={busy !== ''}
                      title="Move the current file into the agent's quarantine dir for blue-team analysis"
                      className="rounded-md border border-amber-500/40 px-2 py-1 text-xs text-amber-300 hover:bg-amber-500/10 disabled:opacity-50"
                    >
                      {busy === 'quarantine' ? 'Requestingâ€¦' : 'Quarantine infected/old file'}
                    </button>
                  )}
                </div>
              )}
              {versions.length === 0 ? (
                <p className="text-sm text-dim">Select a file.</p>
              ) : (
                <table className="w-full text-left text-xs">
                  <thead className="uppercase tracking-wider text-dim">
                    <tr>
                      <th className="py-1 font-medium">Captured</th>
                      <th className="py-1 font-medium">Trigger</th>
                      <th className="py-1 font-medium">Size</th>
                      <th className="py-1 font-medium">SHA-256</th>
                      <th className="py-1 font-medium"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {versions.map((v) => (
                      <Fragment key={v.id}>
                        <tr>
                          <td className="py-1.5 text-fg">{new Date(v.captured_at).toLocaleString()}</td>
                          <td className="py-1.5 text-muted">
                            {v.trigger}
                            <span
                              className={`ml-1.5 rounded px-1 py-0.5 text-[9px] ${v.storage === 'manager' ? 'bg-sky-500/15 text-sky-300' : 'bg-surface-2 text-muted'}`}
                              title={v.storage === 'manager' ? 'content stored on the manager' : 'content stored on the agent'}
                            >
                              {v.storage}
                            </span>
                          </td>
                          <td className="py-1.5 text-muted">{fmtBytes(v.size)}</td>
                          <td className="py-1.5 font-mono text-dim">{v.sha256.slice(0, 12)}â€¦</td>
                          <td className="whitespace-nowrap py-1.5 text-right">
                            {v.diff && (
                              <button
                                onClick={() => setExpanded(expanded === v.id ? null : v.id)}
                                className="text-accent hover:underline"
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
                                {busy === 'restore-' + v.id ? 'â€¦' : 'restore'}
                              </button>
                            )}
                            {!v.diff && !canQuarantine && <span className="text-slate-700">â€”</span>}
                          </td>
                        </tr>
                        {expanded === v.id && v.diff && (
                          <tr>
                            <td colSpan={5} className="pb-2">
                              <pre className="max-h-64 overflow-auto rounded-md bg-bg/70 p-2 font-mono text-[11px] leading-relaxed">
                                {v.diff.split('\n').map((line, i) => (
                                  <div
                                    key={i}
                                    className={line.startsWith('+') ? 'text-emerald-400' : line.startsWith('-') ? 'text-rose-400' : 'text-muted'}
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
                  <h3 className="mb-1 text-[11px] uppercase tracking-wider text-dim">Recent actions</h3>
                  <ul className="space-y-1 text-xs">
                    {actions.map((a) => (
                      <li key={a.id} className="flex flex-wrap items-center gap-2">
                        <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-fg">{a.action}</span>
                        <span className={a.status === 'done' ? 'text-emerald-400' : a.status === 'failed' ? 'text-rose-400' : 'text-dim'}>{a.status}</span>
                        {a.result && <span className="truncate font-mono text-dim" title={a.result}>{a.result}</span>}
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
          <button onClick={onClose} className="rounded-lg border border-border px-4 py-2 text-sm text-fg hover:bg-surface-2">
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
