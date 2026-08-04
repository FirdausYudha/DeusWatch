import { useState, useEffect, Fragment } from 'react'
import {
  fetchAgents,
  fetchManagerVersion,
  requestAgentUpdate,
  createEnrollToken,
  fetchInstallInfo,
  fetchTenants,
  revokeAgent,
  setAgentConfig,
  agentOnline,
  can,
  type AgentInfo,
  type AgentSource,
  type Tenant,
  type Me,
} from '../lib/api'
import DocLink from '../components/DocLink'
import { Button } from '../components/ui'
import SnapshotBrowser from '../snapshots/SnapshotBrowser'

const SOURCE_TYPES = ['file', 'journald', 'wineventlog', 'fim']
const POLL_TYPES = new Set(['fim', 'wineventlog']) // types where the interval applies

// v() prints a semver with exactly one leading "v" — buildVersion baked in from `git describe`
// already carries a `v` prefix (v2.14.0-1-gabc), so blindly prepending in the template
// produces `vv2.14.0-1-gabc`. Handles both prefixed and bare inputs uniformly.
function v(s?: string | null): string {
  if (!s) return ''
  return s.startsWith('v') ? s : 'v' + s
}

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
    <span className={`rounded px-1.5 py-0.5 text-[12.5px] font-medium ${cls}`} title={title}>{label}</span>
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
  const [managerVersion, setManagerVersion] = useState('')
  const [updating, setUpdating] = useState<Record<string, boolean>>({})

  const load = () => {
    fetchAgents()
      .then(setAgents)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(() => {
    load()
    fetchManagerVersion().then(setManagerVersion).catch(() => {})
    const t = setInterval(load, 15_000)
    return () => clearInterval(t)
  }, [])

  const doUpdate = async (a: AgentInfo) => {
    setUpdating((s) => ({ ...s, [a.id]: true }))
    setError('')
    try {
      await requestAgentUpdate(a.name)
      // Optimistic: mark update_requested_at locally so the UI reflects the queued state
      // before the next fetchAgents poll.
      setAgents((cur) => cur.map((x) => (x.id === a.id ? { ...x, update_requested_at: new Date().toISOString() } : x)))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setUpdating((s) => ({ ...s, [a.id]: false }))
    }
  }
  const doUpdateAll = async () => {
    const outdated = agents.filter((a) => !a.revoked && a.agent_version && managerVersion && a.agent_version !== managerVersion)
    if (outdated.length === 0) return
    if (!confirm(`Queue self-update for ${outdated.length} agent(s)? Each picks up the directive on its next heartbeat (~30 s).`)) return
    for (const a of outdated) {
      await doUpdate(a)
    }
  }
  const outdatedCount = agents.filter((a) => !a.revoked && a.agent_version && managerVersion && a.agent_version !== managerVersion).length

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
    <div className="mx-auto max-w-[1400px] px-6 py-5">
      <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="mt-0.5 text-[13px] text-muted">Registered agents, heartbeat status &amp; centrally-pushed config</p>
          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1">
            <DocLink file="new-log-source.md" label="Add a log source" />
            <DocLink file="agent-troubleshooting.md" label="Troubleshooting" />
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
            className="rounded-[8px] bg-accent px-4 py-2 text-[13.5px] font-medium text-white transition-colors hover:opacity-90"
          >
            + Add agent
          </button>
        )}
      </header>

      {error && <p className="mb-4 text-[13.5px] text-rose-400">{error}</p>}

      {/* Warn on "dev" builds — either the manager or any agent reporting "dev" means the
          build didn't get its version stamp, which breaks the version-match auto-clear of the
          update-request flag and produces the "queued update never lands" symptom. Almost
          always caused by `docker build` without `--build-arg VERSION=…` or by a stale image
          cached before scripts/update.sh started passing the git-described version. */}
      {isAdmin && (managerVersion === 'dev' || agents.some((a) => a.agent_version === 'dev')) && (
        <div className="mb-4 rounded-[10px] border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-[13px] text-rose-200">
          <strong>Untagged build detected.</strong> {managerVersion === 'dev' ? 'The manager itself reports version "dev" — it was built without a VERSION arg. ' : ''}
          {agents.some((a) => a.agent_version === 'dev') ? 'One or more agents report "dev" — they were installed from an untagged manager image. ' : ''}
          Self-update relies on version comparison; a "dev" side will never converge. Rebuild the manager with <code className="rounded bg-rose-500/20 px-1 py-0.5 font-mono text-[12px]">scripts/update.sh</code> (it exports the git-described version), then reinstall affected agents from the Agents page.
        </div>
      )}

      {isAdmin && outdatedCount > 0 && (
        <div className="mb-4 flex items-center justify-between rounded-[10px] border border-amber-500/30 bg-amber-500/10 px-4 py-2.5 text-[13px] text-amber-200">
          <span>
            <strong>{outdatedCount}</strong> agent{outdatedCount === 1 ? '' : 's'} out of date · manager is on <strong>{v(managerVersion)}</strong>. Each self-updates on its next heartbeat (~30 s).
          </span>
          <button
            onClick={doUpdateAll}
            className="rounded-md border border-amber-400/60 bg-amber-500/20 px-3 py-1 text-[12.5px] font-medium text-amber-100 hover:bg-amber-500/30"
          >
            ↑ Update all outdated
          </button>
        </div>
      )}

      <div className="overflow-hidden rounded-[12px] border border-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-surface text-[12.5px] uppercase tracking-wider text-dim">
            <tr>
              <th className="px-4 py-2 font-medium">Name</th>
              <th className="px-4 py-2 font-medium">OS</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Heartbeat</th>
              <th className="px-4 py-2 font-medium">Version</th>
              <th className="px-4 py-2 font-medium">Config</th>
              {isAdmin && <th className="px-4 py-2 font-medium">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-surface">
            {agents.length === 0 && (
              <tr>
                <td colSpan={isAdmin ? 7 : 6} className="px-4 py-8 text-center text-dim">
                  No agents yet. Click “Add agent” to enroll one.
                </td>
              </tr>
            )}
            {agents.map((a) => (
              <tr key={a.id} className="hover:bg-surface-2">
                <td className="px-4 py-2 font-medium text-fg">{a.name}</td>
                <td className="px-4 py-2 text-muted">{a.os || '—'}</td>
                <td className="px-4 py-2"><StatusBadge a={a} /></td>
                <td className="px-4 py-2 text-muted">{relative(a.last_seen_at)}</td>
                <td className="px-4 py-2 text-muted">
                  {a.agent_version ? (
                    a.agent_version === managerVersion ? (
                      <span className="text-emerald-300" title="Agent is on the same version as the manager">{v(a.agent_version)}</span>
                    ) : (
                      <span className="text-amber-300" title={`Manager is ${v(managerVersion) || '?'}`}>{v(a.agent_version)}</span>
                    )
                  ) : (
                    <span className="text-dim" title="Pre-v2.12.0 agent — doesn't report its build. Reinstall once to enable self-update.">unknown</span>
                  )}
                  {a.update_requested_at && (
                    <span className="ml-1.5 rounded bg-accent-soft px-1.5 py-0.5 text-[11px] text-accent" title="Self-update queued; picked up on next heartbeat">
                      updating…
                    </span>
                  )}
                </td>
                <td className="px-4 py-2 text-muted">
                  v{a.config_version}
                  {a.sources && a.sources.length > 0 && (
                    <span className="ml-1 text-dim">({a.sources.length} source{a.sources.length > 1 ? 's' : ''})</span>
                  )}
                </td>
                {isAdmin && (
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-2">
                      {!a.revoked && a.agent_version && managerVersion && a.agent_version !== managerVersion && (
                        <button
                          onClick={() => doUpdate(a)}
                          disabled={updating[a.id] || !!a.update_requested_at}
                          className="rounded-md border border-accent/40 bg-accent-soft px-2 py-1 text-[12.5px] text-accent hover:bg-accent hover:text-white disabled:opacity-50"
                          title={`Push new binary (${v(managerVersion)}); agent applies on next heartbeat`}
                        >
                          {a.update_requested_at ? 'Queued' : updating[a.id] ? 'Queuing…' : `↑ Update to ${v(managerVersion)}`}
                        </button>
                      )}
                      <button
                        onClick={() => setEditing(a)}
                        className="rounded-md border border-border px-2 py-1 text-[12.5px] text-fg hover:bg-surface-2"
                      >
                        Monitoring
                      </button>
                      <button
                        onClick={() => setSnapshotsFor(a)}
                        className="rounded-md border border-border px-2 py-1 text-[12.5px] text-fg hover:bg-surface-2"
                        title="Browse the dated FIM snapshot timeline of this agent's watched files"
                      >
                        Snapshots
                      </button>
                      <button
                        onClick={() => setUninstalling(a)}
                        className="rounded-md border border-border px-2 py-1 text-[12.5px] text-fg hover:bg-surface-2"
                        title="Show commands to uninstall this agent from its endpoint"
                      >
                        Uninstall
                      </button>
                      {!a.revoked && (
                        <button
                          onClick={() => doRevoke(a)}
                          className="rounded-md border border-rose-500/40 px-2 py-1 text-[12.5px] text-rose-300 hover:bg-rose-500/10"
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
      <div className="w-full max-w-2xl rounded-[12px] border border-border bg-surface p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h3 className="mb-1 text-[13.5px] font-semibold text-fg">
          Uninstall agent — <span className="text-accent">{agent.name}</span>
          <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 text-[11px] uppercase text-muted">{agent.os || 'linux'}</span>
        </h3>
        <p className="mb-4 text-[12.5px] text-dim">
          Cleanest way: <span className="text-fg">Revoke</span> this agent — it self-uninstalls on its
          next heartbeat. Run the commands below on the endpoint for a manual or forced cleanup.
        </p>
        <div className="mb-2 text-[12.5px] font-medium uppercase tracking-wider text-dim">
          Run on the {isWindows ? 'Windows endpoint (elevated PowerShell)' : 'Linux endpoint'}
        </div>
        <Copyable text={isWindows ? windows : linux} />
        <p className="mt-3 text-[12.5px] text-dim">
          Removing the certs de-enrolls the host; re-installing later issues a fresh certificate.
        </p>
        <div className="mt-5 flex justify-end">
          <button onClick={onClose} className="rounded-[8px] border border-border px-4 py-2 text-[13.5px] text-fg hover:bg-surface-2">Close</button>
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
        className="absolute right-2 top-2 rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-accent hover:bg-surface-2"
      >
        {copied ? 'copied ✓' : 'copy'}
      </button>
      <code className="block whitespace-pre-wrap break-all rounded-[8px] border border-border bg-bg px-3 py-2 pr-14 text-[12.5px] text-emerald-300">
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
  // Multi-tenancy: bind the enrolling agent (and all its telemetry) to a tenant. Only shown when
  // more than one tenant exists; otherwise the agent enrolls into Default.
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [tenantID, setTenantID] = useState('')

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

  const gen = async (tid = tenantID) => {
    setBusy(true)
    setError('')
    try {
      const { token } = await createEnrollToken(tid)
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
    fetchTenants()
      .then(setTenants)
      .catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-xl rounded-[12px] border border-border bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-[16px] font-semibold text-fg">Add agent</h2>
        <p className="mb-4 text-[12.5px] text-dim">Pick the endpoint’s platform, then run the generated command on it.</p>

        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <span className="mb-1 block text-[12.5px] font-medium text-muted">Operating system</span>
            <select
              value={os}
              onChange={(e) => setOs(e.target.value)}
              className="w-full rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[13.5px] outline-none focus:border-accent"
            >
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
            </select>
          </label>
          <label className="block">
            <span className="mb-1 block text-[12.5px] font-medium text-muted">Agent name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. web01"
              className="w-full rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[13.5px] outline-none focus:border-accent"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-[12.5px] font-medium text-muted">Manager host</span>
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              className="w-full rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[13.5px] outline-none focus:border-accent"
            />
          </label>
          {tenants.length > 1 && (
            <label className="block">
              <span className="mb-1 block text-[12.5px] font-medium text-muted">Tenant</span>
              <select
                value={tenantID}
                onChange={(e) => {
                  setTenantID(e.target.value)
                  void gen(e.target.value) // re-issue the token bound to the chosen tenant
                }}
                className="w-full rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[13.5px] outline-none focus:border-accent"
              >
                <option value="">Default</option>
                {tenants
                  .filter((t) => t.slug !== 'default')
                  .map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
              </select>
            </label>
          )}
        </div>

        <div className="mt-5 space-y-4">
          <div>
            <div className="mb-1 text-[12.5px] font-medium text-muted">
              1 · On the manager — open the firewall <span className="text-dim">(elevated PowerShell, once)</span>
            </div>
            <Copyable text={managerFw} />
          </div>
          <div>
            <div className="mb-1 text-[12.5px] font-medium text-muted">
              2 · On the endpoint — paste &amp; run{' '}
              <span className="text-dim">{os === 'windows' ? '(elevated PowerShell)' : '(root; sudo is included)'}</span>
            </div>
            <Copyable text={install} />
            {!token && (
              <p className="mt-1 text-[12.5px] text-amber-400/80">{busy ? 'Generating token…' : 'No token yet — click “Generate token”.'}</p>
            )}
            <p className="mt-1 text-[12.5px] text-dim">
              Downloads the agent, opens its firewall, enrolls with the token, installs an auto-start service, and connects to the gateway.
            </p>
          </div>
        </div>

        {error && <p className="mt-3 text-[13.5px] text-rose-400">{error}</p>}

        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-[8px] border border-border px-4 py-2 text-[13.5px] text-fg hover:bg-surface-2">
            Close
          </button>
          <button
            onClick={() => gen()}
            disabled={busy}
            className="rounded-[8px] bg-accent px-4 py-2 text-[13.5px] font-medium text-white hover:opacity-90 disabled:opacity-50"
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
        className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-[12px] border border-border bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-[16px] font-semibold text-fg">Monitoring — {agent.name}</h2>
        <p className="mb-4 text-[12.5px] text-dim">
          Choose what this agent collects. For <code className="text-fg">fim</code> &amp;{' '}
          <code className="text-fg">wineventlog</code> set a scan interval (seconds) to control intensity.
          Saving bumps the version &amp; the agent re-applies on its next poll.
        </p>

        <div className="space-y-2">
          <div className="grid grid-cols-[1fr_8rem_1.6fr_6rem_2rem] gap-2 px-1 text-[12.5px] uppercase tracking-wider text-dim">
            <span>Dataset</span>
            <span>Type</span>
            <span>Path</span>
            <span>Interval</span>
            <span></span>
          </div>
          {sources.length === 0 && (
            <p className="rounded-[8px] border border-dashed border-border px-3 py-4 text-center text-[12.5px] text-dim">
              No sources. Add one below (or save empty to clear).
            </p>
          )}
          {sources.map((s, i) => (
            <div key={i} className="grid grid-cols-[1fr_8rem_1.6fr_6rem_2rem] gap-2">
              <input
                value={s.dataset}
                onChange={(e) => update(i, { dataset: e.target.value })}
                placeholder="sshd"
                className="rounded-[8px] border border-border bg-surface-2 px-2 py-1.5 text-[13.5px] outline-none focus:border-accent"
              />
              <select
                value={s.type}
                onChange={(e) => update(i, { type: e.target.value })}
                className="rounded-[8px] border border-border bg-surface-2 px-2 py-1.5 text-[13.5px] outline-none focus:border-accent"
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
                className="rounded-[8px] border border-border bg-surface-2 px-2 py-1.5 text-[13.5px] outline-none focus:border-accent"
              />
              {POLL_TYPES.has(s.type) ? (
                <input
                  type="number"
                  min={1}
                  value={s.interval || ''}
                  onChange={(e) => update(i, { interval: Number(e.target.value) })}
                  placeholder={s.type === 'fim' ? '60' : '5'}
                  className="rounded-[8px] border border-border bg-surface-2 px-2 py-1.5 text-[13.5px] outline-none focus:border-accent"
                />
              ) : (
                <span className="grid place-items-center text-[12.5px] text-dim">live</span>
              )}
              <button
                onClick={() => removeRow(i)}
                className="grid place-items-center rounded-[8px] border border-border text-muted hover:bg-surface-2"
                title="Remove"
              >
                ✕
              </button>
              {s.type === 'fim' && (
                <div className="col-span-5 mb-1 grid grid-cols-[auto_1fr_auto_1fr_auto_5rem] items-center gap-2 rounded-[8px] border border-border bg-surface px-2 py-1.5 text-xs">
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
                    title="Where version content is kept — the admin's choice (agent = host only; manager = central copy)"
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
                    placeholder="∞"
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
          className="mt-3 rounded-[8px] border border-dashed border-border px-3 py-1.5 text-[12.5px] text-fg hover:bg-surface-2"
        >
          + Add source
        </button>

        {error && <p className="mt-3 text-[13.5px] text-rose-400">{error}</p>}
        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-[8px] border border-border px-4 py-2 text-[13.5px] text-fg hover:bg-surface-2">
            Cancel
          </button>
          <button
            onClick={save}
            disabled={busy}
            className="rounded-[8px] bg-accent px-4 py-2 text-[13.5px] font-medium text-white hover:opacity-90 disabled:opacity-50"
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

// SnapshotViewer is a thin modal around the shared browser (the full page lives in
// snapshots/Snapshots.tsx) so the timeline, diff and destructive actions have one implementation.
function SnapshotViewer({ agent, me, onClose }: { agent: AgentInfo; me: Me; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="max-h-[90vh] w-full max-w-4xl overflow-y-auto rounded-[12px] border border-border bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 flex items-center justify-between gap-3">
          <h2 className="text-[16px] font-semibold text-fg">FIM snapshots — {agent.name}</h2>
          <DocLink file="adr/0002-versioned-fim-snapshots.md" label="About snapshots" className="shrink-0" />
        </div>
        <p className="mb-3 text-[12.5px] text-dim">
          Dated version timeline of watched files. Expand a version to see the old-vs-new diff.
        </p>
        <SnapshotBrowser agentName={agent.name} me={me} />
        <div className="mt-5 flex justify-end">
          <Button onClick={onClose}>Close</Button>
        </div>
      </div>
    </div>
  )
}
