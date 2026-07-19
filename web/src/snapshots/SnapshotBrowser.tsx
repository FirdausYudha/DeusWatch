import { useEffect, useState, Fragment } from 'react'
import {
  fetchSnapshotPaths,
  fetchSnapshots,
  fetchFileActions,
  snapshotNow,
  quarantineFile,
  restoreVersion,
  bulkRestore,
  can,
  type FIMSnapshot,
  type FIMSnapshotPath,
  type FileAction,
  type Me,
} from '../lib/api'
import { Button, Input, Pill, EmptyState, ErrorText, NoticeBanner } from '../components/ui'

const fmtBytes = (n: number) =>
  n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`

/**
 * SnapshotBrowser is the FIM forensic surface: a watched file's dated version timeline with the
 * old-vs-new diff, per-version restore, on-demand snapshot/quarantine, and the ransomware
 * point-in-time bulk revert. Shared by the Snapshots page and the Agents modal so there is one
 * implementation of these (destructive) actions.
 */
export default function SnapshotBrowser({ agentName, me }: { agentName: string; me: Me }) {
  const [paths, setPaths] = useState<FIMSnapshotPath[]>([])
  const [selected, setSelected] = useState('')
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
    fetchSnapshotPaths(agentName)
      .then((p) => {
        setPaths(p)
        setSelected((cur) => cur || (p.length > 0 ? p[0].path : ''))
      })
      .catch((e) => setError((e as Error).message))

  useEffect(() => {
    setLoading(true)
    setSelected('')
    loadPaths().finally(() => setLoading(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentName])

  const loadFile = () => {
    if (!selected) {
      setVersions([])
      setActions([])
      return
    }
    fetchSnapshots(agentName, selected).then(setVersions).catch((e) => setError((e as Error).message))
    fetchFileActions(agentName, selected).then(setActions).catch(() => {})
  }
  useEffect(loadFile, [agentName, selected])

  const refreshSoon = () => setTimeout(() => { loadFile(); loadPaths() }, 3000)

  const act = async (kind: 'snapshot' | 'quarantine') => {
    if (!selected) return
    if (
      kind === 'quarantine' &&
      !confirm(
        `Quarantine ${selected} on ${agentName}?\n\nThe current file is MOVED into the agent's quarantine dir (read-only) for blue-team analysis. Restore a good version afterwards if needed.`,
      )
    )
      return
    setBusy(kind); setError(''); setMsg('')
    try {
      if (kind === 'snapshot') {
        await snapshotNow(agentName, selected)
        setMsg('Snapshot requested — the agent captures it on its next poll (~10s).')
      } else {
        await quarantineFile(agentName, selected)
        setMsg('Quarantine requested — the agent moves the file on its next poll (~10s).')
      }
      refreshSoon()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  const restore = async (v: FIMSnapshot) => {
    if (
      !confirm(
        `Restore ${selected} to the version from ${new Date(v.captured_at).toLocaleString()}?\n\nThe current file is snapshotted first (nothing is lost), then overwritten with this version.`,
      )
    )
      return
    setBusy('restore-' + v.id); setError(''); setMsg('')
    try {
      await restoreVersion(agentName, selected, v.sha256)
      setMsg('Restore requested — the agent applies it on its next poll (~10s).')
      refreshSoon()
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
    if (
      !confirm(
        `Roll back ALL of ${agentName}'s watched files to their versions as of ${asOf.toLocaleString()}?\n\nRansomware recovery: each file's current content is snapshotted first, then overwritten with its as-of version. Files whose content lives only on a lost agent cannot be restored — manager-stored versions can.`,
      )
    )
      return
    setBusy('bulk'); setError(''); setMsg('')
    try {
      const n = await bulkRestore(agentName, '', asOf.toISOString())
      setMsg(`Point-in-time revert requested for ${n} file(s) — the agent applies them on its next polls.`)
      refreshSoon()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  if (loading) return <p className="text-[12px] text-dim">Loading…</p>

  if (paths.length === 0) {
    return (
      <EmptyState
        title="No snapshots recorded for this agent yet"
        hint="Enable a snapshot mode on a fim source (Agents → Monitoring → Snapshots) and the agent will start capturing dated versions."
      />
    )
  }

  return (
    <div className="space-y-4">
      {canQuarantine && (
        <NoticeBanner
          tone="warn"
          title="Ransomware recovery — roll all files back to a point in time"
          action={
            <div className="flex items-center gap-2">
              <Input type="datetime-local" value={bulkAt} onChange={(e) => setBulkAt(e.target.value)} />
              <Button variant="danger" onClick={doBulkRestore} disabled={busy !== '' || !bulkAt}>
                {busy === 'bulk' ? 'Requesting…' : 'Restore all'}
              </Button>
            </div>
          }
        >
          Every watched file is reverted to its version as of the chosen time. Each file is
          snapshotted first, so nothing is lost.
        </NoticeBanner>
      )}

      <div className="grid grid-cols-[15rem_1fr] gap-4">
        {/* Watched files */}
        <div className="space-y-1 border-r border-border pr-3">
          {paths.map((p) => (
            <button
              key={p.path}
              onClick={() => { setSelected(p.path); setExpanded(null) }}
              className={`block w-full truncate rounded-[8px] px-2 py-1.5 text-left ${
                selected === p.path ? 'bg-accent-soft text-accent' : 'text-muted hover:bg-surface-2'
              }`}
              title={p.path}
            >
              <span className="block truncate font-mono text-[11.5px]">{p.path}</span>
              <span className="text-[10px] text-dim">
                {p.versions} version{p.versions === 1 ? '' : 's'}
              </span>
            </button>
          ))}
        </div>

        {/* Version timeline */}
        <div>
          {selected && (
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <span className="mr-auto truncate font-mono text-[11px] text-dim" title={selected}>
                {selected}
              </span>
              {canSnapshot && (
                <Button onClick={() => act('snapshot')} disabled={busy !== ''}>
                  {busy === 'snapshot' ? 'Requesting…' : 'Snapshot now'}
                </Button>
              )}
              {canQuarantine && (
                <Button
                  variant="danger"
                  onClick={() => act('quarantine')}
                  disabled={busy !== ''}
                  title="Move the current file into the agent's quarantine dir for blue-team analysis"
                >
                  {busy === 'quarantine' ? 'Requesting…' : 'Quarantine infected/old file'}
                </Button>
              )}
            </div>
          )}

          {versions.length === 0 ? (
            <p className="text-[12px] text-dim">Select a file.</p>
          ) : (
            <table className="w-full text-left text-[11.5px]">
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
                        <Pill
                          className={`ml-1.5 ${v.storage === 'manager' ? 'bg-manager/15 text-manager' : 'bg-surface-2 text-muted'}`}
                        >
                          {v.storage}
                        </Pill>
                      </td>
                      <td className="py-1.5 text-muted">{fmtBytes(v.size)}</td>
                      <td className="py-1.5 font-mono text-dim">{v.sha256.slice(0, 12)}…</td>
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
                            className="ml-3 text-medium hover:underline disabled:opacity-50"
                          >
                            {busy === 'restore-' + v.id ? '…' : 'restore'}
                          </button>
                        )}
                        {!v.diff && !canQuarantine && <span className="text-dim">—</span>}
                      </td>
                    </tr>
                    {expanded === v.id && v.diff && (
                      <tr>
                        <td colSpan={5} className="pb-2">
                          <pre className="max-h-64 overflow-auto rounded-[8px] bg-bg p-2 font-mono text-[11px] leading-relaxed">
                            {v.diff.split('\n').map((line, i) => (
                              <div
                                key={i}
                                className={
                                  line.startsWith('+')
                                    ? 'text-success'
                                    : line.startsWith('-')
                                      ? 'text-critical'
                                      : 'text-muted'
                                }
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
              <h3 className="mb-1 text-[10px] font-medium uppercase tracking-wider text-dim">Recent actions</h3>
              <ul className="space-y-1">
                {actions.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-2 text-[11.5px]">
                    <Pill className="bg-surface-2 text-fg">{a.action}</Pill>
                    <span
                      className={
                        a.status === 'done' ? 'text-success' : a.status === 'failed' ? 'text-critical' : 'text-dim'
                      }
                    >
                      {a.status}
                    </span>
                    {a.result && (
                      <span className="truncate font-mono text-dim" title={a.result}>
                        {a.result}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {error && <ErrorText>{error}</ErrorText>}
      {msg && <p className="text-[12px] text-success">{msg}</p>}
    </div>
  )
}
