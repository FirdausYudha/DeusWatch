import { Fragment, useEffect, useMemo, useState } from 'react'
import { searchEvents, fetchAgents, type EventRow, type AgentInfo } from '../lib/api'
import type { DashRangeState } from '../lib/range'
import { PageHeader, Card, StatCard, SeverityBadge, Pill, Input, Select, EmptyState, ErrorText } from '../components/ui'
import DocLink from '../components/DocLink'

/**
 * FileIntegrity is the dedicated monitoring page for everything that happens to files on an
 * endpoint: ordinary FIM changes, ransomware encryption, known-bad hashes and webshell drops.
 *
 * It exists because these events were drowning in the main dashboard's mixed stream — one
 * defacement is three rows among two hundred SSH failures. Here the domain gets its own summary
 * and its own columns (path, action, hash verdict, diff), which the shared Events table cannot
 * afford to spend width on.
 *
 * Deliberately READ-ONLY. Restore, quarantine and point-in-time rollback already live on the
 * Snapshots page, tested and permission-gated; duplicating those controls here would mean two
 * implementations of the same destructive actions. Each row instead links straight to Snapshots
 * for the agent and file in question.
 */

const LIMIT = 500

type Kind = 'ransomware' | 'malware' | 'webshell' | 'change'

// kindOf classifies a file event from the data the detection rules actually key on, not from a
// label string. Verified against the rules themselves:
//   - rules/sigma/ransomware_file_encrypted.yml  -> event.action = file_encrypted
//   - rules/sigma/malicious_file_hash.yml        -> deuswatch.file_hash.verdict = known_bad
// The rule-name checks are the fallback for rules that carry no distinguishing field of their
// own (the webshell containment rule matches on path + extension).
function kindOf(e: EventRow): Kind {
  if (e.event_action === 'file_encrypted') return 'ransomware'
  if (e.dw_filehash_verdict === 'known_bad') return 'malware'
  const rule = (e.rule_name || '').toLowerCase()
  if (rule.includes('webshell')) return 'webshell'
  if (rule.includes('ransomware')) return 'ransomware'
  return 'change'
}

const KIND_STYLE: Record<Kind, string> = {
  ransomware: 'bg-critical/15 text-critical',
  malware: 'bg-critical/15 text-critical',
  webshell: 'bg-high/15 text-high',
  change: 'bg-info/15 text-info',
}
const KIND_LABEL: Record<Kind, string> = {
  ransomware: 'ransomware',
  malware: 'malware',
  webshell: 'webshell',
  change: 'file change',
}

// Short, readable action text. The normalizer emits file_created / file_modified / file_deleted /
// file_encrypted (internal/ingest/normalize.go).
function actionText(a: string): string {
  return (a || '').replace(/^file_/, '') || '—'
}

// rowKey identifies a row by its content so the expanded panel survives a refresh and stays on
// the file the operator actually opened.
function rowKey(e: EventRow): string {
  return `${e.time}|${e.agent_id}|${e.file_path}|${e.event_action}`
}

export default function FileIntegrity({
  range,
  onOpenSnapshots,
}: {
  range: DashRangeState
  onOpenSnapshots?: (agent: string, path: string) => void
}) {
  const [rows, setRows] = useState<EventRow[] | null>(null)
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [err, setErr] = useState('')
  const [q, setQ] = useState('')
  const [kind, setKind] = useState<'all' | Kind>('all')
  const [agent, setAgent] = useState('')
  // Keyed by row identity, not list index. The table re-polls every 30s and rows shift as new
  // events arrive, so an index would silently re-point the open panel at a different file.
  const [openKey, setOpenKey] = useState<string | null>(null)

  useEffect(() => {
    fetchAgents().then(setAgents).catch(() => {})
  }, [])

  useEffect(() => {
    let cancelled = false
    const load = () => {
      const r = range.resolved
      const from = r?.from
        ? r.from.toISOString()
        : r?.hours
          ? new Date(Date.now() - r.hours * 3_600_000).toISOString()
          : undefined
      searchEvents({ category: 'file', q: q || undefined, agent: agent || undefined, from, to: r?.to?.toISOString(), limit: LIMIT })
        .then((res) => {
          if (cancelled) return
          setRows(res)
          setErr('')
        })
        .catch((e) => !cancelled && setErr(String((e as Error).message ?? e)))
    }
    load()
    // Same 30s cadence as the geo map — fresh enough to watch an incident unfold without
    // hammering the API while an operator reads a diff.
    const t = setInterval(load, 30_000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [range.preset, range.from, range.to, q, agent])

  // Summary is computed from the rows actually fetched. That is honest only while the query fits
  // under LIMIT — past that the server truncated and the counts are floors, which `capped` says
  // out loud rather than quietly under-reporting.
  const summary = useMemo(() => {
    const list = rows ?? []
    const hosts = new Set<string>()
    let ransom = 0
    let bad = 0
    for (const e of list) {
      if (e.agent_id || e.host_name) hosts.add(e.agent_id || e.host_name)
      const k = kindOf(e)
      if (k === 'ransomware') ransom++
      if (k === 'malware') bad++
    }
    return { total: list.length, ransom, bad, hosts: hosts.size, capped: list.length >= LIMIT }
  }, [rows])

  const shown = useMemo(() => {
    const list = rows ?? []
    return kind === 'all' ? list : list.filter((e) => kindOf(e) === kind)
  }, [rows, kind])

  const cap = summary.capped ? '≥' : ''

  return (
    <div className="p-5">
      <PageHeader
        subtitle="File changes, ransomware and malware across every endpoint"
        actions={<DocLink file="features/13-file-integrity.md" />}
      />

      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label="File events"
          value={rows === null ? '…' : `${cap}${summary.total}`}
          hint={summary.capped ? `newest ${LIMIT} in range — narrow the filters for exact counts` : 'in the selected range'}
        />
        <StatCard
          label="Ransomware signals"
          value={rows === null ? '…' : `${cap}${summary.ransom}`}
          accentClass={summary.ransom > 0 ? 'text-critical' : 'text-fg'}
          hint="file encrypted in place"
        />
        <StatCard
          label="Known-bad files"
          value={rows === null ? '…' : `${cap}${summary.bad}`}
          accentClass={summary.bad > 0 ? 'text-critical' : 'text-fg'}
          hint="hash matched a reputation feed"
        />
        <StatCard
          label="Endpoints touched"
          value={rows === null ? '…' : `${cap}${summary.hosts}`}
          hint="distinct agents with file activity"
        />
      </div>

      <Card
        title="File activity"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="path, hash, host…"
              className="w-48"
              aria-label="Search file events"
            />
            <Select value={kind} onChange={(e) => setKind(e.target.value as 'all' | Kind)} aria-label="Filter by kind">
              <option value="all">All kinds</option>
              <option value="change">File changes</option>
              <option value="ransomware">Ransomware</option>
              <option value="malware">Malware</option>
              <option value="webshell">Webshell</option>
            </Select>
            <Select value={agent} onChange={(e) => setAgent(e.target.value)} aria-label="Filter by agent">
              <option value="">All agents</option>
              {agents.map((a) => (
                <option key={a.id} value={a.name}>{a.name}</option>
              ))}
            </Select>
          </div>
        }
        bodyClass=""
      >
        {err && <div className="p-4"><ErrorText>{err}</ErrorText></div>}
        {!err && rows === null && <div className="p-6 text-center text-[13.5px] text-dim">loading…</div>}
        {!err && rows !== null && shown.length === 0 && (
          <div className="p-4">
            <EmptyState
              title="No file activity in this range"
              hint="Watched paths are configured per agent, under Agents → the endpoint → FIM. Nothing here also means nothing changed, which is the good outcome."
            />
          </div>
        )}
        {!err && shown.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[52rem] border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-border text-left text-[11.5px] uppercase tracking-wider text-dim">
                  <th className="w-8 px-2 py-2 font-medium"><span className="sr-only">Expand</span></th>
                  <th className="px-4 py-2 font-medium">Time</th>
                  <th className="px-4 py-2 font-medium">Kind</th>
                  <th className="px-4 py-2 font-medium">Sev</th>
                  <th className="px-4 py-2 font-medium">Action</th>
                  <th className="px-4 py-2 font-medium">Path</th>
                  <th className="px-4 py-2 font-medium">Endpoint</th>
                  <th className="px-4 py-2 font-medium">Verdict</th>
                  <th className="px-4 py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {shown.map((e, i) => {
                  const k = kindOf(e)
                  const key = rowKey(e)
                  const open = openKey === key
                  const hasDetail = Boolean(e.file_diff || e.dw_filehash_detail || e.process_name)
                  return (
                    <Fragment key={`${key}-${i}`}>
                      <tr
                        className={`border-b border-border/60 ${
                          open
                            ? 'bg-surface-2'
                            : hasDetail
                              ? 'cursor-pointer hover:bg-surface-2'
                              : ''
                        }`}
                        onClick={() => hasDetail && setOpenKey(open ? null : key)}
                        aria-expanded={hasDetail ? open : undefined}
                      >
                        {/* Disclosure caret — present only on rows that actually have something to
                            show, so "clickable" is visible before the click rather than discovered
                            by a click that does nothing. */}
                        <td className="px-2 py-2 align-middle">
                          {hasDetail && (
                            <svg
                              viewBox="0 0 24 24"
                              className={`h-3.5 w-3.5 transition-transform ${open ? 'rotate-90 text-accent' : 'text-dim'}`}
                              fill="none"
                              stroke="currentColor"
                              strokeWidth={2.5}
                              aria-hidden="true"
                            >
                              <path d="M9 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 font-mono text-[12px] text-muted">
                          {new Date(e.time).toLocaleString()}
                        </td>
                        <td className="px-4 py-2"><Pill className={KIND_STYLE[k]}>{KIND_LABEL[k]}</Pill></td>
                        <td className="px-4 py-2"><SeverityBadge level={e.event_severity} /></td>
                        <td className="whitespace-nowrap px-4 py-2 text-muted">{actionText(e.event_action)}</td>
                        <td className="max-w-[22rem] truncate px-4 py-2 font-mono text-[12px] text-fg" title={e.file_path}>
                          {e.file_path || '—'}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 text-muted">{e.agent_id || e.host_name || '—'}</td>
                        <td className="whitespace-nowrap px-4 py-2">
                          {e.dw_filehash_verdict === 'known_bad' ? (
                            <span className="text-critical">known bad</span>
                          ) : e.dw_filehash_verdict === 'known_good' ? (
                            <span className="text-low">known good</span>
                          ) : (
                            <span className="text-dim">—</span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 text-right">
                          {e.agent_id && e.file_path && onOpenSnapshots && (
                            <button
                              type="button"
                              onClick={(ev) => { ev.stopPropagation(); onOpenSnapshots(e.agent_id, e.file_path) }}
                              className="text-[12.5px] text-accent transition-colors hover:underline"
                              title="Open this file's version timeline, where you can diff and restore it"
                            >
                              Snapshots ↗
                            </button>
                          )}
                        </td>
                      </tr>
                      {open && (
                        // Same tint as the opened row above it, so panel and row read as one
                        // block instead of a detached box floating under the table.
                        <tr className="border-b border-border bg-surface-2">
                          <td />
                          <td colSpan={8} className="px-4 pb-4 pt-1">
                            <div className="mb-2 truncate text-[12.5px]">
                              <span className="text-dim">detail for </span>
                              <span className="font-mono text-fg">{e.file_path || '—'}</span>
                            </div>
                            {(e.process_name || e.user_name) && (
                              <div className="mb-2 text-[12.5px] text-muted">
                                changed by{' '}
                                {e.process_name && (
                                  <span className="font-mono text-fg">
                                    {e.process_name}{e.process_pid ? ` (pid ${e.process_pid})` : ''}
                                  </span>
                                )}
                                {e.user_name && (
                                  <> {e.process_name ? 'as user ' : 'user '}<span className="font-mono text-fg">{e.user_name}</span></>
                                )}
                                <span className="ml-1 text-dim">· who-data</span>
                                <DocLink file="whodata.md" label="docs" className="ml-2" />
                              </div>
                            )}
                            {e.dw_filehash_detail && (
                              <div className="mb-2 text-[12.5px]">
                                <span className="text-dim">hash reputation:</span>{' '}
                                <span className="text-fg">{e.dw_filehash_detail}</span>
                              </div>
                            )}
                            {e.file_hash_sha256 && (
                              <div className="mb-2 break-all font-mono text-[11.5px] text-dim">
                                sha256 {e.file_hash_sha256}
                              </div>
                            )}
                            {e.file_diff ? (
                              <pre className="max-h-80 overflow-auto rounded-[8px] border border-border bg-bg p-2 font-mono text-[12.5px] leading-relaxed">
                                {e.file_diff.split('\n').map((line, k2) => (
                                  <div
                                    key={k2}
                                    className={line.startsWith('+') ? 'text-emerald-400' : line.startsWith('-') ? 'text-rose-400' : 'text-dim'}
                                  >
                                    {line}
                                  </div>
                                ))}
                              </pre>
                            ) : (
                              <p className="text-[12.5px] text-dim">
                                No content diff stored for this event — the watch may be metadata-only, or the file is binary.
                              </p>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
