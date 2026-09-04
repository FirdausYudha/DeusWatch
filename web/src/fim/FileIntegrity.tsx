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

// ── Editor sessions ─────────────────────────────────────────────────────────────
// vim writes its working file next to the target as .<basename>.swp, falling back to .swo then
// .swn when one is already taken. That file's lifetime IS the editing session: it appears when the
// buffer opens and is removed when the editor exits cleanly. So "how long was this file open" is
// already in the event stream — created → deleted on the swap file — and needs no new data.
const SWAP_EXTS = ['.swp', '.swo', '.swn']

function isSwapPath(p: string): boolean {
  return SWAP_EXTS.some((ext) => p.endsWith(ext))
}

// swapCandidates returns the swap-file paths vim would use for a given file.
function swapCandidates(filePath: string): string[] {
  const cut = filePath.lastIndexOf('/')
  const dir = cut >= 0 ? filePath.slice(0, cut + 1) : ''
  const base = cut >= 0 ? filePath.slice(cut + 1) : filePath
  return SWAP_EXTS.map((ext) => `${dir}.${base}${ext}`)
}

type EditorSession = { start?: string; end?: string; user?: string; process?: string }

// duration renders a span the way an operator reads it. Sub-minute precision matters here: the
// difference between a 3-second scripted write and a 4-minute hand edit is the whole signal.
function duration(fromISO: string, toISO: string): string {
  const secs = Math.max(0, Math.round((new Date(toISO).getTime() - new Date(fromISO).getTime()) / 1000))
  if (secs < 60) return `${secs}s`
  const m = Math.floor(secs / 60)
  const s = secs % 60
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m`
}

function clockTime(iso: string): string {
  return new Date(iso).toLocaleTimeString()
}

// noDiffReason explains, in the terms of THIS event, why there is no content diff. Most file
// events legitimately have none — a created file has no earlier version, a deleted one has no new
// content, and the agent only snapshots text files under FIM_SNAPSHOT_MAX_BYTES
// (internal/agent/fimdiff.go). Saying which of those applies is the difference between "the
// feature works and this case has nothing to show" and "the feature looks broken".
function noDiffReason(e: EventRow): string {
  switch (e.event_action) {
    case 'file_created':
      return 'This file was created, so there is no earlier version to compare it against. The next change to it will show a diff.'
    case 'file_deleted':
      return 'This file was deleted, so there is no new content to compare. Its last known-good version is still on the Snapshots page.'
    case 'file_encrypted':
      return 'The content was replaced with high-entropy data, which is not meaningful to show as a line diff. Compare against the last good version on the Snapshots page.'
    default:
      return 'No content diff was stored. FIM snapshots text files up to FIM_SNAPSHOT_MAX_BYTES (2 MiB by default); binaries and larger files are tracked by hash only.'
  }
}

// Fact renders one label/value pair in the expanded row, collapsing an empty value to an em dash
// rather than an empty cell so the grid keeps its shape.
function Fact({ label, value, mono = false }: { label: string; value?: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-semibold uppercase tracking-wide text-dim">{label}</dt>
      <dd className={`truncate ${mono ? 'font-mono' : ''} text-fg`} title={value || undefined}>
        {value || '—'}
      </dd>
    </div>
  )
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
    // Debounced by 300ms, matching the Dashboard's events table. Without it every keystroke in
    // the search box fired its own 500-row query: typing "index.php" meant nine of them.
    const debounce = setTimeout(load, 300)
    // Then a 30s refresh, so an incident can be watched unfolding without a reload.
    const t = setInterval(load, 30_000)
    return () => {
      cancelled = true
      clearTimeout(debounce)
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

  // Index every editor session in the fetched window, keyed by agent + swap path. Built from the
  // unfiltered rows on purpose: the kind filter must not be able to hide the swap events that
  // bound a session for a file the operator IS looking at.
  const sessions = useMemo(() => {
    const m = new Map<string, EditorSession>()
    for (const e of rows ?? []) {
      if (!e.file_path || !isSwapPath(e.file_path)) continue
      const k = `${e.agent_id}|${e.file_path}`
      const s = m.get(k) ?? {}
      if (e.event_action === 'file_created') s.start = e.time
      if (e.event_action === 'file_deleted') s.end = e.time
      if (e.user_name) s.user = e.user_name
      if (e.process_name) s.process = e.process_name
      m.set(k, s)
    }
    return m
  }, [rows])

  // sessionFor resolves a row to its editing session — directly when the row IS the swap file,
  // otherwise via the swap paths vim would have used for it.
  const sessionFor = (e: EventRow): EditorSession | undefined => {
    if (!e.file_path) return undefined
    if (isSwapPath(e.file_path)) return sessions.get(`${e.agent_id}|${e.file_path}`)
    for (const cand of swapCandidates(e.file_path)) {
      const s = sessions.get(`${e.agent_id}|${cand}`)
      if (s) return s
    }
    return undefined
  }

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
                  return (
                    <Fragment key={`${key}-${i}`}>
                      <tr
                        className={`border-b border-border/60 cursor-pointer ${open ? 'bg-surface-2' : 'hover:bg-surface-2'}`}
                        onClick={() => setOpenKey(open ? null : key)}
                        aria-expanded={open}
                      >
                        {/* Every row expands. Most file events legitimately carry no diff (created,
                            deleted, binary), and gating the caret on one being present made 8 of 9
                            rows look inert — operators read that as a broken feature rather than as
                            "nothing to diff here". The panel now always has the hash, the rule and
                            an explicit reason instead. */}
                        <td className="px-2 py-2 align-middle">
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
                            {/* Who-data: the process and the human behind the change. Rendered as
                                a labelled block rather than a sentence because these are the four
                                things an analyst reads first — what ran it, under which pid, who
                                is accountable, and whether root was involved. */}
                            {(e.process_name || e.user_name) ? (
                              <div className="mb-3 rounded-[8px] border border-border bg-bg px-3 py-2">
                                <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-[12.5px] sm:grid-cols-4">
                                  <Fact label="Process" value={e.process_name} mono />
                                  <Fact label="PID" value={e.process_pid ? String(e.process_pid) : ''} mono />
                                  <Fact label="Logged in as" value={e.user_name} mono />
                                  <Fact
                                    label="Ran as"
                                    value={e.user_effective || e.user_name}
                                    mono
                                  />
                                </dl>
                                {e.user_effective && (
                                  // Only ever set when the effective account differs from the
                                  // login account, so its presence IS the escalation.
                                  <p className="mt-2 text-[12.5px] text-medium">
                                    Privilege escalation — <span className="font-mono">{e.user_name}</span>{' '}
                                    made this change as <span className="font-mono">{e.user_effective}</span>{' '}
                                    (sudo, su, or a setuid binary).
                                  </p>
                                )}
                                <div className="mt-1.5 text-[11.5px] text-dim">
                                  who-data <DocLink file="whodata.md" label="docs" className="ml-1" />
                                </div>
                              </div>
                            ) : (
                              <p className="mb-3 text-[12.5px] text-dim">
                                No who-data for this change — the process and user behind it were not
                                recorded. On Linux this is opt-in and needs auditd:{' '}
                                <code className="font-mono text-[11.5px]">AGENT_WHODATA=1</code> in the
                                agent's environment, then restart it.{' '}
                                <DocLink file="whodata.md" label="how to enable" />
                              </p>
                            )}
                            {(() => {
                              const s = sessionFor(e)
                              if (!s || (!s.start && !s.end)) return null
                              return (
                                <div className="mb-2 rounded-[8px] border border-border bg-bg px-3 py-2 text-[12.5px]">
                                  <span className="text-dim">editor session</span>{' '}
                                  {s.start && s.end ? (
                                    <>
                                      <span className="font-mono text-fg">{clockTime(s.start)}</span>
                                      <span className="text-dim"> → </span>
                                      <span className="font-mono text-fg">{clockTime(s.end)}</span>
                                      <span className="ml-2 font-mono text-accent">
                                        {duration(s.start, s.end)}
                                      </span>
                                      <span className="text-dim"> open</span>
                                    </>
                                  ) : s.start ? (
                                    <>
                                      <span className="text-dim">opened </span>
                                      <span className="font-mono text-fg">{clockTime(s.start)}</span>
                                      <span className="ml-2 text-medium">
                                        still open, or the editor did not exit cleanly — a leftover
                                        swap file in a served directory leaks the file's contents
                                      </span>
                                    </>
                                  ) : (
                                    <>
                                      <span className="text-dim">closed </span>
                                      <span className="font-mono text-fg">{clockTime(s.end!)}</span>
                                      <span className="ml-2 text-dim">
                                        (it was opened before this time range — widen the range for
                                        the full duration)
                                      </span>
                                    </>
                                  )}
                                  {(s.user || s.process) && (
                                    <span className="text-dim">
                                      {' · '}
                                      {s.process && <span className="font-mono text-fg">{s.process}</span>}
                                      {s.user && (
                                        <>
                                          {s.process ? ' as ' : ''}
                                          <span className="font-mono text-fg">{s.user}</span>
                                        </>
                                      )}
                                    </span>
                                  )}
                                  <div className="mt-1 text-[11.5px] text-dim">
                                    Derived from the editor's own working file, not from who-data.
                                  </div>
                                </div>
                              )
                            })()}
                            {e.dw_filehash_detail && (
                              <div className="mb-2 text-[12.5px]">
                                <span className="text-dim">hash reputation:</span>{' '}
                                <span className="text-fg">{e.dw_filehash_detail}</span>
                              </div>
                            )}
                            {/* Always-present facts, so an expanded row is never empty even when
                                there is nothing to diff. */}
                            <dl className="mb-3 grid grid-cols-2 gap-x-6 gap-y-1 text-[12.5px] sm:grid-cols-4">
                              <Fact label="Rule" value={e.rule_name} />
                              <Fact label="Technique" value={e.threat_technique_id} mono />
                              <Fact label="Outcome" value={e.event_outcome} />
                              <Fact label="Endpoint" value={e.agent_id || e.host_name} />
                            </dl>
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
                              <p className="max-w-[80ch] text-[12.5px] leading-relaxed text-dim">
                                {noDiffReason(e)}
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
