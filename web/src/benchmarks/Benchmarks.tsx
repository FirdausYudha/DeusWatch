import { useState, useEffect } from 'react'
import {
  fetchBenchmarks,
  fetchBenchmarkChecks,
  can,
  type BenchmarkSummary,
  type BenchmarkCheck,
  type Me,
} from '../lib/api'
import PolicyManager from './PolicyManager'
import DocLink from '../components/DocLink'
import { Page } from '../components/ui'

// scoreTone keeps the colour tied to the number rather than to a judgement about it. A CIS
// benchmark on a host nobody has hardened yet lands in the 40s, and painting that red on day one
// teaches people the page is always red.
function scoreTone(score: number): string {
  if (score >= 90) return 'text-emerald-300'
  if (score >= 70) return 'text-amber-300'
  return 'text-rose-300'
}

export default function Benchmarks({ me }: { me: Me }) {
  const canManage = can(me, 'manage_settings')
  const [rows, setRows] = useState<BenchmarkSummary[]>([])
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [open, setOpen] = useState<BenchmarkSummary | null>(null)
  const [policies, setPolicies] = useState(false)

  useEffect(() => {
    fetchBenchmarks()
      .then(setRows)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoaded(true))
  }, [])

  return (
    <Page>
      <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-wrap gap-3">
          <DocLink file="benchmarks.md" label="Setting up policies" />
          <DocLink file="agent-groups.md" label="Agent groups" />
        </div>
        <button
          onClick={() => setPolicies(true)}
          className="rounded-[8px] border border-border px-4 py-2 text-[13.5px] font-medium text-fg transition-colors hover:bg-surface-2"
          title="Upload a CIS policy once; every agent fetches it"
        >
          Policies
        </button>
      </header>

      {error && <p className="mb-4 text-[13.5px] text-rose-400">{error}</p>}

      {loaded && rows.length === 0 && !error && (
        <div className="rounded-[12px] border border-dashed border-border px-5 py-8 text-center">
          <p className="text-[13.5px] text-muted">No assessments yet.</p>
          <p className="mx-auto mt-2 max-w-xl text-[12.5px] text-dim">
            Benchmarks need two things: a policy, and a source of type{' '}
            <code className="text-fg">sca</code> on the agent. Upload a policy under{' '}
            <span className="text-fg">Policies</span> and every agent fetches it; a policy placed
            directly on an endpoint overrides the one served here. See the setup guide above.
          </p>
        </div>
      )}

      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-[12px] border border-border">
          <table className="w-full text-left text-[13.5px]">
            <thead className="bg-surface text-[12.5px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-4 py-2 font-medium">Agent</th>
                <th className="px-4 py-2 font-medium">Policy</th>
                <th className="px-4 py-2 font-medium">Score</th>
                <th className="px-4 py-2 font-medium">Passed</th>
                <th className="px-4 py-2 font-medium">Failed</th>
                <th className="px-4 py-2 font-medium">Skipped</th>
                <th className="px-4 py-2 font-medium">Assessed</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.agent_name}:${r.policy_id}`} className="border-t border-border">
                  <td className="px-4 py-2 text-fg">{r.agent_name}</td>
                  <td className="px-4 py-2 text-muted">
                    <div className="truncate">{r.policy_name || r.policy_id}</div>
                    {r.policy_name && <div className="text-[12.5px] text-dim">{r.policy_id}</div>}
                  </td>
                  <td className={`px-4 py-2 font-medium ${scoreTone(r.score)}`}>{r.score}%</td>
                  <td className="px-4 py-2 text-emerald-300">{r.passed}</td>
                  <td className="px-4 py-2 text-rose-300">{r.failed}</td>
                  <td
                    className="px-4 py-2 text-dim"
                    title="Checks this engine could not evaluate. They are excluded from the score rather than counted as failures."
                  >
                    {r.not_applicable}
                  </td>
                  <td className="px-4 py-2 text-muted">{new Date(r.assessed_at).toLocaleString()}</td>
                  <td className="px-4 py-2">
                    <button
                      onClick={() => setOpen(r)}
                      className="rounded-md border border-border px-2 py-1 text-[12.5px] text-fg hover:bg-surface-2"
                    >
                      Controls
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {rows.length > 0 && (
        <p className="mt-3 text-[12.5px] text-dim">
          The score counts only the controls that could be evaluated. Skipped ones are excluded rather
          than failed: a control this engine cannot assess must never send somebody to change a
          production host, and counting them as failures would also let a host improve its score by
          becoming less assessable.
        </p>
      )}

      {open && <ControlList row={open} onClose={() => setOpen(null)} />}
      {policies && <PolicyManager canManage={canManage} onClose={() => setPolicies(false)} />}
    </Page>
  )
}

function ControlList({ row, onClose }: { row: BenchmarkSummary; onClose: () => void }) {
  const [checks, setChecks] = useState<BenchmarkCheck[]>([])
  const [failedOnly, setFailedOnly] = useState(true)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(true)

  useEffect(() => {
    setBusy(true)
    fetchBenchmarkChecks(row.agent_name, row.policy_id, failedOnly)
      .then(setChecks)
      .catch((e) => setError((e as Error).message))
      .finally(() => setBusy(false))
  }, [row.agent_name, row.policy_id, failedOnly])

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-[12px] border border-border bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-[16px] font-semibold text-fg">
          {row.policy_name || row.policy_id}
        </h2>
        <p className="mb-4 text-[12.5px] text-dim">
          {row.agent_name} · {row.passed} passed, {row.failed} failed, {row.not_applicable} skipped
        </p>

        <label className="mb-3 flex items-center gap-2 text-[12.5px] text-muted">
          <input type="checkbox" checked={failedOnly} onChange={(e) => setFailedOnly(e.target.checked)} />
          Only what needs work
        </label>

        {error && <p className="mb-3 text-[13.5px] text-rose-400">{error}</p>}
        {busy && <p className="text-[12.5px] text-dim">Loading…</p>}

        <div className="space-y-2">
          {!busy && checks.length === 0 && (
            <p className="rounded-[8px] border border-dashed border-border px-3 py-4 text-center text-[12.5px] text-dim">
              {failedOnly ? 'Nothing failing on this policy.' : 'No controls stored.'}
            </p>
          )}
          {checks.map((c) => (
            <div key={c.check_id} className="rounded-[8px] border border-border bg-surface-2 px-3 py-2">
              <div className="flex items-start gap-2">
                <span
                  className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[11px] ${
                    c.result === 'passed'
                      ? 'bg-emerald-400/15 text-emerald-300'
                      : c.result === 'failed'
                        ? 'bg-rose-400/15 text-rose-300'
                        : 'bg-surface text-dim'
                  }`}
                >
                  {c.result === 'not_applicable' ? 'skipped' : c.result}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-[13.5px] text-fg">{c.title}</div>
                  <div className="text-[12.5px] text-dim">
                    #{c.check_id}
                    {c.cis && c.cis.length > 0 && <> · CIS {c.cis.join(', ')}</>}
                  </div>
                  {/* The reason a control was skipped is the honest part of this page: it names a
                      gap in this engine rather than implying the host is fine. */}
                  {c.result === 'not_applicable' && c.reason && (
                    <p className="mt-1 text-[12.5px] text-amber-400/80">Not assessed: {c.reason}</p>
                  )}
                  {c.result === 'failed' && c.remediation && (
                    <p className="mt-1 whitespace-pre-wrap text-[12.5px] text-muted">
                      <span className="text-dim">Fix: </span>
                      {c.remediation}
                    </p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-5 flex justify-end">
          <button
            onClick={onClose}
            className="rounded-[8px] border border-border px-4 py-2 text-[13.5px] text-fg hover:bg-surface-2"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
