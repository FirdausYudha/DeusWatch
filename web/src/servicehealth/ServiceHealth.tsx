import { useEffect, useMemo, useState } from 'react'
import {
  can,
  clearServiceCheckHeaders,
  createServiceCheck,
  deleteServiceCheck,
  fetchServiceCheckHistory,
  fetchServiceChecks,
  updateServiceCheck,
  type Me,
  type ServiceCheck,
  type ServiceCheckInput,
  type ServiceCheckPoint,
} from '../lib/api'
import { Button, Card, EmptyState, ErrorText, Input, Page, PageHeader, Select, StatCard } from '../components/ui'

// Service & API Health.
//
// The gap this closes came from the hospital's own infrastructure team: ping is green, the server
// is up, the dashboard is quiet — and the registration desk cannot register anyone because one
// integration endpoint answers HTTP 200 with a failure inside the payload, or takes nine seconds
// to answer. Host monitoring never sees that. This page watches the ENDPOINTS a business function
// depends on, which is why checks are grouped by business function rather than by host.

const REFRESH_MS = 15000

type Status = 'up' | 'down' | 'pending' | 'paused'

function statusOf(c: ServiceCheck): Status {
  if (!c.enabled) return 'paused'
  if (c.last_ok === null) return 'pending'
  return c.last_ok ? 'up' : 'down'
}

const STATUS_STYLE: Record<Status, { label: string; cls: string }> = {
  up: { label: 'Up', cls: 'bg-ok/15 text-ok' },
  down: { label: 'Down', cls: 'bg-critical/15 text-critical' },
  pending: { label: 'Not checked yet', cls: 'bg-surface-2 text-dim' },
  paused: { label: 'Paused', cls: 'bg-surface-2 text-muted' },
}

function StatusPill({ status }: { status: Status }) {
  const s = STATUS_STYLE[status]
  return (
    <span className={`inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-[12px] font-semibold ${s.cls}`}>
      {s.label}
    </span>
  )
}

function ago(iso: string | null): string {
  if (!iso) return 'never'
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`
  return `${Math.round(secs / 3600)}h ago`
}

export default function ServiceHealth({ me }: { me: Me }) {
  const [checks, setChecks] = useState<ServiceCheck[]>([])
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [editing, setEditing] = useState<ServiceCheck | 'new' | null>(null)
  const [openId, setOpenId] = useState<string | null>(null)

  const canManage = can(me, 'manage_settings')

  const load = () =>
    fetchServiceChecks()
      .then((cs) => {
        setChecks(cs)
        setError('')
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoaded(true))

  useEffect(() => {
    load()
    const t = setInterval(load, REFRESH_MS)
    return () => clearInterval(t)
  }, [])

  // Grouped by business function, because "pendaftaran is broken" is the sentence an operator
  // needs, not "endpoint 7 of 12 is red".
  const groups = useMemo(() => {
    const by = new Map<string, ServiceCheck[]>()
    for (const c of checks) {
      const g = c.service_group || 'Ungrouped'
      by.set(g, [...(by.get(g) ?? []), c])
    }
    return [...by.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [checks])

  const down = checks.filter((c) => statusOf(c) === 'down')
  const enabled = checks.filter((c) => c.enabled)
  // Averaged over the enabled checks that have actually run, so a pending check does not drag it.
  const measured = enabled.filter((c) => c.last_ok !== null)
  const avgLatency = measured.length
    ? Math.round(measured.reduce((s, c) => s + c.last_latency_ms, 0) / measured.length)
    : null

  return (
    <Page>
      <PageHeader
        subtitle="Probes the endpoints your workflows depend on — not just whether the host answers a ping"
        actions={
          canManage && (
            <Button variant="primary" onClick={() => setEditing('new')}>
              Add check
            </Button>
          )
        }
      />

      {error && <ErrorText>{error}</ErrorText>}

      {editing && (
        <CheckForm
          check={editing === 'new' ? null : editing}
          onCancel={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            load()
          }}
        />
      )}

      {loaded && checks.length === 0 && !editing ? (
        <EmptyState
          title="No service checks yet"
          hint="Add the endpoints a business function depends on — a registration API, a claims web service, the fingerprint reader's port — and DeusWatch will tell you when one stops working, even while the server stays up."
          action={canManage ? <Button variant="primary" onClick={() => setEditing('new')}>Add the first check</Button> : undefined}
        />
      ) : (
        checks.length > 0 && (
          <>
            <div className="mb-5 grid gap-3 sm:grid-cols-3">
              <StatCard label="Checks" value={checks.length} hint={`${enabled.length} enabled`} />
              <StatCard
                label="Down now"
                value={down.length}
                accentClass={down.length ? 'text-critical' : 'text-ok'}
                hint={down.length ? down.map((c) => c.name).join(', ') : 'Everything answering as expected'}
              />
              <StatCard
                label="Avg latency"
                value={avgLatency === null ? '—' : `${avgLatency} ms`}
                hint="Last probe of each enabled check"
              />
            </div>

            <div className="grid gap-4">
              {groups.map(([group, rows]) => (
                <Card key={group} kicker="Business function" title={group} bodyClass="divide-y divide-border">
                  {rows.map((c) => (
                    <CheckRow
                      key={c.id}
                      check={c}
                      open={openId === c.id}
                      onToggle={() => setOpenId(openId === c.id ? null : c.id)}
                      canManage={canManage}
                      onEdit={() => setEditing(c)}
                      onChanged={load}
                    />
                  ))}
                </Card>
              ))}
            </div>
          </>
        )
      )}
    </Page>
  )
}

function CheckRow({
  check: c,
  open,
  onToggle,
  canManage,
  onEdit,
  onChanged,
}: {
  check: ServiceCheck
  open: boolean
  onToggle: () => void
  canManage: boolean
  onEdit: () => void
  onChanged: () => void
}) {
  const status = statusOf(c)
  return (
    <div className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={onToggle} className="min-w-0 flex-1 text-left">
          <div className="flex items-center gap-2">
            <StatusPill status={status} />
            <span className="truncate text-[14px] font-semibold text-fg">{c.name}</span>
            {c.has_headers && (
              <span className="shrink-0 text-[11px] text-dim" title="Credentials are stored encrypted">
                🔒
              </span>
            )}
          </div>
          <div className="mt-1 truncate text-[12.5px] text-dim">
            {c.kind.toUpperCase()} {c.target}
          </div>
        </button>

        <div className="shrink-0 text-right text-[12.5px]">
          <div className="text-fg">
            {c.last_ok === null ? '—' : `${c.last_latency_ms} ms`}
            {c.last_status > 0 && <span className="text-dim"> · HTTP {c.last_status}</span>}
          </div>
          <div className="text-dim">checked {ago(c.last_checked_at)}</div>
        </div>

        {canManage && (
          <div className="flex shrink-0 gap-2">
            <Button onClick={onEdit}>Edit</Button>
            <Button
              variant="danger"
              onClick={async () => {
                if (!confirm(`Delete the check "${c.name}"? Its probe history goes with it.`)) return
                try {
                  await deleteServiceCheck(c.id)
                  onChanged()
                } catch (e) {
                  alert((e as Error).message)
                }
              }}
            >
              Delete
            </Button>
          </div>
        )}
      </div>

      {/* The reason, verbatim from the probe. "HTTP 200 but the response did not contain
          \"code\":\"200\"" is the difference between a wild goose chase and a fixed integration. */}
      {status === 'down' && c.last_error && (
        <div className="mt-2 rounded-[8px] bg-critical/10 px-3 py-2 text-[12.5px] text-critical">
          {c.last_error}
          {c.consec_failures > 1 && (
            <span className="text-critical/70"> · {c.consec_failures} consecutive failures</span>
          )}
        </div>
      )}

      {open && <History id={c.id} />}
    </div>
  )
}

// History is the 24-hour timeline: one bar per probe, red where it failed. It answers the question
// an operator asks next — "is this broken, or has it been flapping all morning?"
function History({ id }: { id: string }) {
  const [points, setPoints] = useState<ServiceCheckPoint[] | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let live = true
    fetchServiceCheckHistory(id, 24)
      .then((p) => live && setPoints(p))
      .catch((e) => live && setError((e as Error).message))
    return () => {
      live = false
    }
  }, [id])

  if (error) return <div className="mt-3 text-[12.5px] text-critical">{error}</div>
  if (!points) return <div className="mt-3 text-[12.5px] text-dim">Loading history…</div>
  if (points.length === 0) return <div className="mt-3 text-[12.5px] text-dim">No probes recorded in the last 24 hours.</div>

  const worst = Math.max(1, ...points.map((p) => p.latency_ms))
  const failures = points.filter((p) => !p.ok).length

  return (
    <div className="mt-3 rounded-[8px] border border-border bg-surface-2 px-3 py-3">
      <div className="mb-2 flex items-center justify-between text-[12px] text-dim">
        <span>Last 24 hours · {points.length} probes</span>
        <span className={failures ? 'text-critical' : 'text-ok'}>
          {failures ? `${failures} failed` : 'all passed'}
        </span>
      </div>
      <div className="flex h-12 items-end gap-[2px] overflow-hidden">
        {points.map((p, i) => (
          <div
            key={i}
            className={`w-[3px] shrink-0 rounded-sm ${p.ok ? 'bg-ok/70' : 'bg-critical'}`}
            // A failed probe gets full height even at 0ms latency, so an outage is never a gap.
            style={{ height: p.ok ? `${Math.max(8, (p.latency_ms / worst) * 100)}%` : '100%' }}
            title={`${new Date(p.time).toLocaleString()} · ${p.ok ? 'ok' : 'failed'} · ${p.latency_ms}ms${p.error ? ` · ${p.error}` : ''}`}
          />
        ))}
      </div>
    </div>
  )
}

const EMPTY: ServiceCheckInput = {
  name: '',
  service_group: '',
  kind: 'http',
  target: '',
  method: 'GET',
  expect_status: 0,
  expect_body: '',
  interval_secs: 60,
  timeout_secs: 10,
  latency_warn_ms: 0,
  fail_threshold: 2,
  enabled: true,
}

function CheckForm({
  check,
  onCancel,
  onSaved,
}: {
  check: ServiceCheck | null
  onCancel: () => void
  onSaved: () => void
}) {
  const [f, setF] = useState<ServiceCheckInput>(
    check
      ? {
          name: check.name,
          service_group: check.service_group,
          kind: check.kind,
          target: check.target,
          method: check.method,
          expect_status: check.expect_status,
          expect_body: check.expect_body,
          interval_secs: check.interval_secs,
          timeout_secs: check.timeout_secs,
          latency_warn_ms: check.latency_warn_ms,
          fail_threshold: check.fail_threshold,
          enabled: check.enabled,
        }
      : EMPTY,
  )
  // Headers are edited as text so credentials never round-trip through the browser: an empty box
  // on an existing check means "keep what is stored", not "delete it".
  const [headerText, setHeaderText] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const set = <K extends keyof ServiceCheckInput>(k: K, v: ServiceCheckInput[K]) =>
    setF((cur) => ({ ...cur, [k]: v }))

  const save = async () => {
    setSaving(true)
    setError('')
    try {
      const body: ServiceCheckInput = { ...f }
      const headers = parseHeaders(headerText)
      if (headers === null) throw new Error('Each header line must be "Name: value"')
      if (Object.keys(headers).length > 0) body.headers = headers
      if (check) await updateServiceCheck(check.id, body)
      else await createServiceCheck(body)
      onSaved()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card className="mb-5" title={check ? `Edit ${check.name}` : 'New service check'}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" hint="What it is called on the board, e.g. “BPJS pendaftaran”">
          <Input value={f.name} onChange={(e) => set('name', e.target.value)} className="w-full" />
        </Field>
        <Field label="Business function" hint="Groups the board, e.g. pendaftaran, klaim, finger">
          <Input value={f.service_group} onChange={(e) => set('service_group', e.target.value)} className="w-full" />
        </Field>

        <Field label="Kind">
          <Select value={f.kind} onChange={(e) => set('kind', e.target.value as 'http' | 'tcp')} className="w-full">
            <option value="http">HTTP — a web service endpoint</option>
            <option value="tcp">TCP — a database or plain socket</option>
          </Select>
        </Field>
        <Field label="Target" hint={f.kind === 'http' ? 'Full URL, e.g. https://api.example/peserta' : 'host:port, e.g. 10.0.0.5:5432'}>
          <Input value={f.target} onChange={(e) => set('target', e.target.value)} className="w-full" />
        </Field>

        {f.kind === 'http' && (
          <>
            <Field label="Method">
              <Select value={f.method} onChange={(e) => set('method', e.target.value)} className="w-full">
                {['GET', 'HEAD', 'POST', 'PUT'].map((m) => (
                  <option key={m}>{m}</option>
                ))}
              </Select>
            </Field>
            <Field label="Expected status" hint="0 = any response below 400. Set it when the endpoint healthily answers 401 or 404.">
              <Input
                type="number"
                value={f.expect_status}
                onChange={(e) => set('expect_status', Number(e.target.value))}
                className="w-full"
              />
            </Field>
            <Field
              label="Expected text in body"
              hint="The rule that catches a 200 whose payload says the operation failed, e.g. &quot;code&quot;:&quot;200&quot;"
              wide
            >
              <Input value={f.expect_body} onChange={(e) => set('expect_body', e.target.value)} className="w-full" />
            </Field>
            <Field
              label="Request headers"
              hint={
                check?.has_headers
                  ? 'Credentials are stored. Leave this empty to keep them, or type new ones to replace them.'
                  : 'One per line, "Name: value". Stored encrypted and never shown again.'
              }
              wide
            >
              <textarea
                value={headerText}
                onChange={(e) => setHeaderText(e.target.value)}
                rows={3}
                placeholder={'X-Cons-ID: 12345\nX-Signature: ...'}
                className="w-full rounded-[8px] border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[12.5px] text-fg outline-none placeholder:text-dim focus:border-accent"
              />
            </Field>
          </>
        )}

        <Field label="Interval (seconds)" hint="How often to probe. Minimum 10.">
          <Input type="number" value={f.interval_secs} onChange={(e) => set('interval_secs', Number(e.target.value))} className="w-full" />
        </Field>
        <Field label="Timeout (seconds)">
          <Input type="number" value={f.timeout_secs} onChange={(e) => set('timeout_secs', Number(e.target.value))} className="w-full" />
        </Field>
        <Field label="Slow threshold (ms)" hint="0 = no budget. A service answering in nine seconds is up on paper and down at the counter.">
          <Input type="number" value={f.latency_warn_ms} onChange={(e) => set('latency_warn_ms', Number(e.target.value))} className="w-full" />
        </Field>
        <Field label="Failures before alerting" hint="Rides out one blip without paging anyone.">
          <Input type="number" value={f.fail_threshold} onChange={(e) => set('fail_threshold', Number(e.target.value))} className="w-full" />
        </Field>

        <label className="flex items-center gap-2 text-[13px] text-fg sm:col-span-2">
          <input type="checkbox" checked={f.enabled} onChange={(e) => set('enabled', e.target.checked)} />
          Enabled
        </label>
      </div>

      {error && (
        <div className="mt-3">
          <ErrorText>{error}</ErrorText>
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="primary" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : check ? 'Save changes' : 'Create check'}
        </Button>
        <Button onClick={onCancel}>Cancel</Button>
        {check?.has_headers && (
          <Button
            variant="danger"
            onClick={async () => {
              if (!confirm('Remove the stored credentials from this check?')) return
              try {
                await clearServiceCheckHeaders(check.id)
                onSaved()
              } catch (e) {
                setError((e as Error).message)
              }
            }}
          >
            Remove stored credentials
          </Button>
        )}
      </div>
    </Card>
  )
}

function Field({
  label,
  hint,
  wide,
  children,
}: {
  label: string
  hint?: string
  wide?: boolean
  children: React.ReactNode
}) {
  return (
    <div className={wide ? 'sm:col-span-2' : ''}>
      <div className="mb-1 text-[12.5px] font-medium text-muted">{label}</div>
      {children}
      {hint && <div className="mt-1 text-[11.5px] text-dim">{hint}</div>}
    </div>
  )
}

// parseHeaders turns the textarea into a map, or null when a line is malformed. Returning null
// rather than skipping the bad line matters: a silently dropped token becomes a fake outage.
function parseHeaders(text: string): Record<string, string> | null {
  const out: Record<string, string> = {}
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line) continue
    const i = line.indexOf(':')
    if (i <= 0) return null
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return out
}
