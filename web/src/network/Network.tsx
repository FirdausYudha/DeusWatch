import { useEffect, useMemo, useState } from 'react'
import {
  can,
  createSNMPDevice,
  deleteSNMPDevice,
  fetchSNMPDevices,
  fetchSNMPIfaces,
  updateSNMPDevice,
  type Me,
  type SNMPDevice,
  type SNMPDeviceInput,
  type SNMPIface,
  type SNMPSensor,
  type SNMPSensorInput,
} from '../lib/api'
import { Button, Card, EmptyState, ErrorText, Input, Page, PageHeader, Select, StatCard } from '../components/ui'

// Network devices over SNMP.
//
// The hospital's SNMP data lives in three tools — The Dude for the switches, WIS Cloud for the
// access points, Grafana at head office — and the ask was one dashboard. The board is grouped by
// LOCATION rather than by device type, because the team manage around twenty hospitals and the
// first question about a dead switch is which building to walk to.
//
// CPU and temperature have no standard SNMP OID, so they are not fields here: each device carries
// sensors the operator defines, which is what makes this work on Ruijie without guessing.

const REFRESH_MS = 20000

type Status = 'up' | 'down' | 'pending' | 'paused'

function statusOf(d: SNMPDevice): Status {
  if (!d.enabled) return 'paused'
  if (d.last_ok === null) return 'pending'
  return d.last_ok ? 'up' : 'down'
}

const STATUS_STYLE: Record<Status, { label: string; cls: string }> = {
  up: { label: 'Up', cls: 'bg-ok/15 text-ok' },
  down: { label: 'Unreachable', cls: 'bg-critical/15 text-critical' },
  pending: { label: 'Not polled yet', cls: 'bg-surface-2 text-dim' },
  paused: { label: 'Paused', cls: 'bg-surface-2 text-muted' },
}

function ago(iso: string | null): string {
  if (!iso) return 'never'
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  return `${Math.round(s / 3600)}h ago`
}

function uptime(secs: number): string {
  if (!secs) return '—'
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  if (d > 0) return `${d}d ${h}h`
  const m = Math.floor((secs % 3600) / 60)
  return `${h}h ${m}m`
}

function SensorChip({ s }: { s: SNMPSensor }) {
  const breached = s.last_breach !== ''
  const value =
    s.last_value !== null
      ? `${Number(s.last_value.toFixed(2))}${s.unit ? ' ' + s.unit : ''}`
      : s.last_text || '—'
  return (
    <span
      title={breached ? s.last_breach : `${s.oid}${s.last_at ? ' · ' + ago(s.last_at) : ''}`}
      className={`inline-flex items-center gap-1.5 rounded-[8px] px-2 py-1 text-[12.5px] ${
        breached ? 'bg-critical/15 text-critical' : 'bg-surface-2 text-fg'
      }`}
    >
      <span className="text-dim">{s.name}</span>
      <span className="font-semibold tabular-nums">{value}</span>
    </span>
  )
}

export default function Network({ me }: { me: Me }) {
  const [devices, setDevices] = useState<SNMPDevice[]>([])
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [editing, setEditing] = useState<SNMPDevice | 'new' | null>(null)
  const [openId, setOpenId] = useState<string | null>(null)

  const canManage = can(me, 'manage_settings')

  const load = () =>
    fetchSNMPDevices()
      .then((d) => {
        setDevices(d)
        setError('')
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoaded(true))

  useEffect(() => {
    load()
    const t = setInterval(load, REFRESH_MS)
    return () => clearInterval(t)
  }, [])

  // Grouped by location: the first question about a dead switch is which building to walk to.
  const groups = useMemo(() => {
    const by = new Map<string, SNMPDevice[]>()
    for (const d of devices) {
      const k = d.location || 'Unassigned'
      by.set(k, [...(by.get(k) ?? []), d])
    }
    return [...by.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [devices])

  const down = devices.filter((d) => statusOf(d) === 'down')
  const breaching = devices.filter((d) => d.enabled && d.sensors.some((s) => s.last_breach !== ''))

  return (
    <Page>
      <PageHeader
        subtitle="Switches, access points and routers over SNMP — one board instead of three tools"
        actions={
          canManage && (
            <Button variant="primary" onClick={() => setEditing('new')}>
              Add device
            </Button>
          )
        }
      />

      {error && <ErrorText>{error}</ErrorText>}

      {editing && (
        <DeviceForm
          device={editing === 'new' ? null : editing}
          onCancel={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            load()
          }}
        />
      )}

      {loaded && devices.length === 0 && !editing ? (
        <EmptyState
          title="No network devices yet"
          hint="Add a switch, access point or router. Uptime and port state come from the standard SNMP tree; for CPU and temperature add the OIDs your vendor uses — the same ones your existing SNMP tool already polls."
          action={canManage ? <Button variant="primary" onClick={() => setEditing('new')}>Add the first device</Button> : undefined}
        />
      ) : (
        devices.length > 0 && (
          <>
            <div className="mb-5 grid gap-3 sm:grid-cols-3">
              <StatCard label="Devices" value={devices.length} hint={`${devices.filter((d) => d.enabled).length} polled`} />
              <StatCard
                label="Unreachable"
                value={down.length}
                accentClass={down.length ? 'text-critical' : 'text-ok'}
                hint={down.length ? down.map((d) => d.name).join(', ') : 'All devices answering'}
              />
              <StatCard
                label="Sensors over limit"
                value={breaching.length}
                accentClass={breaching.length ? 'text-critical' : 'text-ok'}
                hint={breaching.length ? breaching.map((d) => d.name).join(', ') : 'Everything within range'}
              />
            </div>

            <div className="grid gap-4">
              {groups.map(([location, rows]) => (
                <Card key={location} kicker="Location" title={location} bodyClass="divide-y divide-border">
                  {rows.map((d) => (
                    <DeviceRow
                      key={d.id}
                      device={d}
                      open={openId === d.id}
                      onToggle={() => setOpenId(openId === d.id ? null : d.id)}
                      canManage={canManage}
                      onEdit={() => setEditing(d)}
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

function DeviceRow({
  device: d,
  open,
  onToggle,
  canManage,
  onEdit,
  onChanged,
}: {
  device: SNMPDevice
  open: boolean
  onToggle: () => void
  canManage: boolean
  onEdit: () => void
  onChanged: () => void
}) {
  const status = statusOf(d)
  const s = STATUS_STYLE[status]
  return (
    <div className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={onToggle} className="min-w-0 flex-1 text-left">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-[12px] font-semibold ${s.cls}`}>
              {s.label}
            </span>
            <span className="truncate text-[14px] font-semibold text-fg">{d.name}</span>
            <span className="truncate text-[12.5px] text-dim">{d.host}</span>
            {d.sys_name !== '' && d.sys_name !== d.name && (
              <span className="truncate text-[12px] text-dim" title={d.sys_descr}>
                ({d.sys_name})
              </span>
            )}
          </div>
          {d.sensors.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {d.sensors.map((x) => (
                <SensorChip key={x.id} s={x} />
              ))}
            </div>
          )}
        </button>

        <div className="shrink-0 text-right text-[12.5px]">
          <div className="text-fg">up {uptime(d.uptime_secs)}</div>
          <div className="text-dim">polled {ago(d.last_polled_at)}</div>
        </div>

        {canManage && (
          <div className="flex shrink-0 gap-2">
            <Button onClick={onEdit}>Edit</Button>
            <Button
              variant="danger"
              onClick={async () => {
                if (!confirm(`Delete "${d.name}"? Its sensors and polled history go with it.`)) return
                try {
                  await deleteSNMPDevice(d.id)
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

      {/* The reason, verbatim from the poller: "no response" and "wrong community string" send
          you to very different places. */}
      {status === 'down' && d.last_error && (
        <div className="mt-2 rounded-[8px] bg-critical/10 px-3 py-2 text-[12.5px] text-critical">
          {d.last_error}
          {d.consec_failures > 1 && <span className="text-critical/70"> · {d.consec_failures} consecutive polls</span>}
        </div>
      )}

      {open && d.poll_ifaces && <Interfaces id={d.id} />}
      {open && !d.poll_ifaces && (
        <div className="mt-3 text-[12.5px] text-dim">
          Port monitoring is off for this device. Turn on “Poll interfaces” to see per-port state.
        </div>
      )}
    </div>
  )
}

// Interfaces lists the latest state of each port. Down means admin-up but not operationally up;
// a port somebody disabled on purpose is not a fault and is not flagged.
function Interfaces({ id }: { id: string }) {
  const [ifaces, setIfaces] = useState<SNMPIface[] | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let live = true
    fetchSNMPIfaces(id)
      .then((x) => live && setIfaces(x))
      .catch((e) => live && setError((e as Error).message))
    return () => {
      live = false
    }
  }, [id])

  if (error) return <div className="mt-3 text-[12.5px] text-critical">{error}</div>
  if (!ifaces) return <div className="mt-3 text-[12.5px] text-dim">Loading ports…</div>
  if (ifaces.length === 0) return <div className="mt-3 text-[12.5px] text-dim">No port data yet.</div>

  const faulty = ifaces.filter((f) => f.admin_status === 1 && f.oper_status !== 1)
  return (
    <div className="mt-3 rounded-[8px] border border-border bg-surface-2 px-3 py-3">
      <div className="mb-2 flex items-center justify-between text-[12px] text-dim">
        <span>{ifaces.length} ports</span>
        <span className={faulty.length ? 'text-critical' : 'text-ok'}>
          {faulty.length ? `${faulty.length} down` : 'all up'}
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {ifaces.map((f) => {
          const disabled = f.admin_status !== 1
          const down = !disabled && f.oper_status !== 1
          return (
            <span
              key={f.index}
              title={`${f.name || 'if' + f.index} · in ${f.in_octets} B · out ${f.out_octets} B · errors ${f.in_errors}/${f.out_errors}`}
              className={`rounded px-1.5 py-0.5 text-[11.5px] ${
                down ? 'bg-critical/15 text-critical' : disabled ? 'bg-surface text-dim' : 'bg-ok/10 text-ok'
              }`}
            >
              {f.name || `if${f.index}`}
            </span>
          )
        })}
      </div>
    </div>
  )
}

const EMPTY: SNMPDeviceInput = {
  name: '',
  location: '',
  host: '',
  port: 161,
  version: '2c',
  v3_user: '',
  v3_level: 'authPriv',
  v3_auth_proto: 'SHA',
  v3_priv_proto: 'AES',
  poll_secs: 60,
  poll_ifaces: false,
  fail_threshold: 3,
  enabled: true,
  sensors: [],
}

function DeviceForm({
  device,
  onCancel,
  onSaved,
}: {
  device: SNMPDevice | null
  onCancel: () => void
  onSaved: () => void
}) {
  const [f, setF] = useState<SNMPDeviceInput>(
    device
      ? {
          name: device.name,
          location: device.location,
          host: device.host,
          port: device.port,
          version: device.version,
          v3_user: device.v3_user,
          v3_level: device.v3_level,
          v3_auth_proto: device.v3_auth_proto,
          v3_priv_proto: device.v3_priv_proto,
          poll_secs: device.poll_secs,
          poll_ifaces: device.poll_ifaces,
          fail_threshold: device.fail_threshold,
          enabled: device.enabled,
          sensors: device.sensors.map((s) => ({
            name: s.name,
            oid: s.oid,
            unit: s.unit,
            scale: s.scale,
            warn_above: s.warn_above,
            warn_below: s.warn_below,
          })),
        }
      : EMPTY,
  )
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const set = <K extends keyof SNMPDeviceInput>(k: K, v: SNMPDeviceInput[K]) =>
    setF((cur) => ({ ...cur, [k]: v }))

  const setSensor = (i: number, patch: Partial<SNMPSensorInput>) =>
    setF((cur) => ({ ...cur, sensors: cur.sensors.map((s, j) => (j === i ? { ...s, ...patch } : s)) }))

  const save = async () => {
    setSaving(true)
    setError('')
    try {
      if (device) await updateSNMPDevice(device.id, f)
      else await createSNMPDevice(f)
      onSaved()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  const num = (v: string): number | null => (v.trim() === '' ? null : Number(v))

  return (
    <Card className="mb-5" title={device ? `Edit ${device.name}` : 'New network device'}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" hint="What it is called on the board, e.g. “sw-lantai3”">
          <Input value={f.name} onChange={(e) => set('name', e.target.value)} className="w-full" />
        </Field>
        <Field label="Location" hint="Groups the board. The first question about a dead switch is which building.">
          <Input value={f.location} onChange={(e) => set('location', e.target.value)} className="w-full" />
        </Field>
        <Field label="Host" hint="Bare IP or hostname — no scheme, no port">
          <Input value={f.host} onChange={(e) => set('host', e.target.value)} className="w-full" />
        </Field>
        <Field label="Port">
          <Input type="number" value={f.port} onChange={(e) => set('port', Number(e.target.value))} className="w-full" />
        </Field>

        <Field label="SNMP version">
          <Select value={f.version} onChange={(e) => set('version', e.target.value as '2c' | '3')} className="w-full">
            <option value="2c">v2c — community string</option>
            <option value="3">v3 — user, auth and privacy</option>
          </Select>
        </Field>

        {f.version === '2c' ? (
          <Field
            label="Community string"
            hint={device?.has_creds ? 'Stored. Leave empty to keep it, or type a new one to replace it.' : 'Stored encrypted and never shown again.'}
          >
            <Input
              type="password"
              value={f.community ?? ''}
              onChange={(e) => set('community', e.target.value)}
              className="w-full"
              autoComplete="new-password"
            />
          </Field>
        ) : (
          <>
            <Field label="v3 username">
              <Input value={f.v3_user} onChange={(e) => set('v3_user', e.target.value)} className="w-full" />
            </Field>
            <Field label="Security level">
              <Select value={f.v3_level} onChange={(e) => set('v3_level', e.target.value)} className="w-full">
                <option value="authPriv">authPriv — signed and encrypted</option>
                <option value="authNoPriv">authNoPriv — signed only</option>
                <option value="noAuthNoPriv">noAuthNoPriv — neither</option>
              </Select>
            </Field>
            <Field label="Auth protocol">
              <Select value={f.v3_auth_proto} onChange={(e) => set('v3_auth_proto', e.target.value)} className="w-full">
                {['SHA', 'SHA256', 'SHA384', 'SHA512', 'SHA224', 'MD5'].map((p) => (
                  <option key={p}>{p}</option>
                ))}
              </Select>
            </Field>
            <Field label="Auth password" hint={device?.has_creds ? 'Leave empty to keep the stored one.' : undefined}>
              <Input
                type="password"
                value={f.auth_password ?? ''}
                onChange={(e) => set('auth_password', e.target.value)}
                className="w-full"
                autoComplete="new-password"
              />
            </Field>
            <Field label="Privacy protocol">
              <Select value={f.v3_priv_proto} onChange={(e) => set('v3_priv_proto', e.target.value)} className="w-full">
                {['AES', 'AES192', 'AES256', 'DES'].map((p) => (
                  <option key={p}>{p}</option>
                ))}
              </Select>
            </Field>
            <Field label="Privacy password" hint={device?.has_creds ? 'Leave empty to keep the stored one.' : undefined}>
              <Input
                type="password"
                value={f.priv_password ?? ''}
                onChange={(e) => set('priv_password', e.target.value)}
                className="w-full"
                autoComplete="new-password"
              />
            </Field>
          </>
        )}

        <Field label="Poll every (seconds)" hint="Minimum 10. A switch asked too often spends real CPU answering.">
          <Input type="number" value={f.poll_secs} onChange={(e) => set('poll_secs', Number(e.target.value))} className="w-full" />
        </Field>
        <Field label="Failed polls before alerting" hint="SNMP is UDP: one lost packet is not an outage.">
          <Input type="number" value={f.fail_threshold} onChange={(e) => set('fail_threshold', Number(e.target.value))} className="w-full" />
        </Field>

        <label className="flex items-center gap-2 text-[13px] text-fg sm:col-span-2">
          <input type="checkbox" checked={f.poll_ifaces} onChange={(e) => set('poll_ifaces', e.target.checked)} />
          Poll interfaces (per-port state)
        </label>
        <p className="-mt-2 text-[11.5px] text-dim sm:col-span-2">
          Off by default: a 48-port switch is 48 rows per poll, so twenty of them are over a million rows a day.
          Worth it where port state matters, wasteful where only the device's own health does.
        </p>

        <label className="flex items-center gap-2 text-[13px] text-fg sm:col-span-2">
          <input type="checkbox" checked={f.enabled} onChange={(e) => set('enabled', e.target.checked)} />
          Enabled
        </label>
      </div>

      <h3 className="mb-1 mt-5 text-[12.5px] font-semibold uppercase tracking-wider text-dim">Sensors</h3>
      <p className="mb-3 text-[12px] text-dim">
        SNMP has no standard OID for CPU, temperature or power supply — every vendor differs — so they go here.
        Use the OIDs your existing SNMP tool already polls for these devices.
      </p>

      {f.sensors.map((s, i) => (
        <div key={i} className="mb-2 grid gap-2 rounded-[8px] border border-border p-2 sm:grid-cols-6">
          <Input placeholder="Name (CPU)" value={s.name} onChange={(e) => setSensor(i, { name: e.target.value })} />
          <Input
            placeholder="OID (1.3.6.1.4.1…)"
            value={s.oid}
            onChange={(e) => setSensor(i, { oid: e.target.value })}
            className="sm:col-span-2 font-mono text-[12px]"
          />
          <Input placeholder="Unit (%)" value={s.unit ?? ''} onChange={(e) => setSensor(i, { unit: e.target.value })} />
          <Input
            type="number"
            step="any"
            placeholder="Warn above"
            value={s.warn_above ?? ''}
            onChange={(e) => setSensor(i, { warn_above: num(e.target.value) })}
          />
          <div className="flex gap-2">
            <Input
              type="number"
              step="any"
              placeholder="Warn below"
              value={s.warn_below ?? ''}
              onChange={(e) => setSensor(i, { warn_below: num(e.target.value) })}
              className="min-w-0 flex-1"
            />
            <Button
              variant="ghost"
              onClick={() => setF((cur) => ({ ...cur, sensors: cur.sensors.filter((_, j) => j !== i) }))}
              title="Remove this sensor"
            >
              ✕
            </Button>
          </div>
          <div className="sm:col-span-6">
            <label className="flex items-center gap-2 text-[11.5px] text-dim">
              Multiply raw value by
              <input
                type="number"
                step="any"
                value={s.scale ?? 1}
                onChange={(e) => setSensor(i, { scale: Number(e.target.value) })}
                className="w-20 rounded border border-border bg-surface-2 px-2 py-0.5 text-right text-fg outline-none focus:border-accent"
              />
              — devices often report tenths, so 0.1 turns 345 into 34.5 °C
            </label>
          </div>
        </div>
      ))}

      <Button onClick={() => setF((cur) => ({ ...cur, sensors: [...cur.sensors, { name: '', oid: '', scale: 1 }] }))}>
        + Add sensor
      </Button>

      {error && (
        <div className="mt-3">
          <ErrorText>{error}</ErrorText>
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="primary" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : device ? 'Save changes' : 'Create device'}
        </Button>
        <Button onClick={onCancel}>Cancel</Button>
      </div>
    </Card>
  )
}

function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div>
      <div className="mb-1 text-[12.5px] font-medium text-muted">{label}</div>
      {children}
      {hint && <div className="mt-1 text-[11.5px] text-dim">{hint}</div>}
    </div>
  )
}
