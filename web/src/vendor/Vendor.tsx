import { useEffect, useState } from 'react'
import {
  fetchVendorAccounts,
  saveVendorAccount,
  deleteVendorAccount,
  can,
  type VendorAccount,
  type VendorAccountInput,
  type Me,
} from '../lib/api'
import { Button, EmptyState, ErrorText, Input, Page, PageHeader } from '../components/ui'

const DAYS = [
  { n: 1, label: 'Mon' },
  { n: 2, label: 'Tue' },
  { n: 3, label: 'Wed' },
  { n: 4, label: 'Thu' },
  { n: 5, label: 'Fri' },
  { n: 6, label: 'Sat' },
  { n: 7, label: 'Sun' },
]

function daysLabel(days: number[]): string {
  if (days.length === 0) return 'no days'
  return DAYS.filter((d) => days.includes(d.n))
    .map((d) => d.label)
    .join(' ')
}

export default function Vendor({ me }: { me: Me }) {
  const canManage = can(me, 'manage_settings')
  const [rows, setRows] = useState<VendorAccount[]>([])
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [editing, setEditing] = useState<VendorAccount | 'new' | null>(null)

  const load = () =>
    fetchVendorAccounts()
      .then(setRows)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoaded(true))

  useEffect(() => {
    void load()
  }, [])

  return (
    <Page>
      <PageHeader
        subtitle="Vendor accounts and the hours each is allowed to log in. A login outside the window raises an alert."
        actions={
          canManage ? <Button onClick={() => setEditing('new')}>Add vendor account</Button> : undefined
        }
      />

      {error && <ErrorText>{error}</ErrorText>}

      {loaded && rows.length === 0 && !error && (
        <EmptyState
          title="No vendor accounts yet"
          hint="Register the account a vendor logs in with and its agreed hours. DeusWatch then alerts when that account logs in outside the window, which catches both a vendor breaking the agreement and a stolen vendor credential."
          action={canManage ? <Button onClick={() => setEditing('new')}>Add vendor account</Button> : undefined}
        />
      )}

      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-[12px] border border-border">
          <table className="w-full text-left text-[13px]">
            <thead className="bg-surface text-[12px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-4 py-2 font-medium">Account</th>
                <th className="px-4 py-2 font-medium">Allowed days</th>
                <th className="px-4 py-2 font-medium">Window</th>
                <th className="px-4 py-2 font-medium">Timezone</th>
                <th className="px-4 py-2 font-medium">State</th>
                {canManage && <th className="px-4 py-2 font-medium"></th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((v) => (
                <tr key={v.id} className="border-t border-border">
                  <td className="px-4 py-2 font-mono text-fg">{v.account}</td>
                  <td className="px-4 py-2 text-muted">{daysLabel(v.days)}</td>
                  <td className="px-4 py-2 text-muted">
                    {v.start_time}&ndash;{v.end_time}
                  </td>
                  <td className="px-4 py-2 text-muted">{v.timezone}</td>
                  <td className="px-4 py-2">
                    {v.enabled ? (
                      <span className="rounded bg-emerald-400/15 px-1.5 py-0.5 text-[11px] text-emerald-300">
                        enabled
                      </span>
                    ) : (
                      <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-dim">off</span>
                    )}
                  </td>
                  {canManage && (
                    <td className="px-4 py-2">
                      <div className="flex gap-2">
                        <button
                          onClick={() => setEditing(v)}
                          className="rounded-md border border-border px-2 py-1 text-[12px] text-fg hover:bg-surface-2"
                        >
                          Edit
                        </button>
                        <button
                          onClick={async () => {
                            if (!confirm(`Delete vendor account "${v.account}"? Logins by it will no longer be checked against a window.`)) return
                            setError('')
                            try {
                              await deleteVendorAccount(v.id)
                              await load()
                            } catch (e) {
                              setError((e as Error).message)
                            }
                          }}
                          className="rounded-md border border-rose-500/40 px-2 py-1 text-[12px] text-rose-300 hover:bg-rose-500/10"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-3 text-[12px] text-dim">
        The window is evaluated in each account&apos;s own timezone, so a contract written in WIB is
        judged in WIB. A window whose end is before its start wraps past midnight, for overnight
        maintenance.
      </p>

      {editing && (
        <VendorForm
          initial={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            void load()
          }}
        />
      )}
    </Page>
  )
}

function VendorForm({
  initial,
  onClose,
  onSaved,
}: {
  initial: VendorAccount | null
  onClose: () => void
  onSaved: () => void
}) {
  const [account, setAccount] = useState(initial?.account ?? '')
  const [days, setDays] = useState<number[]>(initial?.days ?? [1, 2, 3, 4, 5])
  const [start, setStart] = useState(initial?.start_time ?? '08:00')
  const [end, setEnd] = useState(initial?.end_time ?? '17:00')
  const [timezone, setTimezone] = useState(initial?.timezone ?? 'Asia/Jakarta')
  const [note, setNote] = useState(initial?.note ?? '')
  const [enabled, setEnabled] = useState(initial?.enabled ?? true)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const toggleDay = (n: number) =>
    setDays((prev) => (prev.includes(n) ? prev.filter((x) => x !== n) : [...prev, n].sort()))

  const save = async () => {
    setBusy(true)
    setError('')
    try {
      if (!account.trim()) throw new Error('Account name is required')
      if (days.length === 0) throw new Error('Choose at least one allowed day')
      const input: VendorAccountInput = {
        account: account.trim(),
        days,
        start_time: start,
        end_time: end,
        timezone: timezone.trim(),
        note: note.trim(),
        enabled,
      }
      await saveVendorAccount(input)
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
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-[12px] border border-border bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-[16px] font-semibold text-fg">
          {initial ? `Edit ${initial.account}` : 'Add vendor account'}
        </h2>
        <p className="mb-4 text-[12.5px] text-dim">
          A login by this account outside the window raises a high-severity alert within a minute.
        </p>

        {error && <div className="mb-3"><ErrorText>{error}</ErrorText></div>}

        <label className="mb-3 block">
          <span className="mb-1 block text-[12.5px] font-medium text-muted">Account name</span>
          <Input
            value={account}
            onChange={(e) => setAccount(e.target.value)}
            placeholder="vnd-acme"
            disabled={!!initial}
            className="w-full font-mono"
          />
          {initial && <span className="mt-1 block text-[12px] text-dim">The account name cannot be changed; delete and re-add to rename.</span>}
        </label>

        <div className="mb-3">
          <span className="mb-1 block text-[12.5px] font-medium text-muted">Allowed days</span>
          <div className="flex flex-wrap gap-1.5">
            {DAYS.map((d) => (
              <button
                key={d.n}
                type="button"
                onClick={() => toggleDay(d.n)}
                className={`rounded-md border px-2.5 py-1 text-[12.5px] ${
                  days.includes(d.n)
                    ? 'border-accent bg-accent-soft text-accent'
                    : 'border-border text-muted hover:bg-surface-2'
                }`}
              >
                {d.label}
              </button>
            ))}
          </div>
        </div>

        <div className="mb-3 grid grid-cols-2 gap-3">
          <label className="block">
            <span className="mb-1 block text-[12.5px] font-medium text-muted">Start</span>
            <Input type="time" value={start} onChange={(e) => setStart(e.target.value)} className="w-full" />
          </label>
          <label className="block">
            <span className="mb-1 block text-[12.5px] font-medium text-muted">End</span>
            <Input type="time" value={end} onChange={(e) => setEnd(e.target.value)} className="w-full" />
          </label>
        </div>

        <label className="mb-3 block">
          <span className="mb-1 block text-[12.5px] font-medium text-muted">Timezone (IANA)</span>
          <Input
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            placeholder="Asia/Jakarta"
            className="w-full"
          />
        </label>

        <label className="mb-3 block">
          <span className="mb-1 block text-[12.5px] font-medium text-muted">Note (optional)</span>
          <Input value={note} onChange={(e) => setNote(e.target.value)} className="w-full" />
        </label>

        <label className="mb-4 flex items-center gap-2 text-[13px] text-muted">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled (unchecked stops checking this account without deleting it)
        </label>

        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="rounded-[8px] border border-border px-4 py-2 text-[13px] text-fg hover:bg-surface-2">
            Cancel
          </button>
          <Button onClick={() => void save()} disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </Button>
        </div>
      </div>
    </div>
  )
}
