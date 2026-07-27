import { useEffect, useState } from 'react'
import { fetchTenants, createTenant, type Tenant } from '../lib/api'

// Tenants admin (manage_tenants). A tenant is the data-isolation boundary: agents and all their
// telemetry belong to exactly one tenant, and Postgres RLS keeps them separate. Creating a tenant
// here is step one; a workspace then grants teams access to it (Workspaces page), and an enrollment
// token binds new agents to it (Agents page).
export default function Tenants() {
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const load = () => fetchTenants().then(setTenants).catch((e) => setErr(String(e.message ?? e)))
  useEffect(() => {
    load()
  }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    setBusy(true)
    setErr(null)
    try {
      await createTenant(name.trim())
      setName('')
      await load()
    } catch (e: any) {
      setErr(String(e.message ?? e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-3xl p-4 sm:p-6">
      <form onSubmit={submit} className="mb-6 flex flex-wrap items-end gap-2.5">
        <div className="flex-1 min-w-[220px]">
          <label className="mb-1 block text-[12px] font-medium text-dim">New tenant</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Acme Corp"
            className="w-full rounded-[8px] border border-border bg-surface px-3 py-2 text-[13.5px] text-fg focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
        <button
          type="submit"
          disabled={busy || !name.trim()}
          className="rounded-[8px] bg-accent px-4 py-2 text-[13px] font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          {busy ? 'Creating…' : 'Create tenant'}
        </button>
      </form>

      {err && <div className="mb-4 rounded-[8px] border border-critical/40 bg-critical/10 px-3 py-2 text-[12.5px] text-critical">{err}</div>}

      <div className="overflow-hidden rounded-[10px] border border-border">
        <table className="w-full text-left text-[13px]">
          <thead className="bg-surface-2 text-[11.5px] uppercase tracking-wide text-dim">
            <tr>
              <th className="px-4 py-2.5 font-medium">Name</th>
              <th className="px-4 py-2.5 font-medium">Slug</th>
              <th className="px-4 py-2.5 font-medium">Created</th>
            </tr>
          </thead>
          <tbody>
            {tenants.map((t) => (
              <tr key={t.id} className="border-t border-border">
                <td className="px-4 py-2.5 font-medium text-fg">{t.name}</td>
                <td className="px-4 py-2.5 font-mono text-[12px] text-muted">{t.slug}</td>
                <td className="px-4 py-2.5 text-dim">{new Date(t.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
            {tenants.length === 0 && (
              <tr>
                <td colSpan={3} className="px-4 py-6 text-center text-dim">No tenants yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
