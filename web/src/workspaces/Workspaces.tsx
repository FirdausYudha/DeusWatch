import { useEffect, useState } from 'react'
import {
  fetchAllWorkspaces,
  createWorkspace,
  deleteWorkspace,
  fetchTenants,
  fetchWorkspaceTenants,
  setWorkspaceTenants,
  fetchWorkspaceMembers,
  setWorkspaceMembers,
  fetchUsers,
  type Workspace,
  type Tenant,
  type UserInfo,
} from '../lib/api'
import DocLink from '../components/DocLink'

// Workspaces admin (manage_workspaces). A workspace is a team: it grants access to one+ tenants
// (many-to-many) and holds user memberships. A user's effective tenant scope is the union across the
// workspaces they belong to. Select a workspace to edit which tenants it reaches and who is in it.
export default function Workspaces() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [selected, setSelected] = useState<Workspace | null>(null)
  const [name, setName] = useState('')
  const [err, setErr] = useState<string | null>(null)

  const load = () => fetchAllWorkspaces().then(setWorkspaces).catch((e) => setErr(String(e.message ?? e)))
  useEffect(() => {
    load()
  }, [])

  const remove = async (w: Workspace) => {
    if (!confirm(`Delete workspace “${w.name}”? Members and tenant grants are removed. This cannot be undone.`)) return
    setErr(null)
    try {
      await deleteWorkspace(w.id)
      if (selected?.id === w.id) setSelected(null)
      await load()
    } catch (e: any) {
      setErr(String(e.message ?? e))
    }
  }

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    setErr(null)
    try {
      const ws = await createWorkspace(name.trim())
      setName('')
      await load()
      setSelected(ws)
    } catch (e: any) {
      setErr(String(e.message ?? e))
    }
  }

  return (
    <div className="mx-auto max-w-5xl p-4 sm:p-6">
     <div className="mb-4 flex items-center justify-between">
       <p className="text-[12.5px] text-dim">A workspace grants a team access to one or more tenants.</p>
       <DocLink file="multi-tenancy.md" />
     </div>
     <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
      {/* List + create */}
      <div>
        <form onSubmit={create} className="mb-4 flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="New workspace name"
            className="min-w-0 flex-1 rounded-[8px] border border-border bg-surface px-3 py-2 text-[13px] text-fg focus:outline-none focus:ring-1 focus:ring-accent"
          />
          <button
            type="submit"
            disabled={!name.trim()}
            className="rounded-[8px] bg-accent px-3 py-2 text-[13px] font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            Add
          </button>
        </form>
        {err && <div className="mb-3 rounded-[8px] border border-critical/40 bg-critical/10 px-3 py-2 text-[12px] text-critical">{err}</div>}
        <div className="flex flex-col gap-1">
          {workspaces.map((w) => (
            <div key={w.id} className="group flex items-center gap-1">
              <button
                onClick={() => setSelected(w)}
                className={`flex-1 rounded-[8px] px-3 py-2 text-left text-[13.5px] transition-colors ${
                  selected?.id === w.id ? 'bg-accent-soft text-accent' : 'text-muted hover:bg-surface-2 hover:text-fg'
                }`}
              >
                {w.name}
              </button>
              {w.slug !== 'default' && (
                <button
                  onClick={() => remove(w)}
                  title="Delete workspace"
                  aria-label={`Delete ${w.name}`}
                  className="rounded-[7px] border border-transparent px-2 py-1.5 text-[11.5px] text-dim opacity-0 transition-all hover:border-critical/50 hover:bg-critical/10 hover:text-critical group-hover:opacity-100"
                >
                  ✕
                </button>
              )}
            </div>
          ))}
          {workspaces.length === 0 && <div className="px-3 py-4 text-[12.5px] text-dim">No workspaces yet.</div>}
        </div>
      </div>

      {/* Detail editor */}
      <div>
        {selected ? (
          <WorkspaceEditor key={selected.id} workspace={selected} />
        ) : (
          <div className="grid h-40 place-items-center rounded-[10px] border border-dashed border-border text-[13px] text-dim">
            Select a workspace to edit its tenants and members.
          </div>
        )}
      </div>
     </div>
    </div>
  )
}

function WorkspaceEditor({ workspace }: { workspace: Workspace }) {
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [users, setUsers] = useState<UserInfo[]>([])
  const [tenantIDs, setTenantIDs] = useState<Set<string>>(new Set())
  const [memberIDs, setMemberIDs] = useState<Set<string>>(new Set())
  const [savedMsg, setSavedMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([
      fetchTenants(),
      fetchUsers(),
      fetchWorkspaceTenants(workspace.id),
      fetchWorkspaceMembers(workspace.id),
    ])
      .then(([ts, us, wt, wm]) => {
        setTenants(ts)
        setUsers(us)
        setTenantIDs(new Set(wt))
        setMemberIDs(new Set(wm.map((m) => m.user_id)))
      })
      .catch((e) => setErr(String(e.message ?? e)))
  }, [workspace.id])

  const toggle = (set: Set<string>, upd: (s: Set<string>) => void, id: string) => {
    const next = new Set(set)
    next.has(id) ? next.delete(id) : next.add(id)
    upd(next)
  }

  const save = async () => {
    setErr(null)
    setSavedMsg(null)
    try {
      await setWorkspaceTenants(workspace.id, [...tenantIDs])
      await setWorkspaceMembers(workspace.id, [...memberIDs])
      setSavedMsg('Saved.')
      setTimeout(() => setSavedMsg(null), 2000)
    } catch (e: any) {
      setErr(String(e.message ?? e))
    }
  }

  return (
    <div className="rounded-[10px] border border-border p-4">
      <h2 className="mb-4 text-[15px] font-bold text-fg">{workspace.name}</h2>
      {err && <div className="mb-3 rounded-[8px] border border-critical/40 bg-critical/10 px-3 py-2 text-[12px] text-critical">{err}</div>}

      <section className="mb-5">
        <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-wide text-dim">Tenants (data access)</h3>
        <div className="flex flex-col gap-1.5">
          {tenants.map((t) => (
            <label key={t.id} className="flex items-center gap-2 text-[13px] text-fg">
              <input type="checkbox" checked={tenantIDs.has(t.id)} onChange={() => toggle(tenantIDs, setTenantIDs, t.id)} />
              {t.name}
            </label>
          ))}
          {tenants.length === 0 && <span className="text-[12.5px] text-dim">No tenants — create one on the Tenants page.</span>}
        </div>
      </section>

      <section className="mb-5">
        <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-wide text-dim">Members</h3>
        <div className="flex max-h-56 flex-col gap-1.5 overflow-y-auto">
          {users.map((u) => (
            <label key={u.id} className="flex items-center gap-2 text-[13px] text-fg">
              <input type="checkbox" checked={memberIDs.has(u.id)} onChange={() => toggle(memberIDs, setMemberIDs, u.id)} />
              {u.username}
            </label>
          ))}
        </div>
      </section>

      <div className="flex items-center gap-3">
        <button onClick={save} className="rounded-[8px] bg-accent px-4 py-2 text-[13px] font-semibold text-white transition-opacity hover:opacity-90">
          Save changes
        </button>
        {savedMsg && <span className="text-[12.5px] text-emerald-500">{savedMsg}</span>}
      </div>
    </div>
  )
}
