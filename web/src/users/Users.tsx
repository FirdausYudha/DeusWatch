import { useEffect, useMemo, useState, type FormEvent } from 'react'
import {
  fetchUsers,
  createUser,
  updateUser,
  deleteUser,
  fetchPermissions,
  type UserInfo,
  type PermissionInfo,
  type Me,
} from '../lib/api'

const ROLE_BADGE: Record<string, string> = {
  admin: 'text-rose-300 bg-rose-500/15',
  analyst: 'text-amber-300 bg-amber-500/15',
  viewer: 'text-sky-300 bg-sky-500/15',
}

const ROLES = ['viewer', 'analyst', 'admin']

// groupBy preserves catalog order, splitting into [group, items] sections.
function groupBy(cat: PermissionInfo[]): [string, PermissionInfo[]][] {
  const groups: [string, PermissionInfo[]][] = []
  for (const p of cat) {
    const last = groups[groups.length - 1]
    if (last && last[0] === p.group) last[1].push(p)
    else groups.push([p.group, [p]])
  }
  return groups
}

function Checklist({
  groups,
  selected,
  onToggle,
}: {
  groups: [string, PermissionInfo[]][]
  selected: Set<string>
  onToggle: (key: string) => void
}) {
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {groups.map(([group, items]) => (
        <div key={group} className="rounded-[8px] border border-border bg-surface p-3">
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-dim">{group}</div>
          <div className="space-y-1.5">
            {items.map((p) => (
              <label key={p.key} className="flex cursor-pointer items-center gap-2 text-[12.5px] text-fg">
                <input
                  type="checkbox"
                  checked={selected.has(p.key)}
                  onChange={() => onToggle(p.key)}
                  className="h-4 w-4 rounded border-border-strong bg-surface-2 accent-indigo-500"
                />
                {p.label}
              </label>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

export default function Users({ me }: { me: Me }) {
  const [users, setUsers] = useState<UserInfo[]>([])
  const [catalog, setCatalog] = useState<PermissionInfo[]>([])
  const [roleDefaults, setRoleDefaults] = useState<Record<string, string[]>>({})
  const [error, setError] = useState('')

  // Create form.
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('viewer')
  const [custom, setCustom] = useState(false)
  const [perms, setPerms] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)

  // Inline editor.
  const [editId, setEditId] = useState<string | null>(null)
  const [editRole, setEditRole] = useState('viewer')
  const [editCustom, setEditCustom] = useState(false)
  const [editPerms, setEditPerms] = useState<Set<string>>(new Set())
  const [editBusy, setEditBusy] = useState(false)

  const groups = useMemo(() => groupBy(catalog), [catalog])

  const load = () => {
    fetchUsers()
      .then(setUsers)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(() => {
    load()
    fetchPermissions()
      .then((c) => {
        setCatalog(c.catalog)
        setRoleDefaults(c.role_defaults)
      })
      .catch((e) => setError((e as Error).message))
  }, [])

  // When enabling custom (create), prefill with the selected role's defaults.
  const toggleCustom = (on: boolean) => {
    setCustom(on)
    if (on) setPerms(new Set(roleDefaults[role] ?? []))
  }
  const onRoleChange = (r: string) => {
    setRole(r)
    if (custom) setPerms(new Set(roleDefaults[r] ?? []))
  }

  const togglePerm = (key: string) => {
    setPerms((prev) => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await createUser(username, password, role, custom ? [...perms] : null)
      setUsername('')
      setPassword('')
      setRole('viewer')
      setCustom(false)
      setPerms(new Set())
      load()
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const startEdit = (u: UserInfo) => {
    setEditId(u.id)
    setEditRole(u.role)
    const isCustom = u.permissions !== null
    setEditCustom(isCustom)
    setEditPerms(new Set(u.permissions ?? roleDefaults[u.role] ?? []))
    setError('')
  }
  const editToggleCustom = (on: boolean) => {
    setEditCustom(on)
    if (on) setEditPerms(new Set(roleDefaults[editRole] ?? []))
  }
  const editOnRoleChange = (r: string) => {
    setEditRole(r)
    if (editCustom) setEditPerms(new Set(roleDefaults[r] ?? []))
  }
  const editTogglePerm = (key: string) => {
    setEditPerms((prev) => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }
  const remove = async (u: UserInfo) => {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return
    setError('')
    try {
      await deleteUser(u.id)
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  const saveEdit = async () => {
    if (!editId) return
    setEditBusy(true)
    setError('')
    try {
      await updateUser(editId, editRole, editCustom ? [...editPerms] : null)
      setEditId(null)
      load()
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setEditBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-[1400px] px-6 py-5">
      <header className="mb-8">
        <p className="mt-0.5 text-[12px] text-muted">
          Manage accounts, roles, and per-user permissions (granular RBAC)
        </p>
      </header>

      <section className="mb-8 rounded-[12px] border border-border bg-surface p-5">
        <h2 className="mb-4 text-[11px] font-semibold uppercase tracking-wider text-dim">Add user</h2>
        <form onSubmit={submit} className="space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              className="w-40 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent"
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password (min 8)"
              className="w-44 rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent"
            />
            <select
              value={role}
              onChange={(e) => onRoleChange(e.target.value)}
              className="rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-2 text-[12.5px] text-fg">
              <input
                type="checkbox"
                checked={custom}
                onChange={(e) => toggleCustom(e.target.checked)}
                className="h-4 w-4 rounded border-border-strong bg-surface-2 accent-indigo-500"
              />
              Customize permissions
            </label>
            <button
              type="submit"
              disabled={busy || !username || !password}
              className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white transition-colors hover:opacity-90 disabled:opacity-50"
            >
              {busy ? 'Saving…' : 'Add'}
            </button>
          </div>
          {custom ? (
            <Checklist groups={groups} selected={perms} onToggle={togglePerm} />
          ) : (
            <p className="text-[11px] text-dim">
              Inherits the <span className="text-fg">{role}</span> role defaults. Tick “Customize
              permissions” to tailor exactly what this user can access.
            </p>
          )}
        </form>
        {error && <p className="mt-3 text-[12.5px] text-rose-400">{error}</p>}
      </section>

      <div className="overflow-hidden rounded-[12px] border border-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-surface text-[11px] uppercase tracking-wider text-dim">
            <tr>
              <th className="px-4 py-2 font-medium">Username</th>
              <th className="px-4 py-2 font-medium">Role</th>
              <th className="px-4 py-2 font-medium">Access</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Created</th>
              <th className="px-4 py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-surface">
            {users.map((u) => (
              <tr key={u.id} className="align-top hover:bg-surface-2">
                <td className="px-4 py-2 font-medium text-fg">{u.username}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${ROLE_BADGE[u.role] ?? 'text-muted bg-surface-2'}`}>
                    {u.role}
                  </span>
                </td>
                <td className="px-4 py-2 text-muted">
                  {u.permissions === null ? (
                    <span className="text-dim">role default</span>
                  ) : (
                    <span className="text-accent">custom · {u.permissions.length} perms</span>
                  )}
                </td>
                <td className="px-4 py-2 text-muted">{u.disabled ? 'disabled' : 'active'}</td>
                <td className="px-4 py-2 text-muted">{new Date(u.created_at).toLocaleString('en-US')}</td>
                <td className="px-4 py-2 text-right">
                  <div className="flex justify-end gap-2">
                    <button
                      onClick={() => startEdit(u)}
                      className="rounded-md border border-border px-2 py-1 text-[11px] text-fg transition-colors hover:bg-surface-2"
                    >
                      Edit access
                    </button>
                    {u.username !== me.username && (
                      <button
                        onClick={() => remove(u)}
                        className="rounded-md border border-rose-900/60 px-2 py-1 text-[11px] text-rose-300 transition-colors hover:bg-rose-500/10"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {editId && (
        <div className="fixed inset-0 z-20 grid place-items-center bg-black/50 p-4" onClick={() => setEditId(null)}>
          <div
            className="w-full max-w-2xl rounded-[12px] border border-border bg-surface p-5 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="mb-4 text-[12.5px] font-semibold text-fg">
              Edit access — <span className="text-accent">{users.find((u) => u.id === editId)?.username}</span>
            </h3>
            <div className="mb-4 flex flex-wrap items-center gap-3">
              <select
                value={editRole}
                onChange={(e) => editOnRoleChange(e.target.value)}
                className="rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent"
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
              <label className="flex items-center gap-2 text-[12.5px] text-fg">
                <input
                  type="checkbox"
                  checked={editCustom}
                  onChange={(e) => editToggleCustom(e.target.checked)}
                  className="h-4 w-4 rounded border-border-strong bg-surface-2 accent-indigo-500"
                />
                Customize permissions
              </label>
            </div>
            {editCustom ? (
              <Checklist groups={groups} selected={editPerms} onToggle={editTogglePerm} />
            ) : (
              <p className="text-[11px] text-dim">
                Inherits the <span className="text-fg">{editRole}</span> role defaults.
              </p>
            )}
            <div className="mt-5 flex justify-end gap-3">
              <button
                onClick={() => setEditId(null)}
                className="rounded-[8px] border border-border px-4 py-2 text-[12.5px] text-fg transition-colors hover:bg-surface-2"
              >
                Cancel
              </button>
              <button
                onClick={saveEdit}
                disabled={editBusy}
                className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white transition-colors hover:opacity-90 disabled:opacity-50"
              >
                {editBusy ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
