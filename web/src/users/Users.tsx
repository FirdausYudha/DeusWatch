import { useEffect, useState, type FormEvent } from 'react'
import { fetchUsers, createUser, type UserInfo } from '../lib/api'

const ROLE_BADGE: Record<string, string> = {
  admin: 'text-rose-300 bg-rose-500/15',
  analyst: 'text-amber-300 bg-amber-500/15',
  viewer: 'text-sky-300 bg-sky-500/15',
}

export default function Users() {
  const [users, setUsers] = useState<UserInfo[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('viewer')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () => {
    fetchUsers()
      .then(setUsers)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(load, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await createUser(username, password, role)
      setUsername('')
      setPassword('')
      setRole('viewer')
      load()
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-4xl px-8 py-8">
      <header className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight text-white">Users</h1>
        <p className="mt-1 text-sm text-slate-500">Kelola akun & peran (admin)</p>
      </header>

      <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Tambah user</h2>
        <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username"
            className="w-40 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password (min 8)"
            className="w-44 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          >
            <option value="viewer">viewer</option>
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
          <button
            type="submit"
            disabled={busy || !username || !password}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400 disabled:opacity-50"
          >
            {busy ? 'Menyimpan…' : 'Tambah'}
          </button>
        </form>
        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
      </section>

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2 font-medium">Username</th>
              <th className="px-4 py-2 font-medium">Role</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Dibuat</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {users.map((u) => (
              <tr key={u.id} className="hover:bg-slate-800/40">
                <td className="px-4 py-2 font-medium text-slate-200">{u.username}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${ROLE_BADGE[u.role] ?? 'text-slate-400 bg-slate-700/40'}`}>
                    {u.role}
                  </span>
                </td>
                <td className="px-4 py-2 text-slate-400">{u.disabled ? 'nonaktif' : 'aktif'}</td>
                <td className="px-4 py-2 text-slate-400">{new Date(u.created_at).toLocaleString('id-ID')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
