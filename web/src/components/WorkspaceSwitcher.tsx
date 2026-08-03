import { useEffect, useState } from 'react'
import { fetchMyWorkspaces, getActiveWorkspace, setActiveWorkspace, type Workspace } from '../lib/api'

// WorkspaceSwitcher lets an operator who belongs to more than one workspace narrow their view to a
// single workspace (or all of them). The choice is persisted and sent as X-Workspace-ID on every
// request, so the API re-scopes the user's tenant access. Changing it reloads the app so every page
// re-fetches under the new scope — simple and guaranteed-consistent (a reactive re-fetch of every
// page's data can come later). It stays hidden for the common single-workspace operator.
export default function WorkspaceSwitcher() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [active, setActive] = useState<string>(getActiveWorkspace() ?? '')

  useEffect(() => {
    fetchMyWorkspaces()
      .then(setWorkspaces)
      .catch(() => {})
  }, [])

  if (workspaces.length <= 1) return null

  const onChange = (id: string) => {
    setActive(id)
    setActiveWorkspace(id || null)
    // Re-scope everything: the safest way to make every already-mounted page re-fetch.
    window.location.reload()
  }

  return (
    <label className="flex items-center gap-1.5" title="Active workspace — narrows what you can see">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true" className="text-dim">
        <path d="M3 7l9-4 9 4-9 4zM3 7v10l9 4 9-4V7" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <select
        value={active}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-[8px] border border-border bg-surface px-2 py-1 text-[13.5px] text-fg transition-colors hover:bg-surface-2 focus:outline-none"
      >
        <option value="">All workspaces</option>
        {workspaces.map((w) => (
          <option key={w.id} value={w.id}>
            {w.name}
          </option>
        ))}
      </select>
    </label>
  )
}
