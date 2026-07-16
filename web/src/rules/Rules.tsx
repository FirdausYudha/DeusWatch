import { useEffect, useMemo, useState } from 'react'
import { fetchRules, createRule, updateRule, deleteRule, fetchRulePacks, toggleRulePack, type Rule, type RulePack } from '../lib/api'

const KIND_BADGE: Record<string, string> = {
  single: 'text-sky-300 bg-sky-500/15',
  aggregation: 'text-violet-300 bg-violet-500/15',
}

const NEW_RULE_TEMPLATE = `title: My rule
status: experimental
description: What this detects
level: medium
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event.dataset: sshd
    event.outcome: failure
  condition: selection
tags:
  - attack.t1110
`

type KindFilter = 'all' | 'single' | 'aggregation'
type StatusFilter = 'all' | 'enabled' | 'disabled'

// Human labels for the on-disk rule categories (folder names). Unknown categories fall
// back to a capitalized form.
const CATEGORY_LABEL: Record<string, string> = {
  judi: 'Judi Online',
  deface: 'Web Defacement',
  fim: 'FIM',
  endpoint: 'Endpoint',
  agg: 'Aggregation',
  general: 'General',
  custom: 'Custom',
}

const categoryLabel = (c: string): string =>
  CATEGORY_LABEL[c] ?? (c ? c.charAt(0).toUpperCase() + c.slice(1) : 'Uncategorized')

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([])
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<Rule | null>(null)
  const [creating, setCreating] = useState(false)
  const [query, setQuery] = useState('')
  const [kindFilter, setKindFilter] = useState<KindFilter>('all')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [categoryFilter, setCategoryFilter] = useState('all')

  const load = () => {
    fetchRules()
      .then(setRules)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(load, [])

  const toggle = async (r: Rule) => {
    setError('')
    try {
      await updateRule(r.id, r.name, r.yaml, !r.enabled)
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }
  const remove = async (r: Rule) => {
    if (!confirm(`Delete rule "${r.name}"?`)) return
    setError('')
    try {
      await deleteRule(r.id)
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const counts = useMemo(
    () => ({ total: rules.length, enabled: rules.filter((r) => r.enabled).length }),
    [rules],
  )

  // Distinct categories present, with a count each, for the category filter. Ordered by the
  // known-label order first, then any extras alphabetically.
  const categories = useMemo(() => {
    const counts = new Map<string, number>()
    for (const r of rules) {
      const c = r.category || 'general'
      counts.set(c, (counts.get(c) ?? 0) + 1)
    }
    const order = Object.keys(CATEGORY_LABEL)
    return [...counts.entries()].sort((a, b) => {
      const ia = order.indexOf(a[0]), ib = order.indexOf(b[0])
      if (ia !== -1 || ib !== -1) return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib)
      return a[0].localeCompare(b[0])
    })
  }, [rules])

  // Precompute a lowercase search haystack (name + source + YAML body) once per load,
  // so filtering across ~1000 rules stays cheap on every keystroke.
  const indexed = useMemo(
    () => rules.map((r) => ({ r, hay: `${r.name} ${sourceOf(r.yaml)} ${r.yaml}`.toLowerCase() })),
    [rules],
  )

  const filtered = useMemo(() => {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean)
    return indexed
      .filter(({ r }) => categoryFilter === 'all' || (r.category || 'general') === categoryFilter)
      .filter(({ r }) => kindFilter === 'all' || r.kind === kindFilter)
      .filter(({ r }) =>
        statusFilter === 'all' || (statusFilter === 'enabled' ? r.enabled : !r.enabled),
      )
      // every whitespace-separated term must appear (AND) — lets you narrow with "judi gacor".
      .filter(({ hay }) => terms.every((t) => hay.includes(t)))
      .map(({ r }) => r)
  }, [indexed, query, kindFilter, statusFilter, categoryFilter])

  return (
    <div className="mx-auto max-w-5xl px-8 py-8">
      <header className="mb-6 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Detection rules</h1>
          <p className="mt-1 text-sm text-slate-500">
            Sigma rules · {counts.enabled}/{counts.total} enabled · edits apply to the worker within ~30s
          </p>
        </div>
        <button
          onClick={() => setCreating(true)}
          className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400"
        >
          + New rule
        </button>
      </header>

      {error && <p className="mb-4 text-sm text-rose-400">{error}</p>}

      <RulePacks onChanged={load} />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[220px]">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Escape' && setQuery('')}
            placeholder="Search name, source, or rule body (e.g. gacor, judi, T1110, shadow)…"
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 pr-8 text-sm text-slate-200 outline-none placeholder:text-slate-500 focus:border-indigo-500"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              aria-label="Clear search"
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded px-1 text-slate-500 hover:text-slate-300"
            >
              ×
            </button>
          )}
        </div>
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 outline-none focus:border-indigo-500"
        >
          <option value="all">All categories</option>
          {categories.map(([c, n]) => (
            <option key={c} value={c}>
              {categoryLabel(c)} ({n})
            </option>
          ))}
        </select>
        <select
          value={kindFilter}
          onChange={(e) => setKindFilter(e.target.value as KindFilter)}
          className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 outline-none focus:border-indigo-500"
        >
          <option value="all">All types</option>
          <option value="single">single-event</option>
          <option value="aggregation">aggregation</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
          className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 outline-none focus:border-indigo-500"
        >
          <option value="all">All status</option>
          <option value="enabled">enabled</option>
          <option value="disabled">disabled</option>
        </select>
        <span className="ml-auto whitespace-nowrap text-xs text-slate-500">
          {filtered.length} of {counts.total}
        </span>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2 font-medium">Name</th>
              <th className="px-4 py-2 font-medium">Category</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Source</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  {rules.length === 0 ? 'No rules.' : 'No rules match your search.'}
                </td>
              </tr>
            )}
            {filtered.map((r) => (
              <tr key={r.id} className="hover:bg-slate-800/40">
                <td className="px-4 py-2 font-medium text-slate-200">
                  {r.name}
                  {r.builtin && <span className="ml-2 rounded bg-slate-700/40 px-1.5 py-0.5 text-[10px] text-slate-400">builtin</span>}
                </td>
                <td className="px-4 py-2">
                  <button
                    onClick={() => setCategoryFilter(r.category || 'general')}
                    title="Filter by this category"
                    className="rounded bg-slate-700/40 px-1.5 py-0.5 text-xs text-slate-300 hover:bg-slate-700"
                  >
                    {categoryLabel(r.category || 'general')}
                  </button>
                </td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${KIND_BADGE[r.kind] ?? 'text-slate-400 bg-slate-700/40'}`}>
                    {r.kind === 'aggregation' ? 'aggregation' : 'single-event'}
                  </span>
                </td>
                <td className="px-4 py-2 text-slate-400">{sourceOf(r.yaml)}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${r.enabled ? 'text-emerald-300 bg-emerald-500/15' : 'text-slate-400 bg-slate-700/40'}`}>
                    {r.enabled ? 'enabled' : 'disabled'}
                  </span>
                </td>
                <td className="px-4 py-2 text-right">
                  <div className="flex justify-end gap-2">
                    <button onClick={() => toggle(r)} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">
                      {r.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button onClick={() => setEditing(r)} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">
                      Edit
                    </button>
                    <button onClick={() => remove(r)} className="rounded-md border border-rose-900/60 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10">
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {creating && (
        <RuleEditor
          title="New rule"
          initialName=""
          initialYaml={NEW_RULE_TEMPLATE}
          onClose={() => setCreating(false)}
          onSave={async (name, yaml) => {
            await createRule(name, yaml)
            setCreating(false)
            load()
          }}
        />
      )}
      {editing && (
        <RuleEditor
          title={`Edit — ${editing.name}`}
          initialName={editing.name}
          initialYaml={editing.yaml}
          onClose={() => setEditing(null)}
          onSave={async (name, yaml) => {
            await updateRule(editing.id, name, yaml, editing.enabled)
            setEditing(null)
            load()
          }}
        />
      )}
    </div>
  )
}

// RulePacks is the marketplace: enable/disable whole detection domains (installed packs =
// rule categories) in one click, and browse real-world third-party rulesets to bring in.
function RulePacks({ onChanged }: { onChanged: () => void }) {
  const [packs, setPacks] = useState<RulePack[]>([])
  const [open, setOpen] = useState(true)
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')

  const load = () => { fetchRulePacks().then(setPacks).catch((e) => setErr((e as Error).message)) }
  useEffect(load, [])

  const installed = packs.filter((p) => p.installed)
  const external = packs.filter((p) => !p.installed)

  const toggle = async (p: RulePack, enable: boolean) => {
    setBusy(p.id); setErr('')
    try {
      await toggleRulePack(p.id, enable)
      load()          // refresh pack counts
      onChanged()     // refresh the rules table
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  return (
    <section className="mb-6 rounded-xl border border-slate-800 bg-slate-900/40 p-4">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between text-left">
        <div>
          <h2 className="text-sm font-semibold text-white">Rule packs</h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Enable a whole detection domain in one click, or browse third-party rulesets to add.
          </p>
        </div>
        <span className="text-slate-500">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="mt-4 space-y-5">
          {err && <p className="text-sm text-rose-400">{err}</p>}

          {/* Installed packs — toggle the real bundled rules */}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {installed.map((p) => {
              const allOn = p.rule_count > 0 && p.enabled === p.rule_count
              const someOn = p.enabled > 0 && !allOn
              return (
                <div key={p.id} className="flex flex-col rounded-lg border border-slate-800 bg-slate-900 p-3">
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-200">{p.name}</span>
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${allOn ? 'text-emerald-300 bg-emerald-500/15' : someOn ? 'text-amber-300 bg-amber-500/15' : 'text-slate-400 bg-slate-700/40'}`}>
                      {p.enabled}/{p.rule_count}
                    </span>
                  </div>
                  <p className="mb-3 flex-1 text-xs leading-relaxed text-slate-500">{p.description}</p>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase tracking-wider text-slate-600">{p.source}</span>
                    <button
                      onClick={() => toggle(p, !allOn)}
                      disabled={busy === p.id}
                      className={`rounded-md border px-2.5 py-1 text-xs disabled:opacity-50 ${allOn ? 'border-slate-700 text-slate-300 hover:bg-slate-800' : 'border-indigo-600/60 text-indigo-300 hover:bg-indigo-500/10'}`}
                    >
                      {busy === p.id ? '…' : allOn ? 'Disable all' : someOn ? 'Enable rest' : 'Enable all'}
                    </button>
                  </div>
                </div>
              )
            })}
          </div>

          {/* External catalog — real-world rulesets you bring in (link-out) */}
          {external.length > 0 && (
            <div>
              <h3 className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-500">From the community & vendors</h3>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {external.map((p) => (
                  <a
                    key={p.id}
                    href={p.url}
                    target="_blank"
                    rel="noreferrer"
                    className="group flex flex-col rounded-lg border border-slate-800 bg-slate-900/60 p-3 transition-colors hover:border-slate-700"
                  >
                    <div className="mb-1 flex items-center justify-between gap-2">
                      <span className="font-medium text-slate-200 group-hover:text-white">{p.name}</span>
                      <span className="rounded bg-slate-700/40 px-1.5 py-0.5 text-[10px] text-slate-400">External</span>
                    </div>
                    <p className="mb-2 flex-1 text-xs leading-relaxed text-slate-500">{p.description}</p>
                    <span className="text-[11px] text-indigo-300 group-hover:text-indigo-200">{p.source} · Open ↗</span>
                  </a>
                ))}
              </div>
              <p className="mt-2 text-[11px] text-slate-600">
                External rulesets are brought in via <span className="text-slate-400">New rule</span> (paste Sigma YAML) or the matching sensor input — not one-click yet.
              </p>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

// sourceOf pulls a short "product/service" hint out of the rule YAML for the table.
function sourceOf(yaml: string): string {
  const product = yaml.match(/product:\s*(\S+)/)?.[1]
  const service = yaml.match(/service:\s*(\S+)/)?.[1]
  const category = yaml.match(/category:\s*(\S+)/)?.[1]
  return [product, service ?? category].filter(Boolean).join(' / ') || '—'
}

function RuleEditor({
  title,
  initialName,
  initialYaml,
  onClose,
  onSave,
}: {
  title: string
  initialName: string
  initialYaml: string
  onClose: () => void
  onSave: (name: string, yaml: string) => Promise<void>
}) {
  const [name, setName] = useState(initialName)
  const [yaml, setYaml] = useState(initialYaml)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const save = async () => {
    setBusy(true)
    setError('')
    try {
      await onSave(name.trim(), yaml)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div className="flex max-h-[90vh] w-full max-w-2xl flex-col rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h2 className="mb-1 text-lg font-semibold text-white">{title}</h2>
        <p className="mb-3 text-xs text-slate-500">
          Sigma YAML. An aggregation condition (e.g. <code className="text-slate-300">selection | count() by source.ip &gt; 10</code>)
          makes it an aggregation rule (banlist/brute-force); otherwise it is single-event.
        </p>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Name (defaults to the rule title)"
          className="mb-3 w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
        />
        <textarea
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          spellCheck={false}
          rows={16}
          className="w-full flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-indigo-500"
        />
        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">
            Cancel
          </button>
          <button
            onClick={save}
            disabled={busy || !yaml.trim()}
            className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50"
          >
            {busy ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  )
}
