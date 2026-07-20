import { useEffect, useMemo, useState } from 'react'
import {
  fetchRules, createRule, updateRule, deleteRule,
  fetchRulePacks, toggleRulePack, installRulePack, uninstallRulePack,
  type Rule, type RulePack,
} from '../lib/api'
import { usePersistedState } from '../lib/usePersistedState'

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
  // Persisted so the filters survive leaving the page (the search box stays transient).
  const [kindFilter, setKindFilter] = usePersistedState<KindFilter>('rules.kind', 'all')
  const [statusFilter, setStatusFilter] = usePersistedState<StatusFilter>('rules.status', 'all')
  const [categoryFilter, setCategoryFilter] = usePersistedState('rules.category', 'all')

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
    <div className="mx-auto max-w-[1400px] px-6 py-5">
      <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="mt-0.5 text-[12px] text-muted">
            Sigma rules · {counts.enabled}/{counts.total} enabled · edits apply to the worker within ~30s
          </p>
        </div>
        <button
          onClick={() => setCreating(true)}
          className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white transition-colors hover:opacity-90"
        >
          + New rule
        </button>
      </header>

      {error && <p className="mb-4 text-[12.5px] text-rose-400">{error}</p>}

      <RulePacks onChanged={load} />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[220px]">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Escape' && setQuery('')}
            placeholder="Search name, source, or rule body (e.g. gacor, judi, T1110, shadow)…"
            className="w-full rounded-[8px] border border-border bg-surface-2 px-3 py-2 pr-8 text-[12.5px] text-fg outline-none placeholder:text-dim focus:border-accent"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              aria-label="Clear search"
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded px-1 text-dim hover:text-fg"
            >
              ×
            </button>
          )}
        </div>
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] text-fg outline-none focus:border-accent"
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
          className="rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] text-fg outline-none focus:border-accent"
        >
          <option value="all">All types</option>
          <option value="single">single-event</option>
          <option value="aggregation">aggregation</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
          className="rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] text-fg outline-none focus:border-accent"
        >
          <option value="all">All status</option>
          <option value="enabled">enabled</option>
          <option value="disabled">disabled</option>
        </select>
        <span className="ml-auto whitespace-nowrap text-[11px] text-dim">
          {filtered.length} of {counts.total}
        </span>
      </div>

      <div className="overflow-hidden rounded-[12px] border border-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-surface text-[11px] uppercase tracking-wider text-dim">
            <tr>
              <th className="px-4 py-2 font-medium">Name</th>
              <th className="px-4 py-2 font-medium">Category</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Source</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-surface">
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-dim">
                  {rules.length === 0 ? 'No rules.' : 'No rules match your search.'}
                </td>
              </tr>
            )}
            {filtered.map((r) => (
              <tr key={r.id} className="hover:bg-surface-2">
                <td className="px-4 py-2 font-medium text-fg">
                  {r.name}
                  {r.builtin && <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">builtin</span>}
                </td>
                <td className="px-4 py-2">
                  <button
                    onClick={() => setCategoryFilter(r.category || 'general')}
                    title="Filter by this category"
                    className="rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-fg hover:bg-surface-2"
                  >
                    {categoryLabel(r.category || 'general')}
                  </button>
                </td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${KIND_BADGE[r.kind] ?? 'text-muted bg-surface-2'}`}>
                    {r.kind === 'aggregation' ? 'aggregation' : 'single-event'}
                  </span>
                </td>
                <td className="px-4 py-2 text-muted">{sourceOf(r.yaml)}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${r.enabled ? 'text-emerald-300 bg-emerald-500/15' : 'text-muted bg-surface-2'}`}>
                    {r.enabled ? 'enabled' : 'disabled'}
                  </span>
                </td>
                <td className="px-4 py-2 text-right">
                  <div className="flex justify-end gap-2">
                    <button onClick={() => toggle(r)} className="rounded-md border border-border px-2 py-1 text-[11px] text-fg hover:bg-surface-2">
                      {r.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button onClick={() => setEditing(r)} className="rounded-md border border-border px-2 py-1 text-[11px] text-fg hover:bg-surface-2">
                      Edit
                    </button>
                    <button onClick={() => remove(r)} className="rounded-md border border-rose-900/60 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/10">
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
  // Collapsed by default to keep the page minimal; the choice is remembered once you open it.
  const [open, setOpen] = usePersistedState('rules.packsOpen', false)
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')

  const load = () => { fetchRulePacks().then(setPacks).catch((e) => setErr((e as Error).message)) }
  useEffect(load, [])

  const installed = packs.filter((p) => p.installed)
  const available = packs.filter((p) => !p.installed && p.installable)
  const external = packs.filter((p) => !p.installed && !p.installable)

  // run wraps a pack action: refresh the pack counts and the rules table afterwards.
  const run = async (id: string, fn: () => Promise<unknown>) => {
    setBusy(id); setErr('')
    try {
      await fn()
      load()      // refresh pack counts
      onChanged() // refresh the rules table
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy('')
    }
  }
  const toggle = (p: RulePack, enable: boolean) => run(p.id, () => toggleRulePack(p.id, enable))
  const install = (p: RulePack) => run(p.id, () => installRulePack(p.id))
  const uninstall = (p: RulePack) => {
    if (!confirm(`Uninstall "${p.name}"? Its ${p.rule_count} rule(s) will be removed. You can re-install it any time.`)) return
    run(p.id, () => uninstallRulePack(p.id))
  }

  return (
    <section className="mb-6 rounded-[12px] border border-border bg-surface p-4">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between text-left">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-[12.5px] font-semibold text-fg">Rule packs</h2>
            {available.length > 0 && (
              <span className="rounded bg-accent-soft px-1.5 py-0.5 text-[10px] font-medium text-accent">
                {available.length} available to install
              </span>
            )}
          </div>
          <p className="mt-0.5 text-[11px] text-dim">
            Enable a whole detection domain in one click, or browse third-party rulesets to add.
          </p>
        </div>
        <span className="text-dim">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="mt-4 space-y-5">
          {err && <p className="text-[12.5px] text-rose-400">{err}</p>}

          {/* Installed packs — toggle the real bundled rules */}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {installed.map((p) => {
              const allOn = p.rule_count > 0 && p.enabled === p.rule_count
              const someOn = p.enabled > 0 && !allOn
              return (
                <div key={p.id} className="flex flex-col rounded-[8px] border border-border bg-surface p-3">
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <span className="font-medium text-fg">{p.name}</span>
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${allOn ? 'text-emerald-300 bg-emerald-500/15' : someOn ? 'text-amber-300 bg-amber-500/15' : 'text-muted bg-surface-2'}`}>
                      {p.enabled}/{p.rule_count}
                    </span>
                  </div>
                  <p className="mb-3 flex-1 text-[11px] leading-relaxed text-dim">{p.description}</p>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase tracking-wider text-dim">{p.source}</span>
                    <div className="flex gap-2">
                      {p.remote && (
                        <button
                          onClick={() => install(p)}
                          disabled={busy === p.id}
                          title="Re-fetch from the feed — adds any rules published since you installed"
                          className="rounded-md border border-border px-2.5 py-1 text-[11px] text-fg hover:bg-surface-2 disabled:opacity-50"
                        >
                          {busy === p.id ? '…' : 'Update'}
                        </button>
                      )}
                      {p.installable && (
                        <button
                          onClick={() => uninstall(p)}
                          disabled={busy === p.id}
                          className="rounded-md border border-rose-900/60 px-2.5 py-1 text-[11px] text-rose-300 hover:bg-rose-500/10 disabled:opacity-50"
                        >
                          Uninstall
                        </button>
                      )}
                      <button
                        onClick={() => toggle(p, !allOn)}
                        disabled={busy === p.id}
                        className={`rounded-md border px-2.5 py-1 text-[11px] disabled:opacity-50 ${allOn ? 'border-border text-fg hover:bg-surface-2' : 'border-indigo-600/60 text-accent hover:bg-accent-soft'}`}
                      >
                        {busy === p.id ? '…' : allOn ? 'Disable all' : someOn ? 'Enable rest' : 'Enable all'}
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Bundled curated packs not installed yet — real one-click Install, no network */}
          {available.length > 0 && (
            <div>
              <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-dim">Available to install</h3>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {available.map((p) => (
                  <div key={p.id} className="flex flex-col rounded-[8px] border border-indigo-900/50 bg-accent-soft p-3">
                    <div className="mb-1 flex items-center justify-between gap-2">
                      <span className="font-medium text-fg">{p.name}</span>
                      <div className="flex shrink-0 items-center gap-1">
                        {p.remote && <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">online</span>}
                        <span className="rounded bg-accent-soft px-1.5 py-0.5 text-[10px] font-medium text-accent">{p.rule_count} rules</span>
                      </div>
                    </div>
                    <p className="mb-3 flex-1 text-[11px] leading-relaxed text-dim">{p.description}</p>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase tracking-wider text-dim">{p.source}</span>
                      <button
                        onClick={() => install(p)}
                        disabled={busy === p.id}
                        className="rounded-md bg-accent px-3 py-1 text-[11px] font-medium text-white hover:opacity-90 disabled:opacity-50"
                      >
                        {busy === p.id ? 'Installing…' : 'Install'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[11px] text-dim">
                Packs without an <span className="text-muted">online</span> tag are bundled with DeusWatch — Install works with no internet.
                Online packs are fetched from the DeusWatch feed so they can be added or refreshed without upgrading (set <span className="font-mono">PACKS_FEED_URL=off</span> to disable).
              </p>
            </div>
          )}

          {/* External catalog — real-world rulesets you bring in (link-out) */}
          {external.length > 0 && (
            <div>
              <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-dim">From the community & vendors</h3>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {external.map((p) => (
                  <a
                    key={p.id}
                    href={p.url}
                    target="_blank"
                    rel="noreferrer"
                    className="group flex flex-col rounded-[8px] border border-border bg-surface p-3 transition-colors hover:border-border"
                  >
                    <div className="mb-1 flex items-center justify-between gap-2">
                      <span className="font-medium text-fg group-hover:text-fg">{p.name}</span>
                      <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">External</span>
                    </div>
                    <p className="mb-2 flex-1 text-[11px] leading-relaxed text-dim">{p.description}</p>
                    <span className="text-[11px] text-accent group-hover:text-accent">{p.source} · Open ↗</span>
                  </a>
                ))}
              </div>
              <p className="mt-2 text-[11px] text-dim">
                External rulesets are brought in via <span className="text-muted">New rule</span> (paste Sigma YAML) or the matching sensor input — not one-click yet.
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
      <div className="flex max-h-[90vh] w-full max-w-2xl flex-col rounded-[12px] border border-border bg-surface p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h2 className="mb-1 text-[15px] font-semibold text-fg">{title}</h2>
        <p className="mb-3 text-[11px] text-dim">
          Sigma YAML. An aggregation condition (e.g. <code className="text-fg">selection | count() by source.ip &gt; 10</code>)
          makes it an aggregation rule (banlist/brute-force); otherwise it is single-event.
        </p>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Name (defaults to the rule title)"
          className="mb-3 w-full rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] outline-none focus:border-accent"
        />
        <textarea
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          spellCheck={false}
          rows={16}
          className="w-full flex-1 rounded-[8px] border border-border bg-bg px-3 py-2 font-mono text-[11px] text-fg outline-none focus:border-accent"
        />
        {error && <p className="mt-3 text-[12.5px] text-rose-400">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-[8px] border border-border px-4 py-2 text-[12.5px] text-fg hover:bg-surface-2">
            Cancel
          </button>
          <button
            onClick={save}
            disabled={busy || !yaml.trim()}
            className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            {busy ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  )
}
