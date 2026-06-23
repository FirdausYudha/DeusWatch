import { useEffect, useMemo, useState } from 'react'
import { fetchRules, createRule, updateRule, deleteRule, type Rule } from '../lib/api'

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

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([])
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<Rule | null>(null)
  const [creating, setCreating] = useState(false)

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

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2 font-medium">Name</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Source</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {rules.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-slate-500">No rules.</td>
              </tr>
            )}
            {rules.map((r) => (
              <tr key={r.id} className="hover:bg-slate-800/40">
                <td className="px-4 py-2 font-medium text-slate-200">
                  {r.name}
                  {r.builtin && <span className="ml-2 rounded bg-slate-700/40 px-1.5 py-0.5 text-[10px] text-slate-400">builtin</span>}
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
