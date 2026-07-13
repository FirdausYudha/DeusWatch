import { useEffect, useState, type FormEvent } from 'react'
import {
  fetchPlaybooks, createPlaybook, updatePlaybook, deletePlaybook,
  type PlaybookInfo, type PlaybookSpec,
} from '../lib/api'

const EMPTY: PlaybookSpec = { label: '', name: '', steps: [] }
const input = 'w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 outline-none focus:border-indigo-500'

// Common labels: MITRE tactics (single/aggregation rules label alerts by tactic) plus
// the built-in specials. Free text is still allowed for custom labels.
const KNOWN_LABELS = [
  'bruteforce', 'credential_access', 'initial_access', 'reconnaissance', 'discovery',
  'persistence', 'privilege_escalation', 'defense_evasion', 'execution', 'impact',
  'lateral_movement', 'collection', 'exfiltration', 'command_and_control', 'selfhealth',
]

function specOf(p: PlaybookInfo): PlaybookSpec {
  return { label: p.label, name: p.name, steps: p.steps }
}

// The steps editor works on one textarea (one step per line) - simple and pasteable.
function Form({ value, onChange }: { value: PlaybookSpec; onChange: (v: PlaybookSpec) => void }) {
  return (
    <div className="grid gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block"><span className="mb-1 block text-xs text-slate-400">Label * <span className="text-slate-600">(the alert's deuswatch.label this playbook applies to)</span></span>
          <input className={input} list="playbook-labels" value={value.label}
            onChange={(e) => onChange({ ...value, label: e.target.value })} placeholder="e.g. bruteforce" />
          <datalist id="playbook-labels">
            {KNOWN_LABELS.map((l) => <option key={l} value={l} />)}
          </datalist></label>
        <label className="block"><span className="mb-1 block text-xs text-slate-400">Name</span>
          <input className={input} value={value.name}
            onChange={(e) => onChange({ ...value, name: e.target.value })} placeholder="e.g. SSH Brute Force response" /></label>
      </div>
      <label className="block"><span className="mb-1 block text-xs text-slate-400">Steps * <span className="text-slate-600">(one per line, in order - what the analyst should do)</span></span>
        <textarea className={input} rows={6} value={value.steps.join('\n')}
          onChange={(e) => onChange({ ...value, steps: e.target.value.split('\n') })}
          placeholder={'Approve the recommended IP ban on the Response page\nAudit the targeted account for successful logins\nVerify SSH hardening (key-only auth, rate limiting)'} /></label>
    </div>
  )
}

export default function Playbooks() {
  const [items, setItems] = useState<PlaybookInfo[]>([])
  const [error, setError] = useState('')
  const [add, setAdd] = useState<PlaybookSpec>(EMPTY)
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState<PlaybookInfo | null>(null)
  const [editSpec, setEditSpec] = useState<PlaybookSpec>(EMPTY)

  const load = () => fetchPlaybooks().then(setItems).catch((e) => setError((e as Error).message))
  useEffect(() => { load() }, [])

  const cleanedSteps = (sp: PlaybookSpec) => ({ ...sp, steps: sp.steps.map((s) => s.trim()).filter(Boolean) })

  const submitAdd = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true); setError('')
    try { await createPlaybook(cleanedSteps(add)); setAdd(EMPTY); await load() }
    catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }
  const toggle = async (p: PlaybookInfo) => {
    try { await updatePlaybook(p.id, specOf(p), !p.enabled); await load() }
    catch (err) { setError((err as Error).message) }
  }
  const saveEdit = async () => {
    if (!editing) return
    setBusy(true); setError('')
    try { await updatePlaybook(editing.id, cleanedSteps(editSpec), editing.enabled); setEditing(null); await load() }
    catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }
  const remove = async (p: PlaybookInfo) => {
    if (!confirm(`Delete playbook "${p.name}"? Alerts with label "${p.label}" will no longer carry a recommendation.`)) return
    try { await deletePlaybook(p.id); await load() }
    catch (err) { setError((err as Error).message) }
  }

  return (
    <div className="mx-auto max-w-5xl px-8 py-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-white">Playbooks</h1>
        <p className="mt-1 text-sm text-slate-500">
          Remediation playbooks: each detection label maps to the steps an analyst should take.
          The worker stamps the matching playbook onto every fired alert (visible on the alert's
          detail) - deterministic, instant, fully auditable. Changes apply live, no restart.
        </p>
      </header>

      <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Add playbook</h2>
        <form onSubmit={submitAdd}>
          <Form value={add} onChange={setAdd} />
          <div className="mt-4 flex justify-end">
            <button type="submit" disabled={busy || !add.label.trim() || add.steps.every((s) => !s.trim())}
              className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50">
              {busy ? 'Saving…' : 'Add playbook'}
            </button>
          </div>
        </form>
        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
      </section>

      <section>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Catalog ({items.length})</h2>
        {items.length === 0 ? (
          <p className="rounded-xl border border-dashed border-slate-800 px-4 py-8 text-center text-sm text-slate-600">
            No playbooks yet.
          </p>
        ) : (
          <div className="grid gap-3">
            {items.map((p) => (
              <div key={p.id} className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-indigo-500/15 px-2 py-0.5 font-mono text-xs text-indigo-300">{p.label}</span>
                  <span className="text-sm font-medium text-slate-200">{p.name}</span>
                  {p.builtin && <span className="rounded bg-slate-700/40 px-1.5 py-0.5 text-[10px] text-slate-400">builtin</span>}
                  <span className={`rounded px-1.5 py-0.5 text-xs ${p.enabled ? 'bg-emerald-500/15 text-emerald-300' : 'bg-slate-700/40 text-slate-400'}`}>
                    {p.enabled ? 'enabled' : 'disabled'}
                  </span>
                  <div className="ml-auto flex gap-2">
                    <button onClick={() => toggle(p)} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">{p.enabled ? 'Disable' : 'Enable'}</button>
                    <button onClick={() => { setEditing(p); setEditSpec(specOf(p)) }} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">Edit</button>
                    <button onClick={() => remove(p)} className="rounded-md border border-rose-900/60 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10">Delete</button>
                  </div>
                </div>
                <ol className="mt-3 list-decimal space-y-1 pl-5 text-sm text-slate-400">
                  {p.steps.map((s, i) => <li key={i}>{s}</li>)}
                </ol>
              </div>
            ))}
          </div>
        )}
      </section>

      {editing && (
        <div className="fixed inset-0 z-20 grid place-items-center bg-black/50 p-4" onClick={() => setEditing(null)}>
          <div className="w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="mb-4 text-sm font-semibold text-white">Edit playbook — <span className="text-indigo-300">{editing.label}</span></h3>
            <Form value={editSpec} onChange={setEditSpec} />
            <div className="mt-5 flex justify-end gap-3">
              <button onClick={() => setEditing(null)} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">Cancel</button>
              <button onClick={saveEdit} disabled={busy || !editSpec.label.trim() || editSpec.steps.every((s) => !s.trim())}
                className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50">
                {busy ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
