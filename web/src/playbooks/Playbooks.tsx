import { useEffect, useState, type FormEvent } from 'react'
import {
  fetchPlaybooks, createPlaybook, updatePlaybook, deletePlaybook,
  type PlaybookInfo, type PlaybookSpec,
} from '../lib/api'

const EMPTY: PlaybookSpec = { label: '', name: '', steps: [] }
const input = 'w-full rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[12.5px] text-fg outline-none focus:border-accent'

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
        <label className="block"><span className="mb-1 block text-[11px] text-muted">Label * <span className="text-dim">(the alert's deuswatch.label this playbook applies to)</span></span>
          <input className={input} list="playbook-labels" value={value.label}
            onChange={(e) => onChange({ ...value, label: e.target.value })} placeholder="e.g. bruteforce" />
          <datalist id="playbook-labels">
            {KNOWN_LABELS.map((l) => <option key={l} value={l} />)}
          </datalist></label>
        <label className="block"><span className="mb-1 block text-[11px] text-muted">Name</span>
          <input className={input} value={value.name}
            onChange={(e) => onChange({ ...value, name: e.target.value })} placeholder="e.g. SSH Brute Force response" /></label>
      </div>
      <label className="block"><span className="mb-1 block text-[11px] text-muted">Steps * <span className="text-dim">(one per line, in order - what the analyst should do)</span></span>
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
    <div className="mx-auto max-w-[1400px] px-6 py-5">
      <header className="mb-6">
        <h1 className="text-[16px] font-semibold tracking-tight text-fg">Playbooks</h1>
        <p className="mt-0.5 text-[12px] text-muted">
          Remediation playbooks: each detection label maps to the steps an analyst should take.
          The worker stamps the matching playbook onto every fired alert (visible on the alert's
          detail) - deterministic, instant, fully auditable. Changes apply live, no restart.
        </p>
      </header>

      <section className="mb-8 rounded-[12px] border border-border bg-surface p-5">
        <h2 className="mb-4 text-[11px] font-semibold uppercase tracking-wider text-dim">Add playbook</h2>
        <form onSubmit={submitAdd}>
          <Form value={add} onChange={setAdd} />
          <div className="mt-4 flex justify-end">
            <button type="submit" disabled={busy || !add.label.trim() || add.steps.every((s) => !s.trim())}
              className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-50">
              {busy ? 'Savingâ€¦' : 'Add playbook'}
            </button>
          </div>
        </form>
        {error && <p className="mt-3 text-[12.5px] text-rose-400">{error}</p>}
      </section>

      <section>
        <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-dim">Catalog ({items.length})</h2>
        {items.length === 0 ? (
          <p className="rounded-[12px] border border-dashed border-border px-4 py-8 text-center text-[12.5px] text-dim">
            No playbooks yet.
          </p>
        ) : (
          <div className="grid gap-3">
            {items.map((p) => (
              <div key={p.id} className="rounded-[12px] border border-border bg-surface p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-accent-soft px-2 py-0.5 font-mono text-[11px] text-accent">{p.label}</span>
                  <span className="text-[12.5px] font-medium text-fg">{p.name}</span>
                  {p.builtin && <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">builtin</span>}
                  <span className={`rounded px-1.5 py-0.5 text-[11px] ${p.enabled ? 'bg-emerald-500/15 text-emerald-300' : 'bg-surface-2 text-muted'}`}>
                    {p.enabled ? 'enabled' : 'disabled'}
                  </span>
                  <div className="ml-auto flex gap-2">
                    <button onClick={() => toggle(p)} className="rounded-md border border-border px-2 py-1 text-[11px] text-fg hover:bg-surface-2">{p.enabled ? 'Disable' : 'Enable'}</button>
                    <button onClick={() => { setEditing(p); setEditSpec(specOf(p)) }} className="rounded-md border border-border px-2 py-1 text-[11px] text-fg hover:bg-surface-2">Edit</button>
                    <button onClick={() => remove(p)} className="rounded-md border border-rose-900/60 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/10">Delete</button>
                  </div>
                </div>
                <ol className="mt-3 list-decimal space-y-1 pl-5 text-[12.5px] text-muted">
                  {p.steps.map((s, i) => <li key={i}>{s}</li>)}
                </ol>
              </div>
            ))}
          </div>
        )}
      </section>

      {editing && (
        <div className="fixed inset-0 z-20 grid place-items-center bg-black/50 p-4" onClick={() => setEditing(null)}>
          <div className="w-full max-w-2xl rounded-[12px] border border-border bg-surface p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="mb-4 text-[12.5px] font-semibold text-fg">Edit playbook â€” <span className="text-accent">{editing.label}</span></h3>
            <Form value={editSpec} onChange={setEditSpec} />
            <div className="mt-5 flex justify-end gap-3">
              <button onClick={() => setEditing(null)} className="rounded-[8px] border border-border px-4 py-2 text-[12.5px] text-fg hover:bg-surface-2">Cancel</button>
              <button onClick={saveEdit} disabled={busy || !editSpec.label.trim() || editSpec.steps.every((s) => !s.trim())}
                className="rounded-[8px] bg-accent px-4 py-2 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-50">
                {busy ? 'Savingâ€¦' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
