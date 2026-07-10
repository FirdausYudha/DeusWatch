import { useEffect, useState, type FormEvent } from 'react'
import {
  fetchDecoders, createDecoder, updateDecoder, deleteDecoder,
  fetchDecoderSamples, testDecoder,
  type Decoder, type DecoderSpec,
} from '../lib/api'

const LEVELS = ['', 'info', 'low', 'medium', 'high', 'critical']
const EMPTY: DecoderSpec = { name: '', dataset: '', category: '', action: '', outcome: '', level: '', regex: '' }
const input = 'w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 outline-none focus:border-indigo-500'

function specOf(d: Decoder): DecoderSpec {
  return { name: d.name, dataset: d.dataset, category: d.category, action: d.action, outcome: d.outcome, level: d.level, regex: d.regex }
}

// Form is the shared add/edit field set.
function Form({ value, onChange }: { value: DecoderSpec; onChange: (v: DecoderSpec) => void }) {
  const set = (k: keyof DecoderSpec, v: string) => onChange({ ...value, [k]: v })
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <label className="block"><span className="mb-1 block text-xs text-slate-400">Name</span>
        <input className={input} value={value.name} onChange={(e) => set('name', e.target.value)} placeholder="e.g. haproxy-http" /></label>
      <label className="block"><span className="mb-1 block text-xs text-slate-400">Dataset *</span>
        <input className={input} value={value.dataset} onChange={(e) => set('dataset', e.target.value)} placeholder="agent source dataset, e.g. haproxy" /></label>
      <label className="block"><span className="mb-1 block text-xs text-slate-400">Category</span>
        <input className={input} value={value.category} onChange={(e) => set('category', e.target.value)} placeholder="event.category, e.g. web / mail / authentication" /></label>
      <div className="grid grid-cols-3 gap-2">
        <label className="block"><span className="mb-1 block text-xs text-slate-400">Action</span>
          <input className={input} value={value.action} onChange={(e) => set('action', e.target.value)} /></label>
        <label className="block"><span className="mb-1 block text-xs text-slate-400">Outcome</span>
          <input className={input} value={value.outcome} onChange={(e) => set('outcome', e.target.value)} placeholder="failure" /></label>
        <label className="block"><span className="mb-1 block text-xs text-slate-400">Level</span>
          <select className={input} value={value.level} onChange={(e) => set('level', e.target.value)}>
            {LEVELS.map((l) => <option key={l} value={l}>{l || '(default)'}</option>)}
          </select></label>
      </div>
      <label className="block sm:col-span-2"><span className="mb-1 block text-xs text-slate-400">Regex (Go RE2, named groups -&gt; fields) *</span>
        <textarea className={`${input} font-mono`} rows={2} value={value.regex} onChange={(e) => set('regex', e.target.value)}
          placeholder={`client=[^[]*\\[(?P<source_ip>\\d{1,3}(?:\\.\\d{1,3}){3})\\]`} /></label>
    </div>
  )
}

export default function Decoders() {
  const [items, setItems] = useState<Decoder[]>([])
  const [error, setError] = useState('')
  const [add, setAdd] = useState<DecoderSpec>(EMPTY)
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState<Decoder | null>(null)
  const [editSpec, setEditSpec] = useState<DecoderSpec>(EMPTY)
  // Tester: show real raw lines for a dataset + try the regex against one.
  const [samples, setSamples] = useState<string[]>([])
  const [testLine, setTestLine] = useState('')
  const [testResult, setTestResult] = useState<{ matched: boolean; fields: Record<string, string> } | null>(null)
  const [testMsg, setTestMsg] = useState('')

  const loadSamples = async () => {
    setTestMsg(''); setSamples([])
    if (!add.dataset) { setTestMsg('Enter a dataset first.'); return }
    try {
      const lines = await fetchDecoderSamples(add.dataset)
      setSamples(lines)
      if (lines.length === 0) setTestMsg(`No recent logs seen for dataset "${add.dataset}" yet.`)
    } catch (err) { setTestMsg((err as Error).message) }
  }
  const runTest = async (line: string) => {
    setTestMsg(''); setTestResult(null)
    if (!add.regex || !line) { setTestMsg('Need a regex and a line to test.'); return }
    try { setTestResult(await testDecoder(add, line)) }
    catch (err) { setTestMsg((err as Error).message) }
  }

  const load = () => fetchDecoders().then(setItems).catch((e) => setError((e as Error).message))
  useEffect(() => { load() }, [])

  const submitAdd = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true); setError('')
    try { await createDecoder(add); setAdd(EMPTY); await load() }
    catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }
  const toggle = async (d: Decoder) => {
    try { await updateDecoder(d.id, specOf(d), !d.enabled); await load() }
    catch (err) { setError((err as Error).message) }
  }
  const saveEdit = async () => {
    if (!editing) return
    setBusy(true); setError('')
    try { await updateDecoder(editing.id, editSpec, editing.enabled); setEditing(null); await load() }
    catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }
  const remove = async (d: Decoder) => {
    if (!confirm(`Delete decoder "${d.name}"?`)) return
    try { await deleteDecoder(d.id); await load() }
    catch (err) { setError((err as Error).message) }
  }

  return (
    <div className="mx-auto max-w-5xl px-8 py-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-white">Decoders</h1>
        <p className="mt-1 text-sm text-slate-500">
          Data-driven log parsing for sources without a built-in decoder. A regex extracts fields
          from a dataset's raw lines; the gateway live-reloads changes. Built-ins for sshd/web/fim/
          windows/suricata are always active.
        </p>
      </header>

      <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Add decoder</h2>
        <form onSubmit={submitAdd}>
          <Form value={add} onChange={setAdd} />
          <div className="mt-4 flex justify-end">
            <button type="submit" disabled={busy || !add.dataset || !add.regex}
              className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50">
              {busy ? 'Saving…' : 'Add decoder'}
            </button>
          </div>
        </form>
        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}

        {/* Tester: the answer to "how do I know my raw lines?" - pull real lines, try the regex. */}
        <div className="mt-5 border-t border-slate-800 pt-4">
          <div className="mb-2 flex items-center gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">Test against real log lines</h3>
            <button onClick={loadSamples} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">
              Load recent lines for "{add.dataset || '…'}"
            </button>
          </div>
          {samples.length > 0 && (
            <div className="mb-3 max-h-40 overflow-auto rounded-lg border border-slate-800 bg-slate-950/60 p-2">
              {samples.map((l, i) => (
                <button key={i} onClick={() => { setTestLine(l); runTest(l) }}
                  className="block w-full truncate px-2 py-1 text-left font-mono text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200" title={l}>
                  {l}
                </button>
              ))}
            </div>
          )}
          <div className="flex gap-2">
            <input className={`${input} font-mono`} value={testLine} onChange={(e) => setTestLine(e.target.value)} placeholder="paste one raw log line to test the regex against" />
            <button onClick={() => runTest(testLine)} className="shrink-0 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800">Test</button>
          </div>
          {testMsg && <p className="mt-2 text-xs text-amber-400">{testMsg}</p>}
          {testResult && (
            <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm">
              {testResult.matched ? (
                <>
                  <span className="text-emerald-400">✓ matched</span>
                  {Object.keys(testResult.fields).length > 0 ? (
                    <table className="mt-2 text-xs">
                      <tbody>
                        {Object.entries(testResult.fields).map(([k, v]) => (
                          <tr key={k}><td className="pr-3 font-mono text-slate-500">{k}</td><td className="font-mono text-slate-300">{v}</td></tr>
                        ))}
                      </tbody>
                    </table>
                  ) : <span className="ml-2 text-slate-500">(no named groups extracted; only category/defaults applied)</span>}
                </>
              ) : <span className="text-rose-400">✗ no match on this line</span>}
            </div>
          )}
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Configured ({items.length})</h2>
        {items.length === 0 ? (
          <p className="rounded-xl border border-dashed border-slate-800 px-4 py-8 text-center text-sm text-slate-600">
            No custom decoders yet.
          </p>
        ) : (
          <div className="overflow-hidden rounded-xl border border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-4 py-2">Name</th><th className="px-4 py-2">Dataset</th>
                  <th className="px-4 py-2">Category</th><th className="px-4 py-2">Regex</th>
                  <th className="px-4 py-2">Status</th><th className="px-4 py-2"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                {items.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-800/40">
                    <td className="px-4 py-2 text-slate-200">{d.name}{d.builtin && <span className="ml-1 rounded bg-slate-700/40 px-1.5 py-0.5 text-[10px] text-slate-400">builtin</span>}</td>
                    <td className="px-4 py-2 font-mono text-slate-300">{d.dataset}</td>
                    <td className="px-4 py-2 text-slate-400">{d.category || '—'}</td>
                    <td className="px-4 py-2 max-w-[16rem] truncate font-mono text-xs text-slate-500" title={d.regex}>{d.regex}</td>
                    <td className="px-4 py-2">
                      <span className={`rounded px-1.5 py-0.5 text-xs ${d.enabled ? 'bg-emerald-500/15 text-emerald-300' : 'bg-slate-700/40 text-slate-400'}`}>
                        {d.enabled ? 'enabled' : 'disabled'}
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex justify-end gap-2">
                        <button onClick={() => toggle(d)} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">{d.enabled ? 'Disable' : 'Enable'}</button>
                        <button onClick={() => { setEditing(d); setEditSpec(specOf(d)) }} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">Edit</button>
                        <button onClick={() => remove(d)} className="rounded-md border border-rose-900/60 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10">Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {editing && (
        <div className="fixed inset-0 z-20 grid place-items-center bg-black/50 p-4" onClick={() => setEditing(null)}>
          <div className="w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="mb-4 text-sm font-semibold text-white">Edit decoder — <span className="text-indigo-300">{editing.name}</span></h3>
            <Form value={editSpec} onChange={setEditSpec} />
            <div className="mt-5 flex justify-end gap-3">
              <button onClick={() => setEditing(null)} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">Cancel</button>
              <button onClick={saveEdit} disabled={busy || !editSpec.dataset || !editSpec.regex}
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
