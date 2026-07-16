import { useEffect, useMemo, useState } from 'react'
import {
  fetchIntegrationTypes,
  fetchIntegrations,
  createIntegration,
  updateIntegration,
  deleteIntegration,
  fetchIngestConfig,
  regenerateIngestToken,
  disableIngestWebhook,
  type IntegrationType,
  type Integration,
  type IntegrationField,
} from '../lib/api'
import DocLink from '../components/DocLink'

const CATEGORY: Record<string, string> = {
  firewall: 'Firewall',
  bouncer: 'Bouncer / IPS',
  cti: 'Threat Intel (CTI)',
  llm: 'LLM / AI',
  fim: 'File Integrity (FIM)',
  export: 'Export / Webhook',
  ingest: 'Log ingest',
}
const CATEGORY_BADGE: Record<string, string> = {
  firewall: 'text-orange-300 bg-orange-500/15',
  bouncer: 'text-violet-300 bg-violet-500/15',
  cti: 'text-emerald-300 bg-emerald-500/15',
  llm: 'text-sky-300 bg-sky-500/15',
  fim: 'text-rose-300 bg-rose-500/15',
  export: 'text-cyan-300 bg-cyan-500/15',
  ingest: 'text-teal-300 bg-teal-500/15',
}

// FieldInput renders one config field. For secret fields it shows a "configured"
// placeholder so the admin can leave it blank to keep the stored value.
function FieldInput({
  field,
  value,
  configured,
  onChange,
}: {
  field: IntegrationField
  value: string
  configured: boolean
  onChange: (v: string) => void
}) {
  const hasOptions = !!field.options && field.options.length > 0
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-slate-400">
        {field.label}
        {field.optional && <span className="ml-1 text-slate-600">(optional)</span>}
      </span>
      {hasOptions ? (
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
        >
          {!value && <option value="">Select…</option>}
          {field.options!.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      ) : (
        <input
          type={field.secret ? 'password' : 'text'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.secret && configured ? '•••••••• configured (leave blank to keep)' : field.help ?? ''}
          autoComplete="off"
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
        />
      )}
      {field.help && !(field.secret && configured) && (
        <span className="mt-1 block text-[11px] text-slate-600">{field.help}</span>
      )}
    </label>
  )
}

// IngestWebhookPanel manages the INBOUND raw-log ingest webhook token (POST /api/ingest/webhook).
// Unlike the outbound connectors above (which store encrypted credentials), this is an inbound
// endpoint a Wazuh manager / any external system pushes logs to, so it gets its own panel with a
// token that is generated, copied, regenerated, or disabled here. The page already requires
// manage_integrations, and the endpoints are protected the same way.
function IngestWebhookPanel() {
  const [token, setToken] = useState('')
  const [enabled, setEnabled] = useState(false)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    fetchIngestConfig().then((c) => { setToken(c.token); setEnabled(c.enabled) }).catch(() => {})
  }, [])

  const url = enabled ? `${window.location.origin}/api/ingest/webhook?token=${token}&agent=<name>&dataset=wazuh` : ''
  const regenerate = async () => {
    setBusy(true); setErr('')
    try { const c = await regenerateIngestToken(); setToken(c.token); setEnabled(true) }
    catch (e) { setErr((e as Error).message) }
    finally { setBusy(false) }
  }
  const disable = async () => {
    if (!confirm('Disable the ingest webhook? External systems pushing logs will get 404 until you re-enable it.')) return
    setBusy(true); setErr('')
    try { const c = await disableIngestWebhook(); setToken(c.token); setEnabled(c.enabled) }
    catch (e) { setErr((e as Error).message) }
    finally { setBusy(false) }
  }
  const copy = async () => {
    try { await navigator.clipboard.writeText(url); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* ignore */ }
  }

  return (
    <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold text-white">Log ingest webhook (Wazuh & others)</h2>
        <span className="rounded px-1.5 py-0.5 text-[10px] font-medium text-cyan-300 bg-cyan-500/15">Inbound</span>
        <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${enabled ? 'text-emerald-300 bg-emerald-500/15' : 'text-slate-400 bg-slate-700/40'}`}>
          {enabled ? 'Active' : 'Disabled'}
        </span>
        <DocLink file="wazuh-webhook.md" className="ml-auto shrink-0" />
      </div>
      <p className="mb-3 mt-1 text-sm text-slate-500">
        A token-gated endpoint that external systems POST raw logs or Wazuh alerts to — they flow
        through the normal pipeline (normalize → detect → playbooks → response). Point a Wazuh
        manager's integrator at this URL, or <span className="font-mono text-[11px]">curl</span> lines to it.
      </p>
      {enabled ? (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <input readOnly value={url} onFocus={(e) => e.currentTarget.select()}
              className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-300 outline-none" />
            <button onClick={copy} className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800">{copied ? 'Copied ✓' : 'Copy'}</button>
            <button onClick={regenerate} disabled={busy}
              className="rounded-lg border border-amber-700/60 px-3 py-2 text-sm text-amber-300 hover:bg-amber-500/10 disabled:opacity-50">
              {busy ? 'Regenerating…' : 'Regenerate'}
            </button>
            <button onClick={disable} disabled={busy}
              className="rounded-lg border border-rose-900/60 px-3 py-2 text-sm text-rose-300 hover:bg-rose-500/10 disabled:opacity-50">
              Disable
            </button>
          </div>
          <p className="mt-2 text-xs text-slate-600">
            Replace <span className="font-mono">&lt;name&gt;</span> with the source agent name (shown in the Agent column) and
            <span className="font-mono"> dataset</span> with the log type (<span className="font-mono">wazuh</span>, <span className="font-mono">web</span>, …).
            The token is in the URL — serve it over HTTPS / a trusted tunnel. Regenerating invalidates the old token.
          </p>
        </>
      ) : (
        <button onClick={regenerate} disabled={busy}
          className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50">
          {busy ? 'Generating…' : 'Enable webhook (generate token)'}
        </button>
      )}
      {err && <p className="mt-2 text-sm text-rose-400">{err}</p>}
    </section>
  )
}

export default function Integrations() {
  const [types, setTypes] = useState<IntegrationType[]>([])
  const [items, setItems] = useState<Integration[]>([])
  const [error, setError] = useState('')

  // Add form.
  const [pick, setPick] = useState<string>('')
  const [name, setName] = useState('')
  const [config, setConfig] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)

  // Edit modal.
  const [editing, setEditing] = useState<Integration | null>(null)
  const [editName, setEditName] = useState('')
  const [editEnabled, setEditEnabled] = useState(true)
  const [editConfig, setEditConfig] = useState<Record<string, string>>({})
  const [editBusy, setEditBusy] = useState(false)

  const typeMap = useMemo(() => {
    const m: Record<string, IntegrationType> = {}
    for (const t of types) m[t.type] = t
    return m
  }, [types])

  const load = () => {
    fetchIntegrations()
      .then(setItems)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(() => {
    fetchIntegrationTypes()
      .then(setTypes)
      .catch((e) => setError((e as Error).message))
    load()
  }, [])

  const picked = pick ? typeMap[pick] : null

  const resetAdd = () => {
    setPick('')
    setName('')
    setConfig({})
  }

  const submitAdd = async () => {
    if (!picked) return
    setBusy(true)
    setError('')
    try {
      await createIntegration(picked.type, name, config)
      resetAdd()
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const startEdit = (it: Integration) => {
    setEditing(it)
    setEditName(it.name)
    setEditEnabled(it.enabled)
    setEditConfig({ ...it.config })
    setError('')
  }
  const saveEdit = async () => {
    if (!editing) return
    setEditBusy(true)
    setError('')
    try {
      await updateIntegration(editing.id, editName, editEnabled, editConfig)
      setEditing(null)
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setEditBusy(false)
    }
  }

  const toggleEnabled = async (it: Integration) => {
    try {
      // Send the (masked) config back: non-secret fields are preserved, and blank
      // secret fields are kept by the backend.
      await updateIntegration(it.id, it.name, !it.enabled, it.config)
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const remove = async (it: Integration) => {
    if (!confirm(`Delete integration "${it.name}"?`)) return
    try {
      await deleteIntegration(it.id)
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const editType = editing ? typeMap[editing.type] : null

  return (
    <div className="mx-auto max-w-5xl px-8 py-8">
      <header className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight text-white">Integrations</h1>
        <p className="mt-1 text-sm text-slate-500">
          Connect firewalls, bouncers, and threat-intel providers. API keys & credentials are encrypted at rest.
        </p>
      </header>

      {/* Add integration */}
      <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Add integration</h2>
        <div className="flex flex-wrap gap-2">
          {types.map((t) => (
            <button
              key={t.type}
              onClick={() => {
                setPick(t.type)
                setName('')
                setConfig({})
              }}
              className={`rounded-lg border px-3 py-2 text-left text-sm transition-colors ${
                pick === t.type
                  ? 'border-indigo-500 bg-indigo-500/10 text-indigo-200'
                  : 'border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              <span className={`mr-2 rounded px-1.5 py-0.5 text-[10px] font-medium ${CATEGORY_BADGE[t.category]}`}>
                {CATEGORY[t.category] ?? t.category}
              </span>
              {t.label}
            </button>
          ))}
        </div>

        {picked && (
          <div className="mt-5 rounded-lg border border-slate-800 bg-slate-900 p-4">
            <div className="mb-3 flex items-start justify-between gap-3">
              <p className="text-sm text-slate-400">{picked.desc}</p>
              {picked.doc && <DocLink file={picked.doc} className="shrink-0" />}
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-slate-400">Name</span>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={`e.g. ${picked.label}`}
                  className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
                />
              </label>
              {picked.fields.map((f) => (
                <FieldInput
                  key={f.key}
                  field={f}
                  configured={false}
                  value={config[f.key] ?? ''}
                  onChange={(v) => setConfig((c) => ({ ...c, [f.key]: v }))}
                />
              ))}
            </div>
            <div className="mt-4 flex justify-end gap-3">
              <button
                onClick={resetAdd}
                className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition-colors hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={submitAdd}
                disabled={busy || !name}
                className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400 disabled:opacity-50"
              >
                {busy ? 'Saving…' : 'Add integration'}
              </button>
            </div>
          </div>
        )}
        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
      </section>

      {/* Inbound ingest webhook (Wazuh & others) */}
      <IngestWebhookPanel />

      {/* Existing integrations */}
      <section>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
          Configured ({items.length})
        </h2>
        {items.length === 0 ? (
          <p className="rounded-xl border border-dashed border-slate-800 px-4 py-8 text-center text-sm text-slate-600">
            No integrations yet. Pick one above to get started.
          </p>
        ) : (
          <div className="space-y-2">
            {items.map((it) => {
              const t = typeMap[it.type]
              return (
                <div
                  key={it.id}
                  className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-slate-200">{it.name}</span>
                      {t && (
                        <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${CATEGORY_BADGE[t.category]}`}>
                          {CATEGORY[t.category] ?? t.category}
                        </span>
                      )}
                      {!it.enabled && (
                        <span className="rounded bg-slate-700/40 px-1.5 py-0.5 text-[10px] text-slate-400">disabled</span>
                      )}
                    </div>
                    <div className="mt-0.5 truncate text-xs text-slate-500">{t?.label ?? it.type}</div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <button
                      onClick={() => toggleEnabled(it)}
                      className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800"
                    >
                      {it.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                      onClick={() => startEdit(it)}
                      className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => remove(it)}
                      className="rounded-md border border-rose-900/60 px-2 py-1 text-xs text-rose-300 transition-colors hover:bg-rose-500/10"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </section>

      {/* Edit modal */}
      {editing && editType && (
        <div className="fixed inset-0 z-20 grid place-items-center bg-black/50 p-4" onClick={() => setEditing(null)}>
          <div
            className="w-full max-w-xl rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-white">
                Edit — <span className="text-indigo-300">{editing.name}</span>
                <span className="ml-2 text-xs font-normal text-slate-500">{editType.label}</span>
              </h3>
              {editType.doc && <DocLink file={editType.doc} className="shrink-0" />}
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-slate-400">Name</span>
                <input
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm outline-none focus:border-indigo-500"
                />
              </label>
              {editType.fields.map((f) => (
                <FieldInput
                  key={f.key}
                  field={f}
                  configured={!!editing.secrets_set?.[f.key]}
                  value={editConfig[f.key] ?? ''}
                  onChange={(v) => setEditConfig((c) => ({ ...c, [f.key]: v }))}
                />
              ))}
            </div>
            <label className="mt-4 flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                checked={editEnabled}
                onChange={(e) => setEditEnabled(e.target.checked)}
                className="h-4 w-4 rounded border-slate-600 bg-slate-800 accent-indigo-500"
              />
              Enabled
            </label>
            <div className="mt-5 flex justify-end gap-3">
              <button
                onClick={() => setEditing(null)}
                className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition-colors hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={saveEdit}
                disabled={editBusy}
                className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400 disabled:opacity-50"
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
