import { useState, useEffect } from 'react'
import {
  fetchSCAPolicies,
  uploadSCAPolicy,
  setSCAPolicyEnabled,
  deleteSCAPolicy,
  type SCAPolicyRow,
} from '../lib/api'

// PolicyManager is the central half of benchmarks: upload a policy once, every agent fetches it.
//
// Validation happens on the server at upload, so a malformed policy is rejected here by one
// person who can fix it rather than by five hundred agents that each log a parse error nobody
// reads.
export default function PolicyManager({
  onClose,
  canManage,
}: {
  onClose: () => void
  canManage: boolean
}) {
  const [rows, setRows] = useState<SCAPolicyRow[]>([])
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  // The YAML held back while we ask whether to replace an existing policy, with its signature, so
  // confirming does not lose the one the operator chose.
  const [pending, setPending] = useState<{ yaml: string; sig: string } | null>(null)
  const [sig, setSig] = useState('')

  const load = () =>
    fetchSCAPolicies()
      .then(setRows)
      .catch((e) => setError((e as Error).message))

  useEffect(() => {
    void load()
  }, [])

  const upload = async (yaml: string, replace: boolean, signature: string) => {
    setBusy(true)
    setError('')
    setNote('')
    try {
      const r = await uploadSCAPolicy(yaml, replace, signature)
      setNote(
        `${r.policy_id} stored, ${r.checks} checks, ${r.signed ? 'signed' : 'UNSIGNED'}. ` +
          `Agents pick it up on their next assessment.`,
      )
      setPending(null)
      setSig('')
      await load()
    } catch (e) {
      if ((e as Error).message === 'EXISTS') {
        // Not a failure: ask first, because replacing it changes what the whole estate is
        // measured against.
        setPending({ yaml, sig: signature })
      } else {
        setError((e as Error).message)
      }
    } finally {
      setBusy(false)
    }
  }

  const onFile = async (f: File | undefined) => {
    if (!f) return
    void upload(await f.text(), false, sig)
  }

  // A .sig file is read into the signature box rather than uploaded on its own, so the operator
  // can see what is about to be attached and the two never get paired up wrongly.
  const onSigFile = async (f: File | undefined) => {
    if (!f) return
    setSig((await f.text()).trim())
  }

  const toggle = async (p: SCAPolicyRow) => {
    setError('')
    try {
      await setSCAPolicyEnabled(p.id, !p.enabled)
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const remove = async (p: SCAPolicyRow) => {
    const msg = `Delete "${p.policy_id}"? Its stored results go with it, so the score disappears from this page.`
    if (!confirm(msg)) return
    setError('')
    try {
      await deleteSCAPolicy(p.id)
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-[12px] border border-border bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-[16px] font-semibold text-fg">Benchmark policies</h2>
        <p className="mb-4 text-[12.5px] text-dim">
          Upload a CIS policy once and every agent with an <code className="text-fg">sca</code> source
          fetches it. These are Wazuh SCA policy files, used as they are. A policy placed directly on
          an endpoint still overrides the one served here.
        </p>

        {error && <p className="mb-3 text-[13.5px] text-rose-400">{error}</p>}
        {note && <p className="mb-3 text-[13.5px] text-emerald-300">{note}</p>}

        {pending && (
          <div className="mb-3 rounded-[8px] border border-amber-400/40 bg-amber-400/10 px-3 py-2">
            <p className="text-[13.5px] text-amber-200">
              A policy with that id is already uploaded. Replacing it changes what every agent is
              measured against.
            </p>
            <div className="mt-2 flex gap-2">
              <button
                onClick={() => void upload(pending.yaml, true, pending.sig)}
                disabled={busy}
                className="rounded-md border border-amber-400/50 px-2 py-1 text-[12.5px] text-amber-200 hover:bg-amber-400/20 disabled:opacity-50"
              >
                Replace it
              </button>
              <button
                onClick={() => setPending(null)}
                className="rounded-md border border-border px-2 py-1 text-[12.5px] text-muted hover:bg-surface-2"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        <div className="space-y-2">
          {rows.length === 0 && (
            <p className="rounded-[8px] border border-dashed border-border px-3 py-4 text-center text-[12.5px] text-dim">
              No policies uploaded. Take one from a Wazuh agent&apos;s{' '}
              <code className="text-fg">/var/ossec/ruleset/sca/</code> directory and upload it below.
            </p>
          )}
          {rows.map((p) => (
            <div
              key={p.id}
              className="flex items-center gap-3 rounded-[8px] border border-border bg-surface-2 px-3 py-2"
            >
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13.5px] text-fg">{p.name || p.policy_id}</div>
                <div className="truncate text-[12.5px] text-dim">
                  {p.policy_id} · {p.check_count} checks · rev {p.rev}
                  {p.uploaded_by && ` · ${p.uploaded_by}`}
                </div>
              </div>
              {!p.enabled && (
                <span className="shrink-0 rounded bg-surface px-1.5 py-0.5 text-[11px] text-dim">off</span>
              )}
              {/* An endpoint holding a trusted release key runs only the signed policies, so this
                  is the answer to "why did that host report no score for this benchmark". */}
              {p.signed ? (
                <span
                  className="shrink-0 rounded bg-emerald-400/15 px-1.5 py-0.5 text-[11px] text-emerald-300"
                  title="Signed. Endpoints that require signed policies will run this one."
                >
                  signed
                </span>
              ) : (
                <span
                  className="shrink-0 rounded bg-amber-400/15 px-1.5 py-0.5 text-[11px] text-amber-300"
                  title="Unsigned. Endpoints that hold a trusted release key will refuse to run this one."
                >
                  unsigned
                </span>
              )}
              {canManage && (
                <>
                  <button
                    onClick={() => void toggle(p)}
                    className="shrink-0 rounded-md border border-border px-2 py-1 text-[12.5px] text-fg hover:bg-surface"
                  >
                    {p.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    onClick={() => void remove(p)}
                    className="shrink-0 rounded-md border border-rose-500/40 px-2 py-1 text-[12.5px] text-rose-300 hover:bg-rose-500/10"
                  >
                    Delete
                  </button>
                </>
              )}
            </div>
          ))}
        </div>

        {canManage && (
          <div className="mt-4 space-y-3 border-t border-border pt-4">
            {/* The signature goes first, because it has to be in the box before the policy file
                triggers the upload. Reversing these would silently store the policy unsigned. */}
            <label className="block text-[12.5px] font-medium text-muted">
              Signature <span className="text-dim">(optional, from: dwsign -key update.key -in policy.yml)</span>
              <div className="mt-1 flex gap-2">
                <input
                  value={sig}
                  onChange={(e) => setSig(e.target.value)}
                  placeholder="base64, or load the .sig file"
                  className="min-w-0 flex-1 rounded-[8px] border border-border bg-surface-2 px-3 py-2 font-mono text-[12.5px] outline-none focus:border-accent"
                />
                <input
                  type="file"
                  accept=".sig,.txt"
                  onChange={(e) => void onSigFile(e.target.files?.[0])}
                  className="w-40 shrink-0 rounded-[8px] border border-border bg-surface-2 px-2 py-2 text-[12.5px] text-fg file:mr-2 file:rounded file:border-0 file:bg-surface file:px-2 file:py-1 file:text-fg"
                />
              </div>
            </label>
            <label className="block text-[12.5px] font-medium text-muted">
              Upload a policy (.yml)
              <input
                type="file"
                accept=".yml,.yaml"
                disabled={busy}
                onChange={(e) => void onFile(e.target.files?.[0])}
                className="mt-1 block w-full rounded-[8px] border border-border bg-surface-2 px-3 py-2 text-[13.5px] text-fg file:mr-3 file:rounded file:border-0 file:bg-surface file:px-2 file:py-1 file:text-fg"
              />
            </label>
            <p className="text-[12.5px] text-dim">
              Rejected with a reason if it is not a valid SCA policy, so a broken file never reaches
              an endpoint. The signature is stored as given and checked only on the endpoint: this
              manager does not hold the key, which is what stops it forging one.
            </p>
          </div>
        )}

        <div className="mt-5 flex justify-end">
          <button
            onClick={onClose}
            className="rounded-[8px] border border-border px-4 py-2 text-[13.5px] text-fg hover:bg-surface-2"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
