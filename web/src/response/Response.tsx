import { useEffect, useState } from 'react'
import {
  fetchResponses,
  approveResponse,
  dismissResponse,
  type ResponseAction,
  type ResponseStatus,
  type Me,
} from '../lib/api'

const STATUS_BADGE: Record<ResponseStatus, string> = {
  recommended: 'text-amber-300 bg-amber-500/15',
  approved: 'text-sky-300 bg-sky-500/15',
  executed: 'text-emerald-300 bg-emerald-500/15',
  dismissed: 'text-slate-400 bg-slate-700/40',
  failed: 'text-rose-300 bg-rose-500/15',
}

const FILTERS: { label: string; value: string }[] = [
  { label: 'Semua', value: '' },
  { label: 'Direkomendasikan', value: 'recommended' },
  { label: 'Dieksekusi', value: 'executed' },
  { label: 'Ditolak', value: 'dismissed' },
  { label: 'Gagal', value: 'failed' },
]

function banLabel(seconds: number): string {
  if (seconds <= 0) return 'permanen'
  if (seconds % 86400 === 0) return `${seconds / 86400}h`
  if (seconds % 3600 === 0) return `${seconds / 3600}j`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}d`
}

export default function Response({ me }: { me: Me }) {
  const canApprove = me.role === 'analyst' || me.role === 'admin'
  const [actions, setActions] = useState<ResponseAction[]>([])
  const [filter, setFilter] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  const load = () => {
    fetchResponses(filter)
      .then(setActions)
      .catch((e) => setError((e as Error).message))
  }
  useEffect(() => {
    load()
    const t = setInterval(load, 10_000)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter])

  const act = async (a: ResponseAction, kind: 'approve' | 'dismiss') => {
    if (kind === 'approve' && !confirm(`Setujui blokir ${a.source_ip} (${banLabel(a.ban_seconds)})?`)) return
    setBusy(a.id)
    setError('')
    try {
      if (kind === 'approve') await approveResponse(a.id)
      else await dismissResponse(a.id)
      load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  const pending = actions.filter((a) => a.status === 'recommended').length

  return (
    <div className="mx-auto max-w-5xl px-8 py-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-white">Response</h1>
        <p className="mt-1 text-sm text-slate-500">
          Rekomendasi blokir &amp; approval · ban progresif
          {pending > 0 && <span className="ml-2 text-amber-300">{pending} menunggu persetujuan</span>}
        </p>
      </header>

      <div className="mb-4 flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setFilter(f.value)}
            className={`rounded-lg px-3 py-1.5 text-sm transition-colors ${
              filter === f.value
                ? 'bg-indigo-500/10 font-medium text-indigo-300'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {error && <p className="mb-4 text-sm text-rose-400">{error}</p>}

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2 font-medium">Waktu</th>
              <th className="px-4 py-2 font-medium">Source IP</th>
              <th className="px-4 py-2 font-medium">Alasan</th>
              <th className="px-4 py-2 font-medium">Ban</th>
              <th className="px-4 py-2 font-medium">Pelanggaran</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Aksi</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {actions.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                  Belum ada aksi respons. Alert dengan source IP akan memunculkan rekomendasi blokir.
                </td>
              </tr>
            )}
            {actions.map((a) => (
              <tr key={a.id} className="hover:bg-slate-800/40">
                <td className="px-4 py-2 text-slate-400">{new Date(a.created_at).toLocaleString('id-ID')}</td>
                <td className="px-4 py-2 font-mono text-slate-300">{a.source_ip}</td>
                <td className="px-4 py-2 text-slate-300">{a.reason || a.rule_id || '—'}</td>
                <td className="px-4 py-2 text-slate-400">{banLabel(a.ban_seconds)}</td>
                <td className="px-4 py-2 text-slate-400">#{a.offense_count}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${STATUS_BADGE[a.status]}`}>{a.status}</span>
                  {a.responder && <span className="ml-1 text-xs text-slate-600">{a.responder}</span>}
                  {a.status === 'failed' && a.error && (
                    <div className="mt-0.5 text-xs text-rose-400" title={a.error}>{a.error.slice(0, 40)}…</div>
                  )}
                </td>
                <td className="px-4 py-2">
                  {a.status === 'recommended' && canApprove ? (
                    <div className="flex gap-2">
                      <button
                        onClick={() => act(a, 'approve')}
                        disabled={busy === a.id}
                        className="rounded-md border border-emerald-500/40 px-2 py-1 text-xs text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50"
                      >
                        Setujui
                      </button>
                      <button
                        onClick={() => act(a, 'dismiss')}
                        disabled={busy === a.id}
                        className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
                      >
                        Tolak
                      </button>
                    </div>
                  ) : (
                    <span className="text-xs text-slate-600">{a.decided_by ? `oleh ${a.decided_by}` : '—'}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!canApprove && (
        <p className="mt-3 text-xs text-slate-600">Peran kamu hanya dapat melihat; approve/tolak butuh analyst atau admin.</p>
      )}
    </div>
  )
}
