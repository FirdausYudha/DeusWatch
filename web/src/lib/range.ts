import { usePersistedState } from './usePersistedState'
import type { DashRange } from './api'

// The dashboard's time range lives here rather than inside the Dashboard page, because the picker
// is rendered by the Topbar (the prototype puts it in the header) while the data is fetched by the
// page. Two components reading the same persisted key would NOT stay in step — each
// usePersistedState call owns its own React state — so the range is owned once, here, and passed
// down to both.

export const RANGE_PRESETS: { label: string; hours: number }[] = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 24 * 7 },
  { label: '30d', hours: 24 * 30 },
]

/** localInput formats a Date for a datetime-local input (local time, minute precision). */
export function localInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

/**
 * resolveRange turns the picker state into a DashRange, or null when a custom range is incomplete
 * or invalid. Returning null (rather than silently falling back to a default) is deliberate: the
 * caller skips fetching, so a half-typed date can never be presented as though it were the range
 * the operator asked for.
 */
export function resolveRange(preset: number | 'custom', from: string, to: string): DashRange | null {
  if (preset !== 'custom') return { hours: preset }
  if (!from || !to) return null
  const f = new Date(from)
  const t = new Date(to)
  if (isNaN(+f) || isNaN(+t)) return null
  if (f >= t) return null // an inverted range would return nothing and look like "no data"
  return { from: f, to: t }
}

export type DashRangeState = {
  preset: number | 'custom'
  from: string
  to: string
  setPreset: (p: number | 'custom') => void
  setFrom: (v: string) => void
  setTo: (v: string) => void
  /** The resolved range to fetch, or null while a custom range is incomplete. */
  resolved: DashRange | null
  /** Human label for the current selection, for headers and exports. */
  label: string
}

/** useDashRange owns the dashboard time range. Call once, in App. */
export function useDashRange(): DashRangeState {
  // Persisted so leaving the page and coming back keeps the range you picked.
  const [preset, setPreset] = usePersistedState<number | 'custom'>('dash.preset', 24)
  const [from, setFrom] = usePersistedState('dash.from', '')
  const [to, setTo] = usePersistedState('dash.to', '')

  const resolved = resolveRange(preset, from, to)
  const label =
    preset === 'custom'
      ? from && to
        ? `${from.replace('T', ' ')} → ${to.replace('T', ' ')}`
        : 'Custom range'
      : (RANGE_PRESETS.find((r) => r.hours === preset)?.label ?? `${preset}h`)

  return { preset, from, to, setPreset, setFrom, setTo, resolved, label }
}
