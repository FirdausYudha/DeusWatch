import { useState } from 'react'
import type { TimeRange } from '../lib/api'

// TimeRangePicker is the shared window selector for the performance charts (host Performance and the
// SNMP Network board). Presets go down to one minute; "Custom" reveals two datetime-local inputs.

export const RANGE_PRESETS: { minutes: number; label: string }[] = [
  { minutes: 1, label: '1m' },
  { minutes: 10, label: '10m' },
  { minutes: 30, label: '30m' },
  { minutes: 60, label: '1h' },
  { minutes: 360, label: '6h' },
  { minutes: 1440, label: '24h' },
  { minutes: 10080, label: '7d' },
]

// toLocalInput formats a Date for a datetime-local input (which wants local wall-clock, no zone).
function toLocalInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

export default function TimeRangePicker({ value, onChange }: { value: TimeRange; onChange: (r: TimeRange) => void }) {
  const isCustom = 'from' in value
  const [custom, setCustom] = useState(false)
  const showCustom = custom || isCustom

  // Seed the custom inputs from the current preset window so switching to Custom is not a blank slate.
  const now = new Date()
  const defFrom = isCustom ? new Date(value.from) : new Date(now.getTime() - 60 * 60 * 1000)
  const defTo = isCustom ? new Date(value.to) : now
  const [from, setFrom] = useState(toLocalInput(defFrom))
  const [to, setTo] = useState(toLocalInput(defTo))

  const applyCustom = (f: string, t: string) => {
    const fd = new Date(f), td = new Date(t)
    if (isNaN(+fd) || isNaN(+td) || td <= fd) return
    onChange({ from: fd.toISOString(), to: td.toISOString() })
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="inline-flex rounded-[8px] border border-border p-0.5 text-[13px]">
        {RANGE_PRESETS.map((r) => {
          const active = !showCustom && 'minutes' in value && value.minutes === r.minutes
          return (
            <button
              key={r.minutes}
              onClick={() => { setCustom(false); onChange({ minutes: r.minutes }) }}
              className={`rounded-md px-2.5 py-1 transition-colors ${active ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg'}`}
            >
              {r.label}
            </button>
          )
        })}
        <button
          onClick={() => { setCustom(true); applyCustom(from, to) }}
          className={`rounded-md px-2.5 py-1 transition-colors ${showCustom ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg'}`}
        >
          Custom
        </button>
      </div>
      {showCustom && (
        <div className="flex flex-wrap items-center gap-1.5 text-[12.5px] text-muted">
          <input
            type="datetime-local"
            value={from}
            onChange={(e) => { setFrom(e.target.value); applyCustom(e.target.value, to) }}
            className="rounded-[6px] border border-border bg-surface px-2 py-1 text-fg"
          />
          <span>to</span>
          <input
            type="datetime-local"
            value={to}
            onChange={(e) => { setTo(e.target.value); applyCustom(from, e.target.value) }}
            className="rounded-[6px] border border-border bg-surface px-2 py-1 text-fg"
          />
        </div>
      )}
    </div>
  )
}
