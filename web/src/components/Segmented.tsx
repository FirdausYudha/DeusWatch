// Segmented is the shared pill track behind every time-range picker. The dashboard picker
// (hours, DashRangeState) and the performance/network picker (minutes, TimeRange) bind to
// different state models, so they stay as thin wrappers, but they render their presets through
// this one component so the look (track, active pill, hover) can never drift apart again.
import type { ReactNode } from 'react'

export type SegOption = { key: string; label: string }

// segPillClass is exported so a wrapper can style a button that lives in the track but is not a
// plain preset (e.g. the "Custom" toggle) and still match exactly.
export function segPillClass(active: boolean): string {
  return `rounded-[6px] px-2.5 py-1 text-[12.5px] font-medium transition-colors ${
    active ? 'bg-accent text-white shadow-sm' : 'text-muted hover:text-fg'
  }`
}

export default function Segmented({
  options,
  activeKey,
  onSelect,
  trailing,
}: {
  options: SegOption[]
  activeKey: string | null
  onSelect: (key: string) => void
  /** Rendered inside the same track after the presets (e.g. a Custom button). */
  trailing?: ReactNode
}) {
  return (
    <div className="flex items-center gap-0.5 rounded-[8px] border border-border bg-surface-2 p-[3px]">
      {options.map((o) => (
        <button
          key={o.key}
          onClick={() => onSelect(o.key)}
          aria-pressed={activeKey === o.key}
          className={segPillClass(activeKey === o.key)}
        >
          {o.label}
        </button>
      ))}
      {trailing}
    </div>
  )
}
