import { useEffect, useRef, useState } from 'react'
import { RANGE_PRESETS, localInput, type DashRangeState } from '../lib/range'

// RangePicker is the prototype's segmented time-range control: one track (surface-2, 8px radius,
// 3px padding) holding the presets, with the active one lifted onto the accent.
//
// "Custom" opens a popover rather than expanding inline. Inline inputs would push the topbar past
// its fixed 60px and shift the whole page every time someone opened them.

export default function RangePicker({ range }: { range: DashRangeState }) {
  const [openCustom, setOpenCustom] = useState(false)
  const wrap = useRef<HTMLDivElement>(null)

  // Dismiss the popover on outside click or Escape — a picker that traps you is worse than none.
  useEffect(() => {
    if (!openCustom) return
    const onDown = (e: MouseEvent) => {
      if (wrap.current && !wrap.current.contains(e.target as Node)) setOpenCustom(false)
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpenCustom(false)
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [openCustom])

  const startCustom = () => {
    // Seed a sensible window so the popover is never blank on first open.
    if (!range.to) range.setTo(localInput(new Date()))
    if (!range.from) range.setFrom(localInput(new Date(Date.now() - 24 * 3600 * 1000)))
    range.setPreset('custom')
    setOpenCustom(true)
  }

  const item = (active: boolean) =>
    `rounded-[6px] px-2.5 py-1 text-[11.5px] font-medium transition-colors ${
      active ? 'bg-accent text-white shadow-sm' : 'text-muted hover:text-fg'
    }`

  // A custom range that hasn't been completed yet fetches nothing, so say so rather than leaving
  // the dashboard looking empty for no visible reason.
  const incomplete = range.preset === 'custom' && !range.resolved

  return (
    <div ref={wrap} className="relative flex items-center gap-2">
      <div className="flex items-center gap-0.5 rounded-[8px] border border-border bg-surface-2 p-[3px]">
        {RANGE_PRESETS.map((r) => (
          <button
            key={r.label}
            onClick={() => {
              range.setPreset(r.hours)
              setOpenCustom(false)
            }}
            className={item(range.preset === r.hours)}
            aria-pressed={range.preset === r.hours}
          >
            {r.label}
          </button>
        ))}
        <button
          onClick={openCustom ? () => setOpenCustom(false) : startCustom}
          className={item(range.preset === 'custom')}
          aria-pressed={range.preset === 'custom'}
          aria-expanded={openCustom}
          title={range.preset === 'custom' ? range.label : 'Pick a custom range'}
        >
          Custom
        </button>
      </div>

      {incomplete && !openCustom && (
        <span className="hidden text-[11px] text-amber-300 sm:inline">range incomplete</span>
      )}

      {openCustom && (
        <div className="absolute right-0 top-[calc(100%+8px)] z-30 w-[260px] rounded-[10px] border border-border bg-surface p-3 shadow-xl">
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.4px] text-dim">
            Custom range
          </div>
          <label className="mb-1 block text-[11px] text-muted">From</label>
          <input
            type="datetime-local"
            value={range.from}
            max={range.to || undefined}
            onChange={(e) => range.setFrom(e.target.value)}
            className="mb-2 w-full rounded-[6px] border border-border bg-surface-2 px-2 py-1 text-[11.5px] text-fg outline-none focus:border-accent"
          />
          <label className="mb-1 block text-[11px] text-muted">To</label>
          <input
            type="datetime-local"
            value={range.to}
            min={range.from || undefined}
            onChange={(e) => range.setTo(e.target.value)}
            className="w-full rounded-[6px] border border-border bg-surface-2 px-2 py-1 text-[11.5px] text-fg outline-none focus:border-accent"
          />
          {!range.resolved && (
            <p className="mt-2 text-[11px] text-amber-300">
              {range.from && range.to
                ? 'The start must come before the end.'
                : 'Pick both a start and an end to load data.'}
            </p>
          )}
          <button
            onClick={() => setOpenCustom(false)}
            disabled={!range.resolved}
            className="mt-3 w-full rounded-[6px] bg-accent px-2 py-1.5 text-[11.5px] font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-40"
          >
            Apply
          </button>
        </div>
      )}
    </div>
  )
}
