// Shared UI primitives for the DeusWatch redesign. Every page composes these instead of
// re-inventing card/badge/button chrome, so the look stays consistent and a token change
// (index.css) propagates everywhere. Semantics come first: a colour always means the same thing.
import { forwardRef, useEffect, useState, type ReactNode } from 'react'

// ── Page shell ──────────────────────────────────────────────────────────────
// One max width + gutter for every screen, so left/right spacing is identical page to page
// (the redesign brief's "space kanan-kiri tidak seragam"). Every page wraps its content in this
// instead of its own mx-auto/max-w/px combo.
// The gutter grows with the viewport (24 → 32 → 40px) instead of staying at a flat 24px, which
// read as cramped once the content filled the width. It stays a single definition on purpose: the
// uneven left/right spacing this replaced came from pages setting their own padding.
export function Page({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`mx-auto max-w-[1400px] px-6 py-6 sm:px-8 lg:px-10 ${className}`}>{children}</div>
}

// ── Pagination ──────────────────────────────────────────────────────────────
// usePaged slices an already-fetched list client-side, so long tables stop lagging / needing
// endless scroll with zero backend work. (Server-side paging only where a dataset is truly
// unbounded, e.g. raw events.)
export function usePaged<T>(rows: T[], perPage = 25) {
  const [page, setPage] = useState(1)
  const pages = Math.max(1, Math.ceil(rows.length / perPage))
  const cur = Math.min(page, pages)
  useEffect(() => { if (page !== cur) setPage(cur) }, [cur, page])
  return { slice: rows.slice((cur - 1) * perPage, cur * perPage), page: cur, pages, total: rows.length, perPage, setPage }
}

// Pagination is the shared control every table uses; hidden when everything fits one page.
export function Pagination({ page, pages, total, perPage, onPage }: {
  page: number; pages: number; total: number; perPage: number; onPage: (p: number) => void
}) {
  if (total <= perPage) return null
  const from = (page - 1) * perPage + 1
  const to = Math.min(page * perPage, total)
  const btn = 'rounded-[8px] border border-border px-2.5 py-1 text-fg hover:bg-surface-2 disabled:opacity-40 disabled:hover:bg-transparent'
  return (
    <div className="flex items-center justify-between gap-3 pt-3 text-[13px] text-muted">
      <span>{from}-{to} of {total}</span>
      <div className="flex items-center gap-1.5">
        <button className={btn} disabled={page <= 1} onClick={() => onPage(page - 1)}>Prev</button>
        <span className="px-1">{page} / {pages}</span>
        <button className={btn} disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  )
}

// ── Sorting ───────────────────────────────────────────────────────────────────
// useSort + SortHeader give every table the same click-to-sort behaviour from one place, so a
// table that wants sorting stops hand-rolling it (the old tables each did, differently, or not at
// all). Sorting is client-side on an already-fetched list, same contract as usePaged.
export type SortDir = 'asc' | 'desc'

export function useSort<K extends string>(initialKey: K, initialDir: SortDir = 'asc') {
  const [key, setKey] = useState<K>(initialKey)
  const [dir, setDir] = useState<SortDir>(initialDir)
  // Clicking the active column flips direction; a new column starts ascending.
  const onSort = (k: K) => {
    if (k === key) setDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else { setKey(k); setDir('asc') }
  }
  // sortRows returns a sorted COPY using the accessor for the current key. Nulls always sort last,
  // regardless of direction, so "no reading" never crowds the top.
  function sortRows<T>(rows: T[], accessors: Partial<Record<K, (r: T) => string | number | null | undefined>>): T[] {
    const get = accessors[key]
    if (!get) return rows
    const sign = dir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      const av = get(a), bv = get(b)
      const an = av == null || av === '', bn = bv == null || bv === ''
      if (an && bn) return 0
      if (an) return 1
      if (bn) return -1
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * sign
      return String(av).localeCompare(String(bv), undefined, { numeric: true }) * sign
    })
  }
  return { key, dir, onSort, sortRows }
}

// SortHeader is a <th> whose label toggles the sort; the arrow shows the active column/direction.
export function SortHeader({
  label, active, dir, onClick, className = '',
}: {
  label: string; active: boolean; dir: SortDir; onClick: () => void; className?: string
}) {
  return (
    <th className={className}>
      <button
        onClick={onClick}
        aria-sort={active ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}
        className="inline-flex items-center gap-1 font-medium uppercase tracking-wider transition-colors hover:text-fg"
      >
        <span>{label}</span>
        <Icon name={active && dir === 'desc' ? 'down' : 'up'} size={12} className={active ? 'text-fg' : 'opacity-30'} />
      </button>
    </th>
  )
}

// ── CSV export ──────────────────────────────────────────────────────────────
// exportCSV turns rows already on screen into a downloaded file, so "send this to someone" stops
// meaning a screenshot. Leads with a UTF-8 BOM so Excel reads accented text correctly.
export function exportCSV(filename: string, headers: string[], rows: (string | number | null | undefined)[][]) {
  const esc = (v: string | number | null | undefined) => {
    const s = v == null ? '' : String(v)
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const csv = '﻿' + [headers, ...rows].map((r) => r.map(esc).join(',')).join('\n')
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename.endsWith('.csv') ? filename : `${filename}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

// ── Icon ────────────────────────────────────────────────────────────────────
// Inline action icons, same pattern as Sidebar's NavIcon (stroke paths on a 0 0 24 24 viewBox,
// currentColor so they inherit the button's colour). No icon package, the app must run offline.
// One name = one meaning. Replaces the glyph characters (✕ ✎ ↑ ⛃ …) the redesign brief banned.
const ICON_PATHS: Record<string, string> = {
  close: 'M6 6l12 12M18 6L6 18',
  edit: 'M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z',
  up: 'M12 19V5M5 12l7-7 7 7',
  down: 'M12 5v14M5 12l7 7 7-7',
  filter: 'M3 5h18l-7 8v6l-4 2v-8z',
  map: 'M9 4L3 6v14l6-2 6 2 6-2V4l-6 2zM9 4v14M15 6v14',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  webhook: 'M7 17L17 7M8 7h9v9',
  crosshair: 'M12 2v4M12 18v4M2 12h4M18 12h4M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',
  plus: 'M12 5v14M5 12h14',
  minus: 'M5 12h14',
  drag: 'M9 5h.01M15 5h.01M9 12h.01M15 12h.01M9 19h.01M15 19h.01',
  chevronDown: 'M6 9l6 6 6-6',
  chevronRight: 'M9 6l6 6-6 6',
  chevronUp: 'M6 15l6-6 6 6',
  download: 'M12 3v12M7 10l5 5 5-5M5 21h14',
  upload: 'M12 21V9M7 14l5-5 5 5M5 3h14',
  external: 'M7 17L17 7M8 7h9v9',
  check: 'M20 6L9 17l-5-5',
  copy: 'M9 9h10v10H9zM5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1',
}
export function Icon({ name, size = 16, className = '' }: { name: keyof typeof ICON_PATHS; size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" className={className}>
      <path d={ICON_PATHS[name]} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

// ── Page header ───────────────────────────────────────────────────────────────
// The page's NAME lives in the Topbar (components/Topbar.tsx), so this renders only the parts a
// page knows and the shell cannot: a live subtitle and page-specific actions.
export function PageHeader({
  subtitle,
  actions,
}: {
  subtitle?: string
  actions?: ReactNode
}) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>{subtitle && <p className="text-[13px] text-muted">{subtitle}</p>}</div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}

// ── Card ──────────────────────────────────────────────────────────────────────
export function Card({
  title,
  kicker,
  actions,
  className = '',
  bodyClass = '',
  children,
}: {
  title?: ReactNode
  kicker?: string
  actions?: ReactNode
  className?: string
  bodyClass?: string
  children: ReactNode
}) {
  return (
    <section
      className={`overflow-hidden rounded-[12px] border border-border bg-surface ${className}`}
    >
      {(title || actions || kicker) && (
        <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
          <div className="min-w-0">
            {kicker && (
              <div className="text-[11px] font-medium uppercase tracking-wider text-dim">{kicker}</div>
            )}
            {title && <div className="truncate text-[14.5px] font-bold text-fg">{title}</div>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={bodyClass || 'p-4'}>{children}</div>
    </section>
  )
}

// ── Stat card ─────────────────────────────────────────────────────────────────
// StatCard is the headline-number tile: an uppercase label over a large value, sized to the
// prototype (12px/600 label with 0.4px tracking, 26px/700 value).
//
// `accentClass` is a text-colour utility rather than a raw colour so a stat can carry meaning
// (an alert count in amber) while still following the theme in both light and dark. It defaults
// to plain foreground, a number is only coloured when the colour says something.
export function StatCard({
  label,
  value,
  hint,
  accentClass = 'text-fg',
  className = '',
}: {
  label: string
  value: ReactNode
  hint?: string
  accentClass?: string
  className?: string
}) {
  return (
    <div className={`rounded-[12px] border border-border bg-surface px-[18px] py-4 ${className}`}>
      <div className="text-[13px] font-semibold uppercase tracking-[0.4px] text-dim">{label}</div>
      <div className={`mt-1.5 text-[28px] font-bold leading-none ${accentClass}`}>{value}</div>
      {hint && <div className="mt-1.5 text-[12.5px] text-muted">{hint}</div>}
    </div>
  )
}

// ── Badges ────────────────────────────────────────────────────────────────────
// One colour = one meaning. Keep these maps as the single source of truth for status colour.

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-critical/15 text-critical',
  high: 'bg-high/15 text-high',
  medium: 'bg-medium/15 text-medium',
  low: 'bg-low/15 text-low',
  info: 'bg-info/15 text-info',
}

/** Severity 0-4 (info→critical) or its name. */
export function SeverityBadge({ level }: { level: number | string }) {
  const names = ['info', 'low', 'medium', 'high', 'critical']
  const name = typeof level === 'number' ? (names[level] ?? 'info') : level.toLowerCase()
  return <Pill className={SEVERITY_STYLE[name] ?? SEVERITY_STYLE.info}>{name}</Pill>
}

const BAND_STYLE: Record<string, string> = {
  critical: 'bg-critical/15 text-critical',
  high: 'bg-high/15 text-high',
  medium: 'bg-medium/15 text-medium',
  low: 'bg-low/15 text-low',
}

/** Composite threat band (low/medium/high/critical). */
export function BandBadge({ band, score }: { band: string; score?: number }) {
  return (
    <Pill className={BAND_STYLE[band] ?? BAND_STYLE.low}>
      {score !== undefined ? `${score} · ${band}` : band}
    </Pill>
  )
}

// Action / lifecycle status. "recommended" and "pending" are deliberately amber, never green , 
// the UI must not imply an action already happened (honesty principle).
const STATUS_STYLE: Record<string, string> = {
  recommended: 'bg-medium/15 text-medium',
  pending: 'bg-medium/15 text-medium',
  requested: 'bg-medium/15 text-medium',
  delivered: 'bg-low/15 text-low',
  approved: 'bg-low/15 text-low',
  executed: 'bg-success/15 text-success',
  done: 'bg-success/15 text-success',
  contained: 'bg-critical/15 text-critical',
  released: 'bg-info/15 text-muted',
  dismissed: 'bg-info/15 text-muted',
  unbanned: 'bg-info/15 text-muted',
  failed: 'bg-critical/15 text-critical',
}

export function StatusBadge({ status }: { status: string }) {
  return <Pill className={STATUS_STYLE[status] ?? 'bg-info/15 text-muted'}>{status}</Pill>
}

export function Pill({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11.5px] font-medium ${className}`}
    >
      {children}
    </span>
  )
}

// ── Buttons ───────────────────────────────────────────────────────────────────
type BtnVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

const BTN: Record<BtnVariant, string> = {
  primary: 'bg-accent text-white hover:opacity-90',
  secondary: 'border border-border text-fg hover:bg-surface-2',
  ghost: 'text-muted hover:bg-surface-2 hover:text-fg',
  danger: 'border border-critical/40 text-critical hover:bg-critical/10',
}

export const Button = forwardRef<
  HTMLButtonElement,
  { variant?: BtnVariant } & React.ButtonHTMLAttributes<HTMLButtonElement>
>(function Button({ variant = 'secondary', className = '', children, ...rest }, ref) {
  return (
    <button
      ref={ref}
      {...rest}
      className={`rounded-[8px] px-3 py-1.5 text-[13px] font-medium transition-colors disabled:opacity-45 ${BTN[variant]} ${className}`}
    >
      {children}
    </button>
  )
})

// ── Inputs ────────────────────────────────────────────────────────────────────
export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const { className = '', ...rest } = props
  return (
    <input
      {...rest}
      className={`rounded-[8px] border border-border bg-surface-2 px-2.5 py-1.5 text-[13px] text-fg outline-none placeholder:text-dim focus:border-accent ${className}`}
    />
  )
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  const { className = '', ...rest } = props
  return (
    <select
      {...rest}
      className={`rounded-[8px] border border-border bg-surface-2 px-2.5 py-1.5 text-[13px] text-fg outline-none focus:border-accent ${className}`}
    />
  )
}

// ── States ────────────────────────────────────────────────────────────────────

/** Empty state: always names the one action that fixes it. */
export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="rounded-[12px] border border-dashed border-border px-4 py-10 text-center">
      <div className="text-[14px] font-medium text-muted">{title}</div>
      {hint && <div className="mx-auto mt-1 max-w-md text-[12.5px] text-dim">{hint}</div>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  )
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-[8px] bg-surface-2 ${className}`} />
}

// TableSkeleton is the standard "loading a table" placeholder: a few shimmering rows, so a slow
// fetch shows the shape of what is coming instead of a bare "Loading…" line that then jumps into a
// full table. Pass the column count so the width roughly matches the real table.
export function TableSkeleton({ rows = 6, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-2 p-4" aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} className={`h-5 ${c === 0 ? 'w-[22%]' : 'flex-1'}`} />
          ))}
        </div>
      ))}
    </div>
  )
}

// LastUpdated is the one freshness stamp every auto-refreshing board shows, so "updated 14:03:22"
// reads the same everywhere. Null (not fetched yet) renders nothing.
export function LastUpdated({ at, className = '' }: { at: Date | null; className?: string }) {
  if (!at) return null
  return <span className={`text-[12px] text-dim ${className}`}>updated {at.toLocaleTimeString()}</span>
}

export function ErrorText({ children }: { children: ReactNode }) {
  return <p className="text-[13px] text-critical">{children}</p>
}

/**
 * Honesty banner, used wherever DeusWatch must NOT imply it did something it didn't
 * (e.g. "nothing enforces this ban yet", "recommend-only", "not verified live").
 */
export function NoticeBanner({
  tone = 'warn',
  title,
  children,
  action,
}: {
  tone?: 'warn' | 'info' | 'danger'
  title: string
  children?: ReactNode
  action?: ReactNode
}) {
  const tones = {
    warn: 'border-medium/40 bg-medium/5',
    info: 'border-low/40 bg-low/5',
    danger: 'border-critical/40 bg-critical/5',
  }
  const titleTone = { warn: 'text-medium', info: 'text-low', danger: 'text-critical' }
  return (
    <div className={`rounded-[12px] border p-3 ${tones[tone]}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className={`text-[13.5px] font-medium ${titleTone[tone]}`}>{title}</p>
          {children && <div className="mt-1 text-[12.5px] text-muted">{children}</div>}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
    </div>
  )
}
