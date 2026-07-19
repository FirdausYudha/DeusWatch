// Shared UI primitives for the DeusWatch redesign. Every page composes these instead of
// re-inventing card/badge/button chrome, so the look stays consistent and a token change
// (index.css) propagates everywhere. Semantics come first: a colour always means the same thing.
import type { ReactNode } from 'react'

// ── Page header ───────────────────────────────────────────────────────────────
export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string
  subtitle?: string
  actions?: ReactNode
}) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-[16px] font-semibold tracking-tight text-fg">{title}</h1>
        {subtitle && <p className="mt-0.5 text-[12px] text-muted">{subtitle}</p>}
      </div>
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
              <div className="text-[10px] font-medium uppercase tracking-wider text-dim">{kicker}</div>
            )}
            {title && <div className="truncate text-[13px] font-semibold text-fg">{title}</div>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={bodyClass || 'p-4'}>{children}</div>
    </section>
  )
}

// ── Stat card ─────────────────────────────────────────────────────────────────
export function StatCard({
  label,
  value,
  hint,
  accent = 'var(--dw-accent)',
}: {
  label: string
  value: ReactNode
  hint?: string
  accent?: string
}) {
  return (
    <div className="rounded-[12px] border border-border bg-surface p-4">
      <div className="text-[10px] font-medium uppercase tracking-wider text-dim">{label}</div>
      <div className="mt-1.5 text-[26px] font-semibold leading-none" style={{ color: accent }}>
        {value}
      </div>
      {hint && <div className="mt-1.5 text-[11px] text-muted">{hint}</div>}
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

// Action / lifecycle status. "recommended" and "pending" are deliberately amber, never green —
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
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10.5px] font-medium ${className}`}
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

export function Button({
  variant = 'secondary',
  className = '',
  children,
  ...rest
}: { variant?: BtnVariant } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...rest}
      className={`rounded-[8px] px-3 py-1.5 text-[12px] font-medium transition-colors disabled:opacity-45 ${BTN[variant]} ${className}`}
    >
      {children}
    </button>
  )
}

// ── Inputs ────────────────────────────────────────────────────────────────────
export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const { className = '', ...rest } = props
  return (
    <input
      {...rest}
      className={`rounded-[8px] border border-border bg-surface-2 px-2.5 py-1.5 text-[12px] text-fg outline-none placeholder:text-dim focus:border-accent ${className}`}
    />
  )
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  const { className = '', ...rest } = props
  return (
    <select
      {...rest}
      className={`rounded-[8px] border border-border bg-surface-2 px-2.5 py-1.5 text-[12px] text-fg outline-none focus:border-accent ${className}`}
    />
  )
}

// ── States ────────────────────────────────────────────────────────────────────

/** Empty state: always names the one action that fixes it. */
export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="rounded-[12px] border border-dashed border-border px-4 py-10 text-center">
      <div className="text-[13px] font-medium text-muted">{title}</div>
      {hint && <div className="mx-auto mt-1 max-w-md text-[11.5px] text-dim">{hint}</div>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  )
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-[8px] bg-surface-2 ${className}`} />
}

export function ErrorText({ children }: { children: ReactNode }) {
  return <p className="text-[12px] text-critical">{children}</p>
}

/**
 * Honesty banner — used wherever DeusWatch must NOT imply it did something it didn't
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
          <p className={`text-[12.5px] font-medium ${titleTone[tone]}`}>{title}</p>
          {children && <div className="mt-1 text-[11.5px] text-muted">{children}</div>}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
    </div>
  )
}
