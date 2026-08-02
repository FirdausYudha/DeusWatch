import { useEffect, useMemo, useState } from 'react'
import { fetchAttackGeo, type AttackOrigin, type DashRange } from '../../lib/api'
import { lookupCentroid } from './centroids'
import { arcPath, MAP_HEIGHT, MAP_WIDTH, project } from './projection'
import WorldMapBackground from './WorldMapBackground'

// AttackGeoMap draws an equirectangular world map with animated attack arcs from every external
// source IP in the current dashboard time window to the (statically configured) manager location.
// docs/geo-map.md decision A1 + B1 (v1): country centroid bundle + one env-configured manager
// point.
//
// Design constraints:
//   - Offline-first: no external tiles, no external fonts, no d3 dep. Native SVG only.
//   - Dark + light themes: colours pull from theme CSS variables (--color-*).
//   - Bounded DOM: max 200 origins from the API, arcs drawn on top and pruned by opacity fade
//     rather than kept forever.
//   - prefers-reduced-motion: static arcs (no animateMotion) when the user has that set.

type Selected = AttackOrigin | null

// Manager (destination) location. v1 is a single static point (docs/geo-map.md decision B1);
// admin sets it once by overriding these via localStorage:
//   localStorage.setItem('deuswatch.manager_lat', '-6.2')
//   localStorage.setItem('deuswatch.manager_lon', '106.8')
// Defaults to Jakarta so a Southeast-Asia operator sees a sensible endpoint out of the box.
const MANAGER_LATLON: [number, number] = (() => {
  const readNum = (key: string, fallback: number): number => {
    try {
      const raw = localStorage.getItem(key)
      if (raw === null) return fallback
      const n = Number(raw)
      return Number.isFinite(n) ? n : fallback
    } catch {
      return fallback
    }
  }
  return [readNum('deuswatch.manager_lat', -6.2), readNum('deuswatch.manager_lon', 106.8)]
})()

// prefersReducedMotion snapshots the media-query at mount — good enough for a widget that isn't
// hot-swapping accessibility state per user interaction.
function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return false
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

export default function AttackGeoMap({ range }: { range: DashRange | null }) {
  const [origins, setOrigins] = useState<AttackOrigin[] | null>(null)
  const [err, setErr] = useState('')
  const [selected, setSelected] = useState<Selected>(null)
  const reduced = useMemo(prefersReducedMotion, [])

  useEffect(() => {
    const load = () => {
      fetchAttackGeo(range)
        .then((rows) => {
          setOrigins(rows)
          setErr('')
        })
        .catch((e) => setErr(String((e as Error).message ?? e)))
    }
    load()
    // Refresh every 30 s so newly-alerting IPs show up without a full dashboard reload.
    const t = setInterval(load, 30_000)
    return () => clearInterval(t)
  }, [range])

  const [dstX, dstY] = project(MANAGER_LATLON[0], MANAGER_LATLON[1])

  // Marker size scales with count so a persistent source draws the eye without letting a single
  // burst dominate the view. sqrt(count) keeps the growth gentle.
  const markerRadius = (count: number) => Math.min(14, 3 + Math.sqrt(count) * 1.2)

  if (err) {
    return <p className="py-6 text-center text-[12.5px] text-critical">{err}</p>
  }
  // We deliberately DON'T early-return on `origins === null` (loading) or `origins.length === 0`
  // (no attacks yet). The map itself is the widget's identity — showing a bare "loading…" or
  // "no attacks" text is uglier than showing the world + manager pulse with a subtle overlay hint.
  // An operator with a fresh deploy still sees a functioning globe waiting for its first attacker.
  const list: AttackOrigin[] = origins ?? []

  return (
    <div className="flex flex-col gap-2 text-fg">
      <div className="relative w-full overflow-x-auto rounded-[8px] border border-border bg-surface">
        <svg viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`} className="block h-auto w-full" role="img" aria-label="World map of external attack sources">
          <WorldMapBackground />

          {/* Arcs — behind the markers so the endpoint dots always sit on top. */}
          <g fill="none" strokeLinecap="round" pointerEvents="none">
            {list.map((o) => {
              const [lat, lon] = lookupCentroid(o.country)
              const [sx, sy] = project(lat, lon)
              const d = arcPath([sx, sy], [dstX, dstY])
              const color = o.blocked ? '#10b981' : '#f43f5e'
              return (
                <g key={o.ip + '-arc'} opacity={selected && selected.ip !== o.ip ? 0.15 : 0.55}>
                  <path d={d} stroke={color} strokeWidth={1} opacity={0.6} />
                  {!reduced && (
                    <circle r={2.5} fill={color}>
                      <animateMotion dur={`${3 + (o.count % 3)}s`} repeatCount="indefinite" path={d} />
                    </circle>
                  )}
                </g>
              )
            })}
          </g>

          {/* Manager destination — pulses gently so the eye finds it. */}
          <g pointerEvents="none">
            <circle cx={dstX} cy={dstY} r={6} fill="none" stroke="#22d3ee" strokeWidth={1.5} opacity={0.9}>
              {!reduced && (
                <animate attributeName="r" values="6;16;6" dur="2.5s" repeatCount="indefinite" />
              )}
              {!reduced && (
                <animate attributeName="opacity" values="0.9;0.1;0.9" dur="2.5s" repeatCount="indefinite" />
              )}
            </circle>
            <circle cx={dstX} cy={dstY} r={4} fill="#22d3ee" />
          </g>

          {/* Source markers on top of everything so hover always finds them. */}
          <g>
            {list.map((o) => {
              const [lat, lon] = lookupCentroid(o.country)
              const [x, y] = project(lat, lon)
              const r = markerRadius(o.count)
              const color = o.blocked ? '#10b981' : '#f43f5e'
              const isActive = selected?.ip === o.ip
              return (
                <g key={o.ip} onMouseEnter={() => setSelected(o)} onFocus={() => setSelected(o)}
                  tabIndex={0} style={{ cursor: 'pointer', outline: 'none' }}
                  aria-label={`${o.ip} from ${o.country || 'unknown'}, ${o.count} alerts, ${o.blocked ? 'blocked' : 'active'}`}>
                  <circle cx={x} cy={y} r={r} fill={color} fillOpacity={isActive ? 0.55 : 0.25} stroke={color} strokeWidth={isActive ? 2 : 1} />
                </g>
              )
            })}
          </g>
        </svg>
        {/* Overlay hint when we haven't seen anything yet — kept subtle so the map itself remains
            the star. Absolute-positioned inside the map container's `relative` wrapper so it sits
            over the SVG without shifting layout. Hidden as soon as any origin arrives. */}
        {origins !== null && list.length === 0 && (
          <div className="pointer-events-none absolute inset-x-0 bottom-2 text-center text-[10.5px] uppercase tracking-wide text-dim">
            waiting for external attacks
          </div>
        )}
        {origins === null && (
          <div className="pointer-events-none absolute inset-x-0 bottom-2 text-center text-[10.5px] uppercase tracking-wide text-dim">
            loading…
          </div>
        )}
      </div>

      {/* Hover detail row — mirrors the columns in the reference dashboard the operator sent. */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 rounded-[8px] border border-border bg-surface px-3 py-2 text-[11.5px] sm:grid-cols-5">
        <DetailCell label="Country" value={selected?.country || (selected ? '—' : 'Hover a marker')} />
        <DetailCell label="City" value={selected?.city || (selected ? '—' : '—')} />
        <DetailCell label="IP" value={selected?.ip || '—'} mono />
        <DetailCell label="Alerts" value={selected ? String(selected.count) : '—'} />
        <DetailCell label="Status" value={selected ? (selected.blocked ? 'blocked' : 'active') : '—'}
          valueClass={selected ? (selected.blocked ? 'text-emerald-500' : 'text-rose-500') : ''} />
      </div>
    </div>
  )
}

function DetailCell({ label, value, mono = false, valueClass = '' }: { label: string; value: string; mono?: boolean; valueClass?: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-dim">{label}</div>
      <div className={`truncate ${mono ? 'font-mono text-[11px]' : 'text-[12.5px]'} ${valueClass || 'text-fg'}`}>{value}</div>
    </div>
  )
}
