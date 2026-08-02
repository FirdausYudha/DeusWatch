import { MAP_WIDTH, MAP_HEIGHT } from './projection'
import { WORLD_PATHS } from './worldPaths'

// WorldMapBackground draws the world underneath the attack arcs using REAL country boundaries —
// Natural Earth 1:110m, pre-projected to this viewport by tools/worldmapgen and committed as plain
// SVG path strings (web/src/dashboard/geo/worldPaths.ts).
//
// Why pre-projected paths instead of GeoJSON + d3-geo at runtime: the app must work fully offline
// and the bundle shouldn't carry a projection library for one widget. The generator does the
// topology decoding + projection + simplification once, at build time; the frontend just renders
// <path d> strings. ~63 KB of path data, no runtime deps.
//
// Deliberately plain: no graticule, no equator/meridian guides. The map is context for the attack
// arcs, and gridlines added visual noise that competed with them. Colours pull from theme variables
// so this works in light + dark. Pointer events are off — the interactive bits are the markers on top.

export default function WorldMapBackground() {
  return (
    <g pointerEvents="none">
      {/* Ocean fill so the landmasses read against it. */}
      <rect x={0} y={0} width={MAP_WIDTH} height={MAP_HEIGHT} fill="var(--color-surface-2, #0f172a)" opacity={0.35} />

      {/* Real country boundaries. One <path> per landmass outer ring.
          fillOpacity is deliberately low: the land is context, the attack arcs are the content. */}
      <g fill="currentColor" fillOpacity={0.08} stroke="currentColor" strokeOpacity={0.28} strokeWidth={0.4} strokeLinejoin="round">
        {WORLD_PATHS.map((d, i) => (
          <path key={i} d={d} />
        ))}
      </g>
    </g>
  )
}
