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
// Colours pull from theme variables so this works in light + dark. Pointer events are off — the map
// is background scenery; the interactive bits are the attack markers on top.

export default function WorldMapBackground() {
  const meridians: number[] = []
  for (let lon = -180; lon <= 180; lon += 30) {
    meridians.push(((lon + 180) / 360) * MAP_WIDTH)
  }
  const parallels: number[] = []
  for (let lat = -60; lat <= 60; lat += 30) {
    parallels.push(((90 - lat) / 180) * MAP_HEIGHT)
  }
  return (
    <g pointerEvents="none">
      {/* Ocean fill so the landmasses read against it. */}
      <rect x={0} y={0} width={MAP_WIDTH} height={MAP_HEIGHT} fill="var(--color-surface-2, #0f172a)" opacity={0.35} />

      {/* Graticule — subtle, drawn under the land. */}
      {meridians.map((x, i) => (
        <line key={`m${i}`} x1={x} y1={0} x2={x} y2={MAP_HEIGHT} stroke="currentColor" strokeWidth={0.5} opacity={0.07} />
      ))}
      {parallels.map((y, i) => (
        <line key={`p${i}`} x1={0} y1={y} x2={MAP_WIDTH} y2={y} stroke="currentColor" strokeWidth={0.5} opacity={0.07} />
      ))}
      {/* Equator + prime meridian a shade stronger for orientation. */}
      <line x1={0} y1={MAP_HEIGHT / 2} x2={MAP_WIDTH} y2={MAP_HEIGHT / 2} stroke="currentColor" strokeWidth={0.7} opacity={0.14} />
      <line x1={MAP_WIDTH / 2} y1={0} x2={MAP_WIDTH / 2} y2={MAP_HEIGHT} stroke="currentColor" strokeWidth={0.7} opacity={0.14} />

      {/* Real country boundaries. One <path> per landmass outer ring. */}
      {/* fillOpacity is deliberately low: the land is context, the attack arcs are the content.
          At 0.14 the red/green arcs were competing with the landmass; 0.08 keeps continents clearly
          readable while letting the arcs sit visually on top. */}
      <g fill="currentColor" fillOpacity={0.08} stroke="currentColor" strokeOpacity={0.28} strokeWidth={0.4} strokeLinejoin="round">
        {WORLD_PATHS.map((d, i) => (
          <path key={i} d={d} />
        ))}
      </g>
    </g>
  )
}
