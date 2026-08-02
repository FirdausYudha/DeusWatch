import { MAP_WIDTH, MAP_HEIGHT } from './projection'
import { WORLD_PATHS } from './worldPaths'

// WorldMapBackground draws the world underneath the attack arcs using REAL country boundaries —
// Natural Earth 1:110m, pre-projected to this viewport by tools/worldmapgen and committed as plain
// SVG path strings (web/src/dashboard/geo/worldPaths.ts).
//
// Why pre-projected paths instead of GeoJSON + d3-geo at runtime: the app must work fully offline
// and the bundle shouldn't carry a projection library for one widget. The generator does the
// topology decoding + projection + simplification once; the frontend just renders <path d> strings.
//
// Styling: a clean blue treatment — deep ocean, lighter blue landmasses, hairline borders. No
// graticule, no equator/meridian guides: the map is context, the attack arcs are the content.
// Colours are literal (not theme variables) because this is a deliberate "dark blue map" surface
// that should look the same regardless of the app's light/dark setting — the arcs and markers on
// top carry the semantic colour. Pointer events are off; the markers above handle interaction.

const OCEAN_TOP = '#0d1a30'
const OCEAN_BOTTOM = '#0a1526'
const LAND_FILL = '#243b5c'
const LAND_STROKE = '#37568a'

export default function WorldMapBackground() {
  return (
    <g pointerEvents="none">
      <defs>
        {/* Subtle vertical gradient stops the large ocean area from reading as a flat block. */}
        <linearGradient id="dw-ocean" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={OCEAN_TOP} />
          <stop offset="100%" stopColor={OCEAN_BOTTOM} />
        </linearGradient>
      </defs>

      <rect x={0} y={0} width={MAP_WIDTH} height={MAP_HEIGHT} fill="url(#dw-ocean)" />

      {/* Real country boundaries, one <path> per landmass outer ring. */}
      <g fill={LAND_FILL} stroke={LAND_STROKE} strokeWidth={0.4} strokeLinejoin="round">
        {WORLD_PATHS.map((d, i) => (
          <path key={i} d={d} />
        ))}
      </g>
    </g>
  )
}
