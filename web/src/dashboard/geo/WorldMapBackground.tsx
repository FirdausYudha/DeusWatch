import { MAP_WIDTH, MAP_HEIGHT } from './projection'

// WorldMapBackground draws a schematic world underneath the attack arcs. It is deliberately NOT
// pixel-accurate — a real Natural Earth topology would ship as ~60 KB of GeoJSON + a compiler step
// that isn't worth carrying in v1 (docs/geo-map.md notes this as an accepted v1 trade-off). What
// this gives an operator is:
//   - a coordinate plane so a marker's position reads as "roughly Southeast Asia" vs "roughly
//     Eastern Europe";
//   - the equator and prime meridian as reference lines;
//   - blocky continent hints so the eye doesn't have to guess which pole is which.
//
// Colours pull from theme variables (--color-border, --color-dim) so this works in light + dark
// without a media query. Pointer events off — the map is background scenery only, the interactive
// bits are the markers on top.

export default function WorldMapBackground() {
  const grid: number[] = []
  // Vertical gridlines every 30° of longitude.
  for (let lon = -180; lon <= 180; lon += 30) {
    grid.push(((lon + 180) / 360) * MAP_WIDTH)
  }
  const rows: number[] = []
  // Horizontal gridlines every 30° of latitude.
  for (let lat = -60; lat <= 60; lat += 30) {
    rows.push(((90 - lat) / 180) * MAP_HEIGHT)
  }
  return (
    <g pointerEvents="none">
      {/* Ocean fill — subtle surface tint so continents read against it. */}
      <rect x={0} y={0} width={MAP_WIDTH} height={MAP_HEIGHT} fill="var(--color-surface-2, #0f172a)" opacity={0.4} />
      {/* Gridlines. */}
      {grid.map((x, i) => (
        <line key={`v${i}`} x1={x} y1={0} x2={x} y2={MAP_HEIGHT} stroke="currentColor" strokeWidth={0.5} opacity={0.08} />
      ))}
      {rows.map((y, i) => (
        <line key={`h${i}`} x1={0} y1={y} x2={MAP_WIDTH} y2={y} stroke="currentColor" strokeWidth={0.5} opacity={0.08} />
      ))}
      {/* Equator + prime meridian a shade stronger. */}
      <line x1={0} y1={MAP_HEIGHT / 2} x2={MAP_WIDTH} y2={MAP_HEIGHT / 2} stroke="currentColor" strokeWidth={0.7} opacity={0.18} />
      <line x1={MAP_WIDTH / 2} y1={0} x2={MAP_WIDTH / 2} y2={MAP_HEIGHT} stroke="currentColor" strokeWidth={0.7} opacity={0.18} />
      {/* Continent hints — rough polygons in equirectangular coords. Not to scale, but recognisable
          enough that an operator can tell which quadrant a marker is in. Fill/stroke both keyed to
          the theme so this renders in dark + light. Order roughly northwest → southeast so higher
          Z-order continents (like Australia) don't get hidden behind neighbours. */}
      <g fill="currentColor" fillOpacity={0.12} stroke="currentColor" strokeOpacity={0.35} strokeWidth={0.6}>
        {/* North America */}
        <path d="M 130 90 L 250 80 L 310 130 L 320 200 L 260 240 L 200 230 L 170 200 L 150 160 Z" />
        {/* Central America + Caribbean */}
        <path d="M 240 260 L 285 265 L 300 285 L 275 300 L 245 285 Z" />
        {/* South America */}
        <path d="M 300 290 L 340 300 L 360 350 L 350 420 L 320 460 L 300 430 L 285 370 Z" />
        {/* Greenland */}
        <path d="M 400 60 L 460 50 L 470 100 L 430 115 L 400 95 Z" />
        {/* Europe */}
        <path d="M 470 130 L 560 120 L 570 170 L 530 200 L 490 200 L 470 165 Z" />
        {/* Africa */}
        <path d="M 490 210 L 580 205 L 620 260 L 610 340 L 560 400 L 520 380 L 500 320 L 490 260 Z" />
        {/* Middle East */}
        <path d="M 580 210 L 640 205 L 660 250 L 630 265 L 590 245 Z" />
        {/* Russia + North Asia */}
        <path d="M 570 90 L 900 80 L 920 150 L 870 190 L 780 190 L 700 175 L 620 165 L 580 140 Z" />
        {/* South + Southeast Asia + India */}
        <path d="M 680 220 L 760 220 L 790 270 L 830 260 L 850 290 L 820 320 L 770 320 L 720 300 L 690 270 Z" />
        {/* China + East Asia */}
        <path d="M 780 180 L 880 180 L 900 240 L 850 260 L 800 240 Z" />
        {/* Japan / Korea */}
        <path d="M 900 200 L 930 195 L 935 240 L 910 245 Z" />
        {/* Indonesia + Philippines archipelago (schematic clusters) */}
        <path d="M 830 320 L 900 320 L 910 350 L 850 355 Z" />
        {/* Australia */}
        <path d="M 850 380 L 930 375 L 950 420 L 920 445 L 870 445 L 855 415 Z" />
      </g>
    </g>
  )
}
