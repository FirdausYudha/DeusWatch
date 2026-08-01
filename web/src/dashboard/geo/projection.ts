// Equirectangular (plate carrée) projection helpers for the animated attack-arc map.
//
// Why equirectangular and not Robinson (as originally planned in docs/geo-map.md): both are
// "look at the whole world" projections; equirectangular is lat × lon → x × y with a single
// multiply, which means the projection code is a few lines, the map SVG can be a simple
// coordinate-plane background (no complex polygon set to bundle), and the reverse-project on hover
// is symmetric. Robinson would look prettier but needs a lookup table + cubic interpolation for
// every marker/arc — worth trading later, not in v1 (docs/geo-map.md notes this as an accepted
// v1 trade-off; the projection module is self-contained and swappable when a real world SVG lands).
//
// The map viewport is 1000 × 500 (2:1 aspect, natural for equirectangular). x = 0 at the
// international date line (-180°), x = 1000 at +180°. y = 0 at the north pole (+90°), y = 500 at
// the south pole (-90°).

export const MAP_WIDTH = 1000
export const MAP_HEIGHT = 500

/**
 * project turns [lat, lon] (degrees) into [x, y] SVG coordinates.
 * Points outside the world get clamped so a bad centroid doesn't push a marker off-canvas.
 */
export function project(lat: number, lon: number): [number, number] {
  const clampedLat = Math.max(-90, Math.min(90, lat))
  const clampedLon = Math.max(-180, Math.min(180, lon))
  const x = ((clampedLon + 180) / 360) * MAP_WIDTH
  const y = ((90 - clampedLat) / 180) * MAP_HEIGHT
  return [x, y]
}

/**
 * arcPath returns an SVG path 'd' for a quadratic bezier from source to destination in projected
 * coordinates. The control point sits above the midpoint, offset by a fraction of the horizontal
 * distance — long arcs bow higher, short ones stay flat. Cross-antimeridian pairs (span > 180°)
 * would visually "wrap"; for v1 we accept a straight-through line, which is what most SOC
 * dashboards do.
 */
export function arcPath(src: [number, number], dst: [number, number]): string {
  const [sx, sy] = src
  const [dx, dy] = dst
  const mx = (sx + dx) / 2
  const my = (sy + dy) / 2
  // Curvature: longer arcs bow more; sign flips so arcs bow upward on the map (screen-y is down).
  const distance = Math.hypot(dx - sx, dy - sy)
  const bow = Math.min(200, distance * 0.35)
  const cy = my - bow
  return `M ${sx.toFixed(2)} ${sy.toFixed(2)} Q ${mx.toFixed(2)} ${cy.toFixed(2)} ${dx.toFixed(2)} ${dy.toFixed(2)}`
}
