# Animated attack-arc geo map — contract

**Status:** v1 shipped (A1 + B1 defaults). Kept as the design doc; the "Open decisions" section at
the bottom records the choices made.

## How to enable

In the dashboard, click the **⚑ list / 🗺 map** toggle in the "Attack origins" card header — it
persists in localStorage under `deuswatch.ui.dashboard.geo_map` so your choice survives reloads.

The manager's location defaults to Jakarta (`-6.2, 106.8`). Override per-browser by pasting into
the console once:

```js
localStorage.setItem('deuswatch.manager_lat', '-6.2')
localStorage.setItem('deuswatch.manager_lon', '106.8')
```

## Goal

Replace the current dashboard "AttackMap" (a flag + heat-bar list, `web/src/dashboard/widgets.tsx`)
with a real world map that draws animated arcs from every attacker source to the manager (or the
attacked agent), plus a synchronised hover table for country / city / latitude / longitude / ISP-ASN
/ blocked status. Reference: the operator's colleague's dashboard image.

**Explicit non-goal:** match the reference image pixel-perfect. That is polished pro design work. V1
targets a functional, professional-looking map — arcs animate correctly, hover populates the table,
dark + light both work — without a full design system pass.

## Rendering approach

- **Offline-first constraint** — DeusWatch must run fully without internet. No CDN, no map tiles
  fetched at runtime, no external font sources. Everything bundled.
- **SVG world map**, static, bundled. Robinson projection (equal-visual-area, good for whole-world
  political maps). Source: **Natural Earth 1:110m Admin-0 Countries**, public domain, converted to a
  minified SVG (~50–80 KB gzipped after path optimisation).
- **Arcs** — SVG `<path>` per attack, quadratic bezier `M src Q ctrl dst`. Colour by severity band.
  A `<circle>` travels along the path via `<animateMotion>` for the pulsing dot.
- **Interactivity** — hover a source marker → detail row lights up at the bottom (Country / City /
  Lat / Lon / ISP-ASN / Blocked). Blocked = whether the source IP currently has an active ban action
  (join to `response_actions`).
- **No d3.** d3-geo + topojson add ~150–200 KB. Native SVG paths are enough for a static Robinson
  map; the added flexibility of d3 is unused here.

## Data pipeline

Events already carry `source_geo_country_iso` + `source_geo_city` (from AbuseIPDB → OTX → MaxMind
GeoIP fallback in `internal/enrich/clients.go`). Two things are missing:

1. **Lat/lon** — needed to place source markers and origin points of arcs.
2. **Destination lat/lon** — the endpoint the arc points to.

### Decision A — lat/lon source (see "Open decisions" below)

- **Option A1 — bundle country centroid table** (~5 KB, 200 entries). One marker per country
  aggregated; accuracy = country level, no ISP city precision. Zero DB work, zero runtime overhead.
- **Option A2 — MaxMind GeoLite2-City DB** (~70 MB, free but requires MaxMind account for updates).
  Enricher fetches lat/lon per IP. Accurate to city level; ISP-ASN column can be populated too.

Recommended default: **A1** for v1. Ship city-level (A2) as a v2 opt-in if operators ask.

### Decision B — destination point

- **Option B1 — single static manager location.** `MANAGER_LAT` + `MANAGER_LON` env on the API.
  All arcs point at one dot. Simple, matches the "hub" visual of the reference image.
- **Option B2 — per-agent destination.** Every agent has its own lat/lon (env or auto-detect via
  IP geolocation at enroll). Arcs terminate at whichever agent was hit.

Recommended default: **B1** for v1. B2 is a natural follow-up once agents have geo metadata.

## Data model

- No new tables. Just an app-level static bundle at `web/src/dashboard/geo/centroids.json`.
- API endpoint `GET /api/dashboard/attacks/geo?range=24h` returns a compact array:
  `[{ip, country, city, lat, lon, count, blocked}]` — one entry per unique source IP in the range.
  Country + city are read from the already-populated `source_geo_country_iso` / `source_geo_city`
  columns (verified in `internal/store/query.go`); lat/lon come from the centroid bundle in v1 (A1).
  `blocked` = row exists in `response_actions` with a currently-active status.

## Frontend design

- New component `AttackGeoMap` in `web/src/dashboard/geo/AttackGeoMap.tsx`.
- The existing `map` widget kind (currently maps to `AttackMap`) is renamed to `map_list` (the flag
  list widget, kept for smaller layouts); the new kind is `map_geo`.
- Dashboard PANELS layout keeps the `Attack origins` panel full-width, swaps its kind to `map_geo`.
- Renders:
  - `<svg viewBox="0 0 1000 500">` root, Robinson-projected world map behind.
  - Attack source dots (radius scales with count).
  - Arcs (opacity fades over 10s to avoid buildup).
  - Manager destination dot with subtle pulse ring.
  - Hover on a source dot → dispatches to a right-side detail panel showing the six fields.
- Dark + light both work — the SVG map is themed via `currentColor` fills and CSS variables (same
  approach as `dashboard/widgets.tsx` uses today).
- Reduced-motion respect: if `prefers-reduced-motion: reduce`, arcs render static (no animateMotion).

## Bundle & performance

- SVG map bundled: ~60 KB gzipped.
- Centroid JSON: ~5 KB.
- Component code: ~250–350 LoC.
- Existing bundle ~470 KB → estimated ~540 KB after. No d3, no map tiles, no runtime deps.
- Arcs capped at 200 concurrent visible; older arcs fade & retire so the DOM stays bounded even in a
  brute-force burst.

## Rollout

- Feature-flagged via `dashboard.geo_map` boolean in localStorage — off by default in v1 release so
  operators can opt in. Once verified on the operator's own dashboard, flip the default to on in
  the following patch.
- Existing `AttackMap` list widget stays available for narrow layouts / accessibility fallback.

## Tests

- Unit: centroid lookup returns known lat/lon for a handful of ISO codes; unknown ISO → null.
- Component: renders N markers for N distinct source IPs; hovering a marker updates the detail row
  (React Testing Library).
- API: `GET /api/dashboard/attacks/geo` returns aggregated + blocked-joined rows; RLS-scoped so a
  tenant-narrowed user sees only their sources.

## Estimated size

- v1 (Option A1 + B1, recommended): **one full session** — ~600 lines total (backend endpoint +
  SVG map + component + tests + docs), one commit, one minor release.
- v2 (Option A2 or B2): dedicated follow-up, ~1 more session each.

## Decisions taken for v1

**Decision A — lat/lon source: A1 (country centroid bundle)** — ~250 ISO-3166 alpha-2 entries in
`web/src/dashboard/geo/centroids.ts`. Country-level accuracy. No enrichment change; city text is
whatever `source_geo_city` already carries.

**Decision B — destination point: B1 (single static manager location)** — configured via
localStorage keys `deuswatch.manager_lat` and `deuswatch.manager_lon`, default (Jakarta) baked in.

**Decision C — projection: equirectangular, not Robinson** — one multiply per point, no lookup
tables. Contract had Robinson as the aspiration; equirectangular is what's actually implemented and
looks fine for a whole-world attack view. Swapping is a self-contained edit to `projection.ts`.

**Decision D — world map: REAL Natural Earth 1:110m boundaries** (upgraded in v2.7.2; v2.7.0–2.7.1
shipped schematic outlines that looked obviously fake). `tools/worldmapgen` downloads the
world-atlas TopoJSON distribution, decodes the delta-encoded arc topology, projects it with the
same equirectangular maths as `projection.ts`, simplifies it (drop islands < 4 px², thin points
closer than 1.6 px, round to integers) and emits `web/src/dashboard/geo/worldPaths.ts` — 267 plain
SVG path strings, ~63 KB.

The generator runs **manually**, not at build time, so the app keeps its offline guarantee and
carries no topojson/d3 runtime dependency:

```bash
go run ./tools/worldmapgen > web/src/dashboard/geo/worldPaths.ts
```

Natural Earth is public domain (<https://www.naturalearthdata.com/about/terms-of-use/>).
