// Command worldmapgen converts Natural Earth 1:110m country boundaries (via the world-atlas
// TopoJSON distribution) into a pre-projected SVG path bundle for the dashboard's attack-arc map.
//
// Why a generator instead of committing a hand-drawn map: the schematic outlines that shipped in
// v2.7.0 looked obviously fake. This produces real country boundaries while keeping the offline
// constraint — the output is a plain .ts file with pre-projected path strings, so the frontend
// needs no topojson/d3 dependency at runtime and no network access ever.
//
// Usage (network required, run manually when the map needs regenerating):
//
//	go run ./tools/worldmapgen > web/src/dashboard/geo/worldPaths.ts
//
// The projection here MUST match web/src/dashboard/geo/projection.ts (equirectangular, 1000x500).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	srcURL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"

	mapWidth  = 1000.0
	mapHeight = 500.0

	// minAreaPx drops islands smaller than this (in projected px²). At 4px² the specks that add
	// bytes without being visible at dashboard scale disappear, but every recognisable landmass
	// (including e.g. Cyprus, Crete, Hawaii) survives.
	minAreaPx = 4.0
	// thinTolerancePx removes consecutive points closer together than this. 1.6px keeps coastlines
	// clearly recognisable while roughly halving the byte count.
	thinTolerancePx = 1.6
)

type topology struct {
	Transform struct {
		Scale     [2]float64 `json:"scale"`
		Translate [2]float64 `json:"translate"`
	} `json:"transform"`
	Arcs    [][][2]float64 `json:"arcs"`
	Objects struct {
		Countries struct {
			Geometries []geometry `json:"geometries"`
		} `json:"countries"`
	} `json:"objects"`
}

type geometry struct {
	Type string          `json:"type"`
	Arcs json.RawMessage `json:"arcs"`
}

type point struct{ X, Y float64 }

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	topo, err := fetchTopology()
	if err != nil {
		log.Fatalf("worldmapgen: %v", err)
	}

	// Decode the delta-encoded arcs into absolute lon/lat.
	sx, sy := topo.Transform.Scale[0], topo.Transform.Scale[1]
	tx, ty := topo.Transform.Translate[0], topo.Transform.Translate[1]
	arcs := make([][]point, len(topo.Arcs))
	for i, arc := range topo.Arcs {
		var cx, cy float64
		pts := make([]point, len(arc))
		for j, d := range arc {
			cx += d[0]
			cy += d[1]
			pts[j] = point{X: cx*sx + tx, Y: cy*sy + ty}
		}
		arcs[i] = pts
	}

	var paths []string
	for _, g := range topo.Objects.Countries.Geometries {
		for _, ringIdx := range outerRings(g) {
			ring := resolveRing(arcs, ringIdx)
			projected := make([]point, len(ring))
			for i, p := range ring {
				projected[i] = project(p)
			}
			if ringArea(projected) < minAreaPx {
				continue
			}
			if d := toPath(thin(projected, thinTolerancePx)); d != "" {
				paths = append(paths, d)
			}
		}
	}
	// Deterministic output so regenerating produces a reviewable diff rather than a reshuffle.
	sort.Strings(paths)

	emit(paths)
	log.Printf("worldmapgen: %d paths", len(paths))
}

func fetchTopology() (*topology, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(srcURL)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var topo topology
	if err := json.Unmarshal(body, &topo); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &topo, nil
}

// outerRings returns the outer ring of every polygon in the geometry (holes are dropped — the map
// is a filled landmass silhouette, and at this scale interior holes like the Caspian add bytes for
// nearly no visual gain).
func outerRings(g geometry) [][]int {
	switch g.Type {
	case "Polygon":
		var rings [][]int
		if err := json.Unmarshal(g.Arcs, &rings); err != nil || len(rings) == 0 {
			return nil
		}
		return [][]int{rings[0]}
	case "MultiPolygon":
		var polys [][][]int
		if err := json.Unmarshal(g.Arcs, &polys); err != nil {
			return nil
		}
		out := make([][]int, 0, len(polys))
		for _, poly := range polys {
			if len(poly) > 0 {
				out = append(out, poly[0])
			}
		}
		return out
	default:
		return nil
	}
}

// resolveRing stitches arc indices into a single point ring. A negative index means "use arc
// ~i reversed"; continuation arcs drop their first point because it duplicates the previous end.
func resolveRing(arcs [][]point, idxs []int) []point {
	var out []point
	for _, i := range idxs {
		var seg []point
		if i < 0 {
			src := arcs[^i]
			seg = make([]point, len(src))
			for j, p := range src {
				seg[len(src)-1-j] = p
			}
		} else {
			seg = arcs[i]
		}
		if len(out) > 0 && len(seg) > 0 {
			seg = seg[1:]
		}
		out = append(out, seg...)
	}
	return out
}

// project is equirectangular — it MUST stay in sync with projection.ts on the frontend.
func project(p point) point {
	return point{
		X: ((p.X + 180) / 360) * mapWidth,
		Y: ((90 - p.Y) / 180) * mapHeight,
	}
}

func ringArea(pts []point) float64 {
	var a float64
	for i := range pts {
		j := (i + 1) % len(pts)
		a += pts[i].X*pts[j].Y - pts[j].X*pts[i].Y
	}
	return math.Abs(a / 2)
}

// thin drops points closer than tol to the previously kept point. Cheap, stable, and good enough
// at this scale — a full Douglas-Peucker gains little once coordinates are rounded to integers.
func thin(pts []point, tol float64) []point {
	if len(pts) < 4 {
		return pts
	}
	out := []point{pts[0]}
	for _, p := range pts[1 : len(pts)-1] {
		last := out[len(out)-1]
		if math.Hypot(p.X-last.X, p.Y-last.Y) >= tol {
			out = append(out, p)
		}
	}
	return append(out, pts[len(pts)-1])
}

func toPath(pts []point) string {
	if len(pts) < 3 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "M%.0f %.0f", pts[0].X, pts[0].Y)
	for _, p := range pts[1:] {
		fmt.Fprintf(&b, "L%.0f %.0f", p.X, p.Y)
	}
	b.WriteByte('Z')
	return b.String()
}

func emit(paths []string) {
	w := os.Stdout
	fmt.Fprintf(w, `// Code generated by tools/worldmapgen; DO NOT EDIT.
//
// Real country boundaries (Natural Earth 1:110m via the world-atlas TopoJSON distribution),
// pre-projected to the dashboard's equirectangular 1000x500 viewport and simplified for size.
// Regenerate with:  go run ./tools/worldmapgen > web/src/dashboard/geo/worldPaths.ts
//
// Natural Earth is public domain (https://www.naturalearthdata.com/about/terms-of-use/).
//
// %d filled land paths. Holes are omitted; islands under %.0f px² are dropped.

export const WORLD_PATHS: readonly string[] = [
`, len(paths), minAreaPx)
	for _, p := range paths {
		fmt.Fprintf(w, "  '%s',\n", p)
	}
	fmt.Fprintln(w, "]")
}
