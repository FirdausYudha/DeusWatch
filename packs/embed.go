// Package packs embeds the curated, INSTALLABLE Sigma rule packs that ship inside DeusWatch.
//
// These are the "bundled" half of the rule-pack marketplace: clicking Install imports the
// pack's rules into the DB and enables them — no network access, so it works on an air-gapped
// deployment. (The remote half — fetching a pack over HTTPS so it can auto-update — layers on
// top of the same import path.)
//
// Curation rule: only ship rules that match fields DeusWatch actually populates (see
// sigma.FlattenEvent). A rule that references telemetry we never collect would install fine and
// then never fire, which is worse than not shipping it.
package packs

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
)

// FS holds every pack's rule files (<pack-id>/*.yml).
//
//go:embed */*.yml
var FS embed.FS

// Pack describes one installable curated pack.
type Pack struct {
	ID   string // directory name + the rule category it installs under
	Name string
	Desc string
}

// Catalog is the set of bundled installable packs.
var Catalog = []Pack{
	{
		ID:   "waf-essentials",
		Name: "WAF / Web attack essentials",
		Desc: "Turns ModSecurity / OWASP CRS blocks into labeled attack alerts: SQLi, XSS, path traversal, RCE, and scanners probing known exploit paths. Needs a WAF log source (docs/modsecurity.md).",
	},
}

// Find returns the catalog entry for id.
func Find(id string) (Pack, bool) {
	for _, p := range Catalog {
		if p.ID == id {
			return p, true
		}
	}
	return Pack{}, false
}

// Rules returns every rule file in a pack, keyed by file name.
func Rules(id string) (map[string][]byte, error) {
	if _, ok := Find(id); !ok {
		return nil, fmt.Errorf("packs: unknown pack %q", id)
	}
	entries, err := fs.ReadDir(FS, id)
	if err != nil {
		return nil, fmt.Errorf("packs: read %q: %w", id, err)
	}
	out := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".yml" {
			continue
		}
		b, err := FS.ReadFile(path.Join(id, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = b
	}
	return out, nil
}
