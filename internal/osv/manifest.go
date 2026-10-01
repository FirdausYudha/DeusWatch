package osv

import (
	"bufio"
	"encoding/json"
	"strings"
)

// Software Composition Analysis input: turning the dependency lockfiles an agent ships into package
// URLs OSV can match. Each parser is deliberately small and format-specific rather than pulling in a
// dependency per ecosystem; lockfiles are stable, well-documented formats.

// Dep is one language dependency found in a manifest.
type Dep struct {
	PURLType string // purl type: npm | golang | pypi | gem | cargo | composer
	Name     string
	Version  string
}

// PURL renders the dependency as a package URL for an OSV query.
func (d Dep) PURL() string {
	return "pkg:" + d.PURLType + "/" + esc(d.Name) + "@" + esc(d.Version)
}

// ParseManifest extracts dependencies from a lockfile. The file's base name selects the parser;
// unknown names and unparseable content yield nil rather than an error, because a single odd file on
// one endpoint must never fail a whole scan.
func ParseManifest(baseName, content string) []Dep {
	switch baseName {
	case "package-lock.json":
		return parsePackageLock(content)
	case "go.sum":
		return parseGoSum(content)
	case "requirements.txt":
		return parseRequirements(content)
	case "composer.lock":
		return parseComposerLock(content)
	case "Cargo.lock":
		return parseCargoLock(content)
	case "Gemfile.lock":
		return parseGemfileLock(content)
	default:
		// go.mod, yarn.lock, pnpm-lock.yaml, pom.xml, poetry.lock, Pipfile.lock, gradle.lockfile:
		// not parsed yet. go.sum covers Go; the rest are future work.
		return nil
	}
}

// parsePackageLock handles npm lockfile v1 ("dependencies") and v2/v3 ("packages").
func parsePackageLock(content string) []Dep {
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if json.Unmarshal([]byte(content), &doc) != nil {
		return nil
	}
	var out []Dep
	for path, p := range doc.Packages {
		if path == "" || p.Version == "" {
			continue // "" is the root project itself
		}
		// Keys look like "node_modules/foo" or "node_modules/a/node_modules/b"; the real package is
		// whatever follows the LAST node_modules segment.
		name := p.Name
		if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
			name = path[i+len("node_modules/"):]
		} else if name == "" {
			continue
		}
		if name != "" {
			out = append(out, Dep{PURLType: "npm", Name: name, Version: p.Version})
		}
	}
	for name, d := range doc.Dependencies {
		if name != "" && d.Version != "" {
			out = append(out, Dep{PURLType: "npm", Name: name, Version: d.Version})
		}
	}
	return dedupe(out)
}

// parseGoSum reads go.sum lines "module version hash". The "/go.mod" pseudo-entries are skipped so
// each module is counted once.
func parseGoSum(content string) []Dep {
	var out []Dep
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || strings.HasSuffix(f[1], "/go.mod") {
			continue
		}
		out = append(out, Dep{PURLType: "golang", Name: f[0], Version: strings.TrimPrefix(f[1], "v")})
	}
	return dedupe(out)
}

// parseRequirements reads pinned pip requirements ("name==1.2.3"). Unpinned or range specs are
// skipped: without an exact version there is nothing to match against.
func parseRequirements(content string) []Dep {
	var out []Dep
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, ";"); i >= 0 { // environment markers
			line = strings.TrimSpace(line[:i])
		}
		name, version, ok := strings.Cut(line, "==")
		if !ok {
			continue
		}
		name = strings.TrimSpace(strings.SplitN(name, "[", 2)[0]) // drop extras: pkg[extra]
		version = strings.TrimSpace(version)
		if name != "" && version != "" {
			out = append(out, Dep{PURLType: "pypi", Name: name, Version: version})
		}
	}
	return dedupe(out)
}

func parseComposerLock(content string) []Dep {
	var doc struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if json.Unmarshal([]byte(content), &doc) != nil {
		return nil
	}
	var out []Dep
	for _, list := range [][]struct{ Name, Version string }{doc.Packages, doc.PackagesDev} {
		for _, p := range list {
			if p.Name != "" && p.Version != "" {
				out = append(out, Dep{PURLType: "composer", Name: p.Name, Version: strings.TrimPrefix(p.Version, "v")})
			}
		}
	}
	return dedupe(out)
}

// parseCargoLock reads the TOML [[package]] blocks without a TOML dependency: each block has a
// name and version line, which is all we need.
func parseCargoLock(content string) []Dep {
	var out []Dep
	var name, version string
	flush := func() {
		if name != "" && version != "" {
			out = append(out, Dep{PURLType: "cargo", Name: name, Version: version})
		}
		name, version = "", ""
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "[[package]]" {
			flush()
			continue
		}
		if v, ok := tomlString(line, "name"); ok {
			name = v
		} else if v, ok := tomlString(line, "version"); ok {
			version = v
		}
	}
	flush()
	return dedupe(out)
}

// tomlString matches `key = "value"`.
func tomlString(line, key string) (string, bool) {
	rest, ok := strings.CutPrefix(line, key)
	if !ok {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	rest, ok = strings.CutPrefix(rest, "=")
	if !ok {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	if len(rest) < 2 || rest[0] != '"' {
		return "", false
	}
	if end := strings.IndexByte(rest[1:], '"'); end >= 0 {
		return rest[1 : 1+end], true
	}
	return "", false
}

// parseGemfileLock reads the GEM/specs section, where dependencies appear as "    name (1.2.3)".
// Deeper-indented lines are transitive requirement constraints, not resolved versions.
func parseGemfileLock(content string) []Dep {
	var out []Dep
	inSpecs := false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if trimmed == "" || (!strings.HasPrefix(raw, " ") && trimmed != "specs:") {
			inSpecs = false
			continue
		}
		if !inSpecs {
			continue
		}
		// Resolved gems sit at exactly 4 spaces of indent.
		if !strings.HasPrefix(raw, "    ") || strings.HasPrefix(raw, "      ") {
			continue
		}
		name, rest, ok := strings.Cut(trimmed, " (")
		if !ok {
			continue
		}
		version := strings.TrimSuffix(rest, ")")
		if name != "" && version != "" && !strings.ContainsAny(version, "<>=~") {
			out = append(out, Dep{PURLType: "gem", Name: name, Version: version})
		}
	}
	return dedupe(out)
}

func dedupe(in []Dep) []Dep {
	seen := make(map[Dep]bool, len(in))
	out := in[:0:0]
	for _, d := range in {
		if d.Name == "" || d.Version == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// FixedForPackage returns the fixed version for a LANGUAGE package (npm, PyPI, Go, ...), where the
// affected entry is keyed by ecosystem name rather than a distro release.
func (v Vuln) FixedForPackage(pkg string) string {
	for key, fixed := range v.Fixed {
		_, name, ok := strings.Cut(key, "|")
		if ok && strings.EqualFold(name, pkg) && fixed != "" {
			return fixed
		}
	}
	return ""
}
