// Package rules is the DB-backed detection-rule store (Wazuh-style management). Rules
// are Sigma YAML classified as single-event or aggregation; they are seeded from the
// bundled rules/ on first start and managed from the UI. The worker loads the enabled
// set and live-reloads on changes.
package rules

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"deuswatch/internal/detect/sigma"
	"deuswatch/packs"
)

// Rule is a stored detection rule.
type Rule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`     // single | aggregation
	Category  string    `json:"category"` // judi | deface | fim | endpoint | agg | general | custom
	YAML      string    `json:"yaml"`
	Enabled   bool      `json:"enabled"`
	Builtin   bool      `json:"builtin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store persists rules.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const cols = `id, name, kind, category, yaml, enabled, builtin, created_at, updated_at`

func scan(row pgx.Row) (*Rule, error) {
	var r Rule
	if err := row.Scan(&r.ID, &r.Name, &r.Kind, &r.Category, &r.YAML, &r.Enabled, &r.Builtin, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// titleOf extracts a Sigma rule's title for the default rule name.
func titleOf(yamlText, fallback string) string {
	var head struct {
		Title string `yaml:"title"`
	}
	if yaml.Unmarshal([]byte(yamlText), &head) == nil && head.Title != "" {
		return head.Title
	}
	return fallback
}

// List returns all rules ordered by name.
func (s *Store) List(ctx context.Context) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+cols+` FROM rules ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("rules: list: %w", err)
	}
	defer rows.Close()
	out := make([]Rule, 0, 32)
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// Create validates and inserts a custom rule.
func (s *Store) Create(ctx context.Context, name, yamlText string) (*Rule, error) {
	kind, err := sigma.Classify([]byte(yamlText))
	if err != nil {
		return nil, fmt.Errorf("rules: invalid rule: %w", err)
	}
	if name == "" {
		name = titleOf(yamlText, "rule")
	}
	return scan(s.pool.QueryRow(ctx,
		`INSERT INTO rules (name, kind, category, yaml, enabled, builtin) VALUES ($1,$2,'custom',$3,true,false) RETURNING `+cols,
		name, kind, yamlText))
}

// Update validates and replaces a rule's name/yaml/enabled (re-deriving its kind).
func (s *Store) Update(ctx context.Context, id, name, yamlText string, enabled bool) (*Rule, error) {
	kind, err := sigma.Classify([]byte(yamlText))
	if err != nil {
		return nil, fmt.Errorf("rules: invalid rule: %w", err)
	}
	if name == "" {
		name = titleOf(yamlText, "rule")
	}
	r, err := scan(s.pool.QueryRow(ctx,
		`UPDATE rules SET name=$1, kind=$2, yaml=$3, enabled=$4, updated_at=now() WHERE id=$5 RETURNING `+cols,
		name, kind, yamlText, enabled, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("rules: not found")
	}
	return r, err
}

// ── Rule packs (a lightweight marketplace over the bundled rules) ───────────
//
// A "pack" is a curated group of detection rules. Installed packs map 1:1 to the rule
// CATEGORY already stored per rule, so enabling/disabling a pack toggles the real rules that
// ship with DeusWatch - no fake buttons. The catalog also lists real-world third-party
// rulesets you can bring in (SigmaHQ, ET Open, OWASP CRS, …) as link-outs.

// Pack is one entry in the marketplace.
type Pack struct {
	ID          string `json:"id"` // category key (installed) or catalog id (external)
	Name        string `json:"name"`
	Description string `json:"description"`
	Source      string `json:"source"` // "DeusWatch core" | vendor
	RuleCount   int    `json:"rule_count"`
	Enabled     int    `json:"enabled"`   // enabled rules within the pack
	Installed   bool   `json:"installed"` // true = present in the DB and toggleable
	// Installable = a bundled curated pack that Install imports with one click (no network).
	// Set on catalog entries that are not installed yet, and on installed ones so the UI can
	// offer Uninstall (a core category is never uninstallable).
	Installable bool   `json:"installable,omitempty"`
	URL         string `json:"url,omitempty"` // upstream link for external packs
}

// packMeta gives each rule category a human name, description and source for the UI.
var packMeta = map[string]struct{ Name, Desc, Source string }{
	"web-attack": {"Web Attacks", "SQLi, XSS, path traversal, scanners and webshell activity in web / proxy logs.", "DeusWatch core"},
	"deface":     {"Web Defacement", "Defacement markers and unauthorized content changes on web roots.", "DeusWatch core"},
	"fim":        {"File Integrity (FIM)", "Changes to sensitive files and web roots (integrity monitoring).", "DeusWatch core"},
	"endpoint":   {"Linux Endpoint (ATT&CK)", "Persistence, privilege-escalation and living-off-the-land on Linux hosts.", "DeusWatch core"},
	"windows":    {"Windows Security", "Logon abuse, account lockout and suspicious Windows authentication.", "DeusWatch core"},
	"auth":       {"Authentication & Brute-force", "SSH / login brute-force, invalid users and root logins.", "DeusWatch core"},
	"judi":       {"Illegal Gambling (ID)", "Indonesian illegal online-gambling ('judi online') indicators in web traffic.", "DeusWatch core"},
	"agg":        {"Correlation", "Multi-event correlation: port scans, brute-force bursts, password spraying.", "DeusWatch core"},
	"general":    {"General", "Miscellaneous baseline detections.", "DeusWatch core"},
	"custom":     {"Custom (yours)", "Rules you created or imported.", "You"},
}

// packOrder controls how installed packs are listed (known ones first, in this order).
var packOrder = []string{"web-attack", "deface", "fim", "endpoint", "windows", "auth", "judi", "agg", "general", "custom"}

// externalPacks is the catalog of real-world third-party rulesets. These are informational
// link-outs (bring-your-own via rule import / the matching sensor input) - honestly not
// one-click installs yet - so the marketplace shows the wider ecosystem without faking it.
var externalPacks = []Pack{
	{ID: "sigmahq", Name: "SigmaHQ Community Rules", Description: "Thousands of community detections in Sigma format — import the ones you need as YAML in New rule.", Source: "SigmaHQ", URL: "https://github.com/SigmaHQ/sigma"},
	{ID: "sysmon-modular", Name: "Sysmon-modular (Windows)", Description: "Olaf Hartong's Sysmon config + mapped Windows telemetry detections.", Source: "olafhartong", URL: "https://github.com/olafhartong/sysmon-modular"},
	{ID: "et-open", Name: "Emerging Threats Open (IDS)", Description: "Suricata / Snort IDS ruleset — pair it with the Suricata sensor input.", Source: "Proofpoint ET", URL: "https://rules.emergingthreats.net/"},
	{ID: "owasp-crs", Name: "OWASP Core Rule Set (WAF)", Description: "ModSecurity WAF ruleset. Run it inline; DeusWatch ingests its alerts and bans the source IP.", Source: "OWASP", URL: "https://coreruleset.org/"},
	{ID: "yara-forge", Name: "YARA Forge", Description: "Aggregated YARA rules for malware file scanning (roadmap: YARA on FIM-changed files).", Source: "YARA-HQ", URL: "https://yarahq.github.io/"},
	{ID: "mitre-attack", Name: "MITRE ATT&CK", Description: "The technique knowledge base DeusWatch rules map to (threat.technique.*).", Source: "MITRE", URL: "https://attack.mitre.org/"},
}

// Packs returns the installed packs (from rule categories, with counts) followed by the
// external catalog.
func (s *Store) Packs(ctx context.Context) ([]Pack, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT COALESCE(NULLIF(category,''),'general') AS cat,
		        count(*),
		        count(*) FILTER (WHERE enabled)
		 FROM rules GROUP BY cat`)
	if err != nil {
		return nil, fmt.Errorf("rules: packs: %w", err)
	}
	defer rows.Close()
	byCat := map[string]Pack{}
	for rows.Next() {
		var cat string
		var total, enabled int
		if err := rows.Scan(&cat, &total, &enabled); err != nil {
			return nil, err
		}
		m, ok := packMeta[cat]
		name, desc, source := m.Name, m.Desc, m.Source
		if !ok {
			name = cat
			source = "DeusWatch core"
		}
		p := Pack{ID: cat, Name: name, Description: desc, Source: source, RuleCount: total, Enabled: enabled, Installed: true}
		// A category that came from the bundled catalog stays uninstallable-safe: mark it so the
		// UI can offer Uninstall (core categories never get that button).
		if cp, isCurated := packs.Find(cat); isCurated {
			p.Name, p.Description, p.Source, p.Installable = cp.Name, cp.Desc, "DeusWatch pack", true
		}
		byCat[cat] = p
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Known categories first (in packOrder), then any extras alphabetically.
	out := make([]Pack, 0, len(byCat)+len(packs.Catalog)+len(externalPacks))
	seen := map[string]bool{}
	for _, cat := range packOrder {
		if p, ok := byCat[cat]; ok {
			out = append(out, p)
			seen[cat] = true
		}
	}
	extras := make([]string, 0)
	for cat := range byCat {
		if !seen[cat] {
			extras = append(extras, cat)
		}
	}
	sort.Strings(extras)
	for _, cat := range extras {
		out = append(out, byCat[cat])
	}
	// Bundled curated packs that are NOT installed yet -> one-click installable entries.
	for _, cp := range packs.Catalog {
		if _, already := byCat[cp.ID]; already {
			continue
		}
		n := 0
		if files, ferr := packs.Rules(cp.ID); ferr == nil {
			n = len(files)
		}
		out = append(out, Pack{
			ID: cp.ID, Name: cp.Name, Description: cp.Desc, Source: "DeusWatch pack",
			RuleCount: n, Installable: true,
		})
	}
	return append(out, externalPacks...), nil
}

// InstallPack imports a bundled curated pack's rules into the DB (category = pack id) and
// enables them — the one-click "Install". Rules already present (matched by name) are skipped,
// so re-installing is safe and never duplicates. Returns how many were added.
func (s *Store) InstallPack(ctx context.Context, id string) (int, error) {
	p, ok := packs.Find(id)
	if !ok {
		return 0, fmt.Errorf("rules: unknown pack %q", id)
	}
	files, err := packs.Rules(p.ID)
	if err != nil {
		return 0, err
	}
	added := 0
	for fname, data := range files {
		kind, cerr := sigma.Classify(data)
		if cerr != nil {
			// A pack rule that doesn't parse is a packaging bug — skip it rather than fail the
			// whole install, but say so.
			return added, fmt.Errorf("rules: pack %q: %s: %w", id, fname, cerr)
		}
		name := titleOf(string(data), fname)
		var exists bool
		if qerr := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rules WHERE name=$1)`, name).Scan(&exists); qerr != nil {
			return added, qerr
		}
		if exists {
			continue
		}
		if _, ierr := s.pool.Exec(ctx,
			`INSERT INTO rules (name, kind, category, yaml, enabled, builtin) VALUES ($1,$2,$3,$4,true,true)`,
			name, kind, p.ID, string(data)); ierr == nil {
			added++
		}
	}
	return added, nil
}

// UninstallPack removes an installed curated pack's rules. Only packs from the bundled catalog
// can be uninstalled this way, so a core category (fim/auth/…) can never be wiped by mistake.
func (s *Store) UninstallPack(ctx context.Context, id string) (int64, error) {
	if _, ok := packs.Find(id); !ok {
		return 0, fmt.Errorf("rules: %q is not an installable pack", id)
	}
	ct, err := s.pool.Exec(ctx, `DELETE FROM rules WHERE category=$1`, id)
	if err != nil {
		return 0, fmt.Errorf("rules: uninstall pack: %w", err)
	}
	return ct.RowsAffected(), nil
}

// SetEnabledByCategory toggles every rule in a pack (category) on/off at once. Returns how
// many rules changed; 0 means the id was not an installed pack.
func (s *Store) SetEnabledByCategory(ctx context.Context, category string, enabled bool) (int64, error) {
	ct, err := s.pool.Exec(ctx,
		`UPDATE rules SET enabled=$1, updated_at=now()
		 WHERE COALESCE(NULLIF(category,''),'general')=$2`, enabled, category)
	if err != nil {
		return 0, fmt.Errorf("rules: set pack enabled: %w", err)
	}
	return ct.RowsAffected(), nil
}

// SetEnabled toggles a rule on/off.
func (s *Store) SetEnabled(ctx context.Context, id string, enabled bool) error {
	ct, err := s.pool.Exec(ctx, `UPDATE rules SET enabled=$1, updated_at=now() WHERE id=$2`, enabled, id)
	if err != nil {
		return fmt.Errorf("rules: set enabled: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("rules: not found")
	}
	return nil
}

// Delete removes a rule.
func (s *Store) Delete(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM rules WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("rules: delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("rules: not found")
	}
	return nil
}

// SeedFromDir inserts the on-disk rules as builtins when the table is empty (first run).
func (s *Store) SeedFromDir(ctx context.Context, dir string) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM rules`).Scan(&n); err != nil {
		return 0, fmt.Errorf("rules: count: %w", err)
	}
	if n > 0 {
		return 0, nil
	}
	seeded := 0
	for _, f := range gather(dir) {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		kind, err := sigma.Classify(data)
		if err != nil {
			continue // skip anything that doesn't parse
		}
		name := titleOf(string(data), filepath.Base(f.path))
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO rules (name, kind, category, yaml, enabled, builtin) VALUES ($1,$2,$3,$4,true,true)`,
			name, kind, f.category, string(data)); err == nil {
			seeded++
		}
	}
	return seeded, nil
}

// SyncBuiltinsFromDir inserts on-disk rules that are not already present (matched by name),
// so new bundled rules from an upgrade are picked up without disturbing existing or
// user-edited rules. It also backfills the category of existing builtins that don't have one
// yet (from an upgrade that predates categories). Returns how many were added. Note: a builtin
// the operator deliberately deleted may be re-added on a later upgrade.
func (s *Store) SyncBuiltinsFromDir(ctx context.Context, dir string) (int, error) {
	added := 0
	for _, f := range gather(dir) {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		kind, err := sigma.Classify(data)
		if err != nil {
			continue
		}
		name := titleOf(string(data), filepath.Base(f.path))
		var id, category string
		err = s.pool.QueryRow(ctx, `SELECT id, category FROM rules WHERE name=$1`, name).Scan(&id, &category)
		if err == nil {
			// Already present — backfill its category if it predates this feature.
			if category == "" && f.category != "" {
				_, _ = s.pool.Exec(ctx, `UPDATE rules SET category=$1 WHERE id=$2`, f.category, id)
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			continue // a real error — skip this file
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO rules (name, kind, category, yaml, enabled, builtin) VALUES ($1,$2,$3,$4,true,true)`,
			name, kind, f.category, string(data)); err == nil {
			added++
		}
	}
	return added, nil
}

// Enabled parses the enabled rules into detector inputs (single-event Ruleset + agg rules).
func (s *Store) Enabled(ctx context.Context) (sigma.Ruleset, []*sigma.AggRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT kind, yaml FROM rules WHERE enabled ORDER BY name`)
	if err != nil {
		return nil, nil, fmt.Errorf("rules: enabled: %w", err)
	}
	defer rows.Close()
	var single sigma.Ruleset
	var agg []*sigma.AggRule
	for rows.Next() {
		var kind, y string
		if err := rows.Scan(&kind, &y); err != nil {
			return nil, nil, err
		}
		if kind == sigma.KindAggregation {
			if r, err := sigma.ParseAggRule([]byte(y)); err == nil {
				agg = append(agg, r)
			}
		} else if r, err := sigma.ParseRule([]byte(y)); err == nil {
			single = append(single, r)
		}
	}
	return single, agg, rows.Err()
}

// ruleFile is one on-disk rule with the category derived from its folder.
type ruleFile struct {
	path     string
	category string // subfolder name (judi/deface/...); "general" for a root-level rule
}

// gather collects *.yml/*.yaml in dir and one level of subdirectories, tagging each with
// the category (its subfolder name; root-level rules get "general").
func gather(dir string) []ruleFile {
	var out []ruleFile
	for _, pat := range []string{"*.yml", "*.yaml"} {
		if m, err := filepath.Glob(filepath.Join(dir, pat)); err == nil {
			for _, f := range m {
				out = append(out, ruleFile{path: f, category: "general"})
			}
		}
		if sub, err := filepath.Glob(filepath.Join(dir, "*", pat)); err == nil {
			for _, f := range sub {
				out = append(out, ruleFile{path: f, category: filepath.Base(filepath.Dir(f))})
			}
		}
	}
	return out
}
