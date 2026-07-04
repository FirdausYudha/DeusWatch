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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"deuswatch/internal/detect/sigma"
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
