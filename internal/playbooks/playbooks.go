// Package playbooks is the DB-backed catalog of remediation playbooks (design doc
// section 9): each detection label (deuswatch.label) maps to a static list of
// remediation steps. The worker stamps the matching playbook onto every fired alert
// (deuswatch.remediation.*) - deterministic, <1ms, no cost, fully auditable - and the
// analyst sees WHAT TO DO next to the alert itself. Seeded from the bundled
// rules/playbooks/ dir on first start (builtin=true) and managed from the UI; the
// worker live-reloads the enabled set.
package playbooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"deuswatch/internal/ingest"
)

// Spec is the operator-editable part of a playbook.
type Spec struct {
	Label string   `json:"label" yaml:"label"` // deuswatch.label this playbook applies to
	Name  string   `json:"name" yaml:"name"`   // human title, e.g. "SSH Brute Force response"
	Steps []string `json:"steps" yaml:"steps"` // ordered remediation steps
}

// Validate enforces the invariants the UI editor and the seed path both rely on.
func Validate(sp Spec) error {
	label := strings.TrimSpace(sp.Label)
	if label == "" {
		return errors.New("playbooks: label is required (the deuswatch.label the playbook applies to)")
	}
	if strings.ContainsAny(label, " \t\n") {
		return errors.New("playbooks: label must be a single token (e.g. bruteforce, credential_access)")
	}
	if len(sp.Steps) == 0 {
		return errors.New("playbooks: at least one step is required")
	}
	if len(sp.Steps) > 20 {
		return errors.New("playbooks: at most 20 steps (keep it actionable)")
	}
	for i, st := range sp.Steps {
		if strings.TrimSpace(st) == "" {
			return fmt.Errorf("playbooks: step %d is empty", i+1)
		}
		if len(st) > 500 {
			return fmt.Errorf("playbooks: step %d is too long (max 500 chars)", i+1)
		}
	}
	return nil
}

// normalize trims fields and defaults the name to the label.
func normalize(sp Spec) Spec {
	sp.Label = strings.ToLower(strings.TrimSpace(sp.Label))
	sp.Name = strings.TrimSpace(sp.Name)
	if sp.Name == "" {
		sp.Name = sp.Label
	}
	steps := make([]string, 0, len(sp.Steps))
	for _, st := range sp.Steps {
		if st = strings.TrimSpace(st); st != "" {
			steps = append(steps, st)
		}
	}
	sp.Steps = steps
	return sp
}

// Playbook is a stored playbook row (Spec + management metadata).
type Playbook struct {
	ID string `json:"id"`
	Spec
	Enabled   bool      `json:"enabled"`
	Builtin   bool      `json:"builtin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store persists playbooks.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const cols = `id, label, name, steps, enabled, builtin, created_at, updated_at`

func scan(row pgx.Row) (*Playbook, error) {
	var p Playbook
	if err := row.Scan(&p.ID, &p.Label, &p.Name, &p.Steps, &p.Enabled, &p.Builtin,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// List returns all playbooks ordered by label.
func (s *Store) List(ctx context.Context) ([]Playbook, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+cols+` FROM playbooks ORDER BY label`)
	if err != nil {
		return nil, fmt.Errorf("playbooks: list: %w", err)
	}
	defer rows.Close()
	out := make([]Playbook, 0, 16)
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// Create validates and inserts a custom playbook (one per label).
func (s *Store) Create(ctx context.Context, sp Spec) (*Playbook, error) {
	sp = normalize(sp)
	if err := Validate(sp); err != nil {
		return nil, err
	}
	p, err := scan(s.pool.QueryRow(ctx,
		`INSERT INTO playbooks (label, name, steps, enabled, builtin)
		 VALUES ($1,$2,$3,true,false) RETURNING `+cols,
		sp.Label, sp.Name, sp.Steps))
	if err != nil && strings.Contains(err.Error(), "duplicate") {
		return nil, fmt.Errorf("playbooks: a playbook for label %q already exists (edit it instead)", sp.Label)
	}
	return p, err
}

// Update validates and replaces a playbook.
func (s *Store) Update(ctx context.Context, id string, sp Spec, enabled bool) (*Playbook, error) {
	sp = normalize(sp)
	if err := Validate(sp); err != nil {
		return nil, err
	}
	p, err := scan(s.pool.QueryRow(ctx,
		`UPDATE playbooks SET label=$1, name=$2, steps=$3, enabled=$4, updated_at=now()
		 WHERE id=$5 RETURNING `+cols,
		sp.Label, sp.Name, sp.Steps, enabled, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("playbooks: not found")
	}
	return p, err
}

// Delete removes a playbook.
func (s *Store) Delete(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM playbooks WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("playbooks: delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("playbooks: not found")
	}
	return nil
}

// EnabledByLabel returns the enabled playbooks keyed by label (for the worker).
func (s *Store) EnabledByLabel(ctx context.Context) (map[string]Spec, error) {
	rows, err := s.pool.Query(ctx, `SELECT label, name, steps FROM playbooks WHERE enabled`)
	if err != nil {
		return nil, fmt.Errorf("playbooks: enabled: %w", err)
	}
	defer rows.Close()
	out := map[string]Spec{}
	for rows.Next() {
		var sp Spec
		if err := rows.Scan(&sp.Label, &sp.Name, &sp.Steps); err != nil {
			return nil, err
		}
		out[sp.Label] = sp
	}
	return out, rows.Err()
}

// SyncBuiltinsFromDir inserts bundled playbooks (by label) that are not already present,
// so new ones from an upgrade appear without disturbing operator edits.
func (s *Store) SyncBuiltinsFromDir(ctx context.Context, dir string) (int, error) {
	added := 0
	for _, sp := range readSpecs(dir) {
		sp = normalize(sp)
		if Validate(sp) != nil {
			continue
		}
		var id string
		err := s.pool.QueryRow(ctx, `SELECT id FROM playbooks WHERE label=$1`, sp.Label).Scan(&id)
		if err == nil {
			continue // already present (possibly operator-edited) — leave it alone
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO playbooks (label, name, steps, enabled, builtin) VALUES ($1,$2,$3,true,true)`,
			sp.Label, sp.Name, sp.Steps); err == nil {
			added++
		}
	}
	return added, nil
}

// readSpecs reads playbook specs from *.yml/*.yaml in dir (non-recursive), skipping bad files.
func readSpecs(dir string) []Spec {
	var out []Spec
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, f := range m {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var sp Spec
			if yaml.Unmarshal(data, &sp) == nil {
				out = append(out, sp)
			}
		}
	}
	return out
}

// ── Live catalog (worker side) ─────────────────────────────

// Live is the worker's in-memory view of the enabled playbooks, safe for concurrent
// use and refreshed by the live-reload loop.
type Live struct {
	mu      sync.RWMutex
	byLabel map[string]Spec
}

func NewLive() *Live { return &Live{byLabel: map[string]Spec{}} }

// Reload swaps in the current enabled set from the store.
func (l *Live) Reload(ctx context.Context, s *Store) error {
	m, err := s.EnabledByLabel(ctx)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.byLabel = m
	l.mu.Unlock()
	return nil
}

// Len returns the number of loaded playbooks (for startup logging).
func (l *Live) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.byLabel)
}

// Annotate stamps the matching playbook onto an alert as its remediation
// recommendation. It never overwrites a recommendation that is already present
// (e.g. one set by the LLM or the response engine) and is a no-op for events
// without a label or without a matching playbook.
func (l *Live) Annotate(e *ingest.Event) {
	if e == nil || e.DeusWatch.Label == "" || e.DeusWatch.Remediation.Action != "" {
		return
	}
	l.mu.RLock()
	sp, ok := l.byLabel[e.DeusWatch.Label]
	l.mu.RUnlock()
	if !ok {
		return
	}
	e.DeusWatch.Remediation = ingest.Remediation{
		Action: FormatSteps(sp),
		Source: ingest.RemediationPlaybook,
		Status: ingest.RemediationRecommended,
	}
}

// FormatSteps renders a playbook as the numbered text stored in
// deuswatch.remediation.action (one step per line).
func FormatSteps(sp Spec) string {
	var b strings.Builder
	for i, st := range sp.Steps {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%d. %s", i+1, st)
	}
	return b.String()
}
