// Package decoders is the DB-backed store for custom, data-driven log decoders (the DeusWatch
// equivalent of Wazuh decoders). A decoder matches a dataset's raw lines with a Go RE2 regex and
// maps named capture groups into DCS fields. Decoders are seeded from the bundled decoders/ dir
// on first start (builtin=true) and managed from the UI; the gateway loads the enabled set and
// live-reloads on changes.
package decoders

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

	"deuswatch/internal/ingest"
)

// Decoder is a stored decoder row (DecoderSpec + management metadata).
type Decoder struct {
	ID string `json:"id"`
	ingest.DecoderSpec
	Enabled   bool      `json:"enabled"`
	Builtin   bool      `json:"builtin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store persists decoders.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const cols = `id, name, dataset, category, action, outcome, level, regex, enabled, builtin, created_at, updated_at`

func scan(row pgx.Row) (*Decoder, error) {
	var d Decoder
	if err := row.Scan(&d.ID, &d.Name, &d.Dataset, &d.Category, &d.Action, &d.Outcome, &d.Level,
		&d.Regex, &d.Enabled, &d.Builtin, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return nil, err
	}
	return &d, nil
}

// List returns all decoders ordered by dataset then name.
func (s *Store) List(ctx context.Context) ([]Decoder, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+cols+` FROM decoders ORDER BY dataset, name`)
	if err != nil {
		return nil, fmt.Errorf("decoders: list: %w", err)
	}
	defer rows.Close()
	out := make([]Decoder, 0, 16)
	for rows.Next() {
		d, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// Create validates and inserts a custom decoder.
func (s *Store) Create(ctx context.Context, sp ingest.DecoderSpec) (*Decoder, error) {
	if err := ingest.ValidateDecoder(sp); err != nil {
		return nil, fmt.Errorf("decoders: invalid decoder: %w", err)
	}
	if sp.Name == "" {
		sp.Name = sp.Dataset
	}
	return scan(s.pool.QueryRow(ctx,
		`INSERT INTO decoders (name, dataset, category, action, outcome, level, regex, enabled, builtin)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,true,false) RETURNING `+cols,
		sp.Name, sp.Dataset, sp.Category, sp.Action, sp.Outcome, sp.Level, sp.Regex))
}

// Update validates and replaces a decoder.
func (s *Store) Update(ctx context.Context, id string, sp ingest.DecoderSpec, enabled bool) (*Decoder, error) {
	if err := ingest.ValidateDecoder(sp); err != nil {
		return nil, fmt.Errorf("decoders: invalid decoder: %w", err)
	}
	if sp.Name == "" {
		sp.Name = sp.Dataset
	}
	d, err := scan(s.pool.QueryRow(ctx,
		`UPDATE decoders SET name=$1, dataset=$2, category=$3, action=$4, outcome=$5, level=$6,
		 regex=$7, enabled=$8, updated_at=now() WHERE id=$9 RETURNING `+cols,
		sp.Name, sp.Dataset, sp.Category, sp.Action, sp.Outcome, sp.Level, sp.Regex, enabled, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("decoders: not found")
	}
	return d, err
}

// SetEnabled toggles a decoder on/off.
func (s *Store) SetEnabled(ctx context.Context, id string, enabled bool) error {
	ct, err := s.pool.Exec(ctx, `UPDATE decoders SET enabled=$1, updated_at=now() WHERE id=$2`, enabled, id)
	if err != nil {
		return fmt.Errorf("decoders: set enabled: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("decoders: not found")
	}
	return nil
}

// Delete removes a decoder.
func (s *Store) Delete(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM decoders WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("decoders: delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("decoders: not found")
	}
	return nil
}

// EnabledSet builds an ingest.DecoderSet from the enabled decoders (for the gateway).
func (s *Store) EnabledSet(ctx context.Context) (*ingest.DecoderSet, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT name, dataset, category, action, outcome, level, regex FROM decoders WHERE enabled`)
	if err != nil {
		return nil, fmt.Errorf("decoders: enabled: %w", err)
	}
	defer rows.Close()
	var specs []ingest.DecoderSpec
	for rows.Next() {
		var sp ingest.DecoderSpec
		if err := rows.Scan(&sp.Name, &sp.Dataset, &sp.Category, &sp.Action, &sp.Outcome, &sp.Level, &sp.Regex); err != nil {
			return nil, err
		}
		specs = append(specs, sp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ingest.BuildDecoderSet(specs)
}

// SyncBuiltinsFromDir inserts bundled decoders (by name) that are not already present, so new
// examples from an upgrade appear without disturbing operator edits. Invalid files are skipped.
func (s *Store) SyncBuiltinsFromDir(ctx context.Context, dir string) (int, error) {
	added := 0
	for _, sp := range readSpecs(dir) {
		if ingest.ValidateDecoder(sp) != nil {
			continue
		}
		if sp.Name == "" {
			sp.Name = sp.Dataset
		}
		var id string
		err := s.pool.QueryRow(ctx, `SELECT id FROM decoders WHERE name=$1`, sp.Name).Scan(&id)
		if err == nil {
			continue // already present
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO decoders (name, dataset, category, action, outcome, level, regex, enabled, builtin)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,true,true)`,
			sp.Name, sp.Dataset, sp.Category, sp.Action, sp.Outcome, sp.Level, sp.Regex); err == nil {
			added++
		}
	}
	return added, nil
}

// readSpecs reads decoder specs from *.yml/*.yaml in dir (non-recursive), skipping bad files.
func readSpecs(dir string) []ingest.DecoderSpec {
	var out []ingest.DecoderSpec
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, f := range m {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var sp ingest.DecoderSpec
			if yaml.Unmarshal(data, &sp) == nil {
				out = append(out, sp)
			}
		}
	}
	return out
}
