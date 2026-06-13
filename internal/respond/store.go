package respond

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store memetakan response_actions ke Postgres. Memenuhi ActionStore.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Insert menyimpan aksi baru (status awal) dan mengembalikan id-nya.
func (s *Store) Insert(ctx context.Context, a *Action) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO response_actions
			(source_ip, action, reason, rule_id, ban_seconds, offense_count, source, status)
		VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`,
		a.SourceIP, a.ActionType, strOrNil(a.Reason), strOrNil(a.RuleID),
		a.BanSeconds, a.OffenseCount, a.Source, string(a.Status)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("respond: insert: %w", err)
	}
	return id, nil
}

// Offenses menghitung berapa kali IP ini SUDAH diblok (status executed) — dipakai
// untuk ban progresif.
func (s *Store) Offenses(ctx context.Context, ip string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM response_actions WHERE source_ip = $1::inet AND status = 'executed'`, ip).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("respond: offenses: %w", err)
	}
	return n, nil
}

const actionCols = `id, created_at, host(source_ip), action, COALESCE(reason,''), COALESCE(rule_id,''),
	ban_seconds, offense_count, source, status, COALESCE(responder,''),
	COALESCE(decided_by,''), decided_at, executed_at, COALESCE(error,'')`

func scanAction(row pgx.Row) (*Action, error) {
	var a Action
	var status, action string
	if err := row.Scan(&a.ID, &a.CreatedAt, &a.SourceIP, &action, &a.Reason, &a.RuleID,
		&a.BanSeconds, &a.OffenseCount, &a.Source, &status, &a.Responder,
		&a.DecidedBy, &a.DecidedAt, &a.ExecutedAt, &a.Error); err != nil {
		return nil, err
	}
	a.ActionType, a.Status = action, Status(status)
	return &a, nil
}

// Get mengambil satu aksi berdasarkan id.
func (s *Store) Get(ctx context.Context, id string) (*Action, error) {
	a, err := scanAction(s.pool.QueryRow(ctx, `SELECT `+actionCols+` FROM response_actions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("respond: aksi tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("respond: get: %w", err)
	}
	return a, nil
}

// SetStatus mengubah status + pencatat keputusan (approve/dismiss).
func (s *Store) SetStatus(ctx context.Context, id string, status Status, decidedBy string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE response_actions SET status = $2, decided_by = $3, decided_at = now() WHERE id = $1`,
		id, string(status), strOrNil(decidedBy))
	if err != nil {
		return fmt.Errorf("respond: set status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("respond: aksi tidak ditemukan")
	}
	return nil
}

// SetExecuted menandai hasil eksekusi: executed bila execErr nil, selain itu failed.
func (s *Store) SetExecuted(ctx context.Context, id, responder string, execErr error) error {
	status, errMsg := StatusExecuted, ""
	if execErr != nil {
		status, errMsg = StatusFailed, execErr.Error()
	}
	var execAt any = time.Now()
	if execErr != nil {
		execAt = nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE response_actions SET status = $2, responder = $3, executed_at = $4, error = $5 WHERE id = $1`,
		id, string(status), strOrNil(responder), execAt, strOrNil(errMsg))
	if err != nil {
		return fmt.Errorf("respond: set executed: %w", err)
	}
	return nil
}

// List mengembalikan aksi terbaru; bila status != "" hanya status itu.
func (s *Store) List(ctx context.Context, status string, limit int) ([]Action, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + actionCols + ` FROM response_actions`
	args := []any{}
	if status != "" {
		q += ` WHERE status = $1`
		args = append(args, status)
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d`, limit)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("respond: list: %w", err)
	}
	defer rows.Close()
	out := make([]Action, 0, 32)
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
