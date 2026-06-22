package respond

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store maps response_actions to Postgres. It satisfies ActionStore.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Insert stores a new action (initial status) and returns its id.
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

// Offenses counts how many times this IP has ALREADY been blocked (status executed) —
// used for the progressive ban.
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

// Get fetches one action by id.
func (s *Store) Get(ctx context.Context, id string) (*Action, error) {
	a, err := scanAction(s.pool.QueryRow(ctx, `SELECT `+actionCols+` FROM response_actions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("respond: action not found")
	}
	if err != nil {
		return nil, fmt.Errorf("respond: get: %w", err)
	}
	return a, nil
}

// SetStatus changes the status + records the decision (approve/dismiss).
func (s *Store) SetStatus(ctx context.Context, id string, status Status, decidedBy string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE response_actions SET status = $2, decided_by = $3, decided_at = now() WHERE id = $1`,
		id, string(status), strOrNil(decidedBy))
	if err != nil {
		return fmt.Errorf("respond: set status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("respond: action not found")
	}
	return nil
}

// SetExecuted records the execution result: executed if execErr is nil, otherwise failed.
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

// List returns the most recent actions; if status != "" only that status.
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

// ActiveBlocks returns the source IPs that should currently be blocked: approved or
// executed block actions whose ban window has not expired (ban_seconds = 0 = permanent).
// Used to feed agent-side firewalls.
func (s *Store) ActiveBlocks(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT host(source_ip) FROM response_actions
		WHERE action = 'block' AND status IN ('approved','executed')
		  AND (ban_seconds = 0
		       OR COALESCE(executed_at, decided_at, created_at) + make_interval(secs => ban_seconds) > now())`)
	if err != nil {
		return nil, fmt.Errorf("respond: active blocks: %w", err)
	}
	defer rows.Close()
	out := make([]string, 0, 32)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
