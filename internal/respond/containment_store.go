package respond

// Postgres persistence for host containment (containment_actions). Part of *Store so it
// shares the pool with the IP-ban engine. The anti-double-containment guard is enforced by
// a partial unique index on agent_id WHERE status IN ('recommended','contained'), so the
// insert is atomic even under concurrent alerts for the same host.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const containCols = `id, created_at, agent_id, COALESCE(host_name,''), COALESCE(ip::text,''),
	COALESCE(reason,''), COALESCE(rule_id,''), timeout_seconds, status, auto,
	COALESCE(decided_by,''), contained_at, expires_at, released_at, COALESCE(error,'')`

func scanContainment(row pgx.Row) (*Containment, error) {
	var c Containment
	var status string
	if err := row.Scan(&c.ID, &c.CreatedAt, &c.AgentID, &c.HostName, &c.IP, &c.Reason,
		&c.RuleID, &c.TimeoutSeconds, &status, &c.Auto, &c.DecidedBy,
		&c.ContainedAt, &c.ExpiresAt, &c.ReleasedAt, &c.Error); err != nil {
		return nil, err
	}
	c.Status = ContainmentStatus(status)
	return &c, nil
}

// InsertContainment inserts a recommended containment, but only if the agent has no active
// (recommended/contained) record — the ON CONFLICT clause matches the partial unique index,
// so a concurrent second alert for the same host is skipped (created=false), not duplicated.
func (s *Store) InsertContainment(ctx context.Context, c *Containment) (string, bool, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO containment_actions
			(agent_id, host_name, ip, reason, rule_id, timeout_seconds, status, auto)
		VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8)
		ON CONFLICT (agent_id) WHERE status IN ('recommended','contained')
		DO NOTHING
		RETURNING id`,
		c.AgentID, strOrNil(c.HostName), ipOrNil(c.IP), strOrNil(c.Reason), strOrNil(c.RuleID),
		c.TimeoutSeconds, string(c.Status), c.Auto).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil // conflict — agent already has an open containment
	}
	if err != nil {
		return "", false, fmt.Errorf("respond: insert containment: %w", err)
	}
	return id, true, nil
}

// GetContainment fetches one record by id.
func (s *Store) GetContainment(ctx context.Context, id string) (*Containment, error) {
	c, err := scanContainment(s.pool.QueryRow(ctx, `SELECT `+containCols+` FROM containment_actions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("respond: containment not found")
	}
	if err != nil {
		return nil, fmt.Errorf("respond: get containment: %w", err)
	}
	return c, nil
}

// MarkContained flips a record to contained and stamps the (optional) expiry.
func (s *Store) MarkContained(ctx context.Context, id string, expiresAt *time.Time) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE containment_actions SET status = 'contained', contained_at = now(), expires_at = $2 WHERE id = $1`,
		id, expiresAt)
	if err != nil {
		return fmt.Errorf("respond: mark contained: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("respond: containment not found")
	}
	return nil
}

// SetContainmentStatus changes status + records who/when. released also stamps released_at.
func (s *Store) SetContainmentStatus(ctx context.Context, id string, status ContainmentStatus, by string) error {
	var releasedAt any
	if status == ContainReleased {
		releasedAt = time.Now()
	}
	ct, err := s.pool.Exec(ctx,
		`UPDATE containment_actions
		 SET status = $2, decided_by = $3, released_at = COALESCE($4, released_at) WHERE id = $1`,
		id, string(status), strOrNil(by), releasedAt)
	if err != nil {
		return fmt.Errorf("respond: set containment status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("respond: containment not found")
	}
	return nil
}

// SetContainmentError records a non-fatal error (e.g. the edge block failed).
func (s *Store) SetContainmentError(ctx context.Context, id, msg string) error {
	_, err := s.pool.Exec(ctx, `UPDATE containment_actions SET error = $2 WHERE id = $1`, id, strOrNil(msg))
	if err != nil {
		return fmt.Errorf("respond: set containment error: %w", err)
	}
	return nil
}

// ActiveContainmentByAgent returns the currently-contained record for an agent name (the
// gateway derives the agent's isolation directive from this), or nil when the agent is free.
func (s *Store) ActiveContainmentByAgent(ctx context.Context, agentName string) (*Containment, error) {
	c, err := scanContainment(s.pool.QueryRow(ctx,
		`SELECT `+containCols+` FROM containment_actions
		 WHERE agent_id = $1 AND status = 'contained' ORDER BY created_at DESC LIMIT 1`, agentName))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("respond: active containment: %w", err)
	}
	return c, nil
}

// ExpiredContained returns contained rows whose timeout has passed (for auto-release).
func (s *Store) ExpiredContained(ctx context.Context, now time.Time) ([]*Containment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+containCols+` FROM containment_actions
		 WHERE status = 'contained' AND expires_at IS NOT NULL AND expires_at < $1`, now)
	if err != nil {
		return nil, fmt.Errorf("respond: expired contained: %w", err)
	}
	defer rows.Close()
	var out []*Containment
	for rows.Next() {
		c, err := scanContainment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListContainments returns the most recent containment records; if status != "" only that one.
func (s *Store) ListContainments(ctx context.Context, status string, limit int) ([]Containment, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + containCols + ` FROM containment_actions`
	args := []any{}
	if status != "" {
		q += ` WHERE status = $1`
		args = append(args, status)
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d`, limit)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("respond: list containments: %w", err)
	}
	defer rows.Close()
	out := make([]Containment, 0, limit)
	for rows.Next() {
		c, err := scanContainment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ipOrNil returns nil for an empty IP so a nullable inet column stays NULL.
func ipOrNil(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}
