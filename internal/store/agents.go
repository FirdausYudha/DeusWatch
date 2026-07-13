package store

import (
	"context"
	"fmt"
	"time"

	"deuswatch/internal/selfhealth"
)

// AgentHealthRows returns the health snapshot of every non-revoked agent for the
// worker's self-monitoring checker (design doc section 13).
func (s *Store) AgentHealthRows(ctx context.Context) ([]selfhealth.AgentHealth, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, COALESCE(os,''), last_seen_at, status, health_degraded, health_detail
		 FROM agents WHERE NOT revoked`)
	if err != nil {
		return nil, fmt.Errorf("store: agent health rows: %w", err)
	}
	defer rows.Close()
	var out []selfhealth.AgentHealth
	for rows.Next() {
		var a selfhealth.AgentHealth
		if err := rows.Scan(&a.ID, &a.Name, &a.OS, &a.LastSeen, &a.Status, &a.Degraded, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAgentStatus persists a status computed by the health checker.
func (s *Store) SetAgentStatus(ctx context.Context, id, status string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agents SET status = $2 WHERE id = $1`, id, status)
	return err
}

// OldestEventChunk returns the oldest events-hypertable chunk's end time and the total
// chunk count (nil end when the hypertable has no chunks / TimescaleDB is absent).
func (s *Store) OldestEventChunk(ctx context.Context) (end *time.Time, count int, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT min(range_end), count(*) FROM timescaledb_information.chunks
		 WHERE hypertable_name = 'events'`).Scan(&end, &count)
	if err != nil {
		return nil, 0, fmt.Errorf("store: oldest chunk: %w", err)
	}
	return end, count, nil
}

// DropEventChunksBefore drops all events chunks that end at/before `before` (an instant
// chunk drop - no row-by-row delete) and returns how many were dropped. Used by the
// disk-watermark janitor; retention policies handle the normal aging path.
func (s *Store) DropEventChunksBefore(ctx context.Context, before time.Time) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT drop_chunks('events', older_than => $1::timestamptz)`, before)
	if err != nil {
		return 0, fmt.Errorf("store: drop chunks: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
}
