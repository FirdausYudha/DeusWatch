package store

import (
	"context"
	"fmt"
)

// RequestRestore records an operator's request to restore a file to its known-good snapshot
// on a specific agent. Deduplicated: an already-pending request for the same agent+path is
// left as-is.
func (s *Store) RequestRestore(ctx context.Context, agentName, path, requestedBy string) error {
	if agentName == "" || path == "" {
		return fmt.Errorf("store: restore needs agent and path")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO file_restores (agent_name, path, requested_by)
		SELECT $1, $2, $3
		WHERE NOT EXISTS (
		  SELECT 1 FROM file_restores WHERE agent_name=$1 AND path=$2 AND status='requested')`,
		agentName, path, requestedBy)
	if err != nil {
		return fmt.Errorf("store: request restore: %w", err)
	}
	return nil
}

// PendingRestores returns the file paths the agent should restore, and marks them delivered
// (one-shot) so the agent applies each request once. Called by the gateway's restore feed.
func (s *Store) PendingRestores(ctx context.Context, agentName string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE file_restores SET status='delivered', delivered_at=now()
		WHERE id IN (SELECT id FROM file_restores WHERE agent_name=$1 AND status='requested')
		RETURNING path`, agentName)
	if err != nil {
		return nil, fmt.Errorf("store: pending restores: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
