package store

import (
	"context"
	"fmt"
	"time"
)

// FIMSnapshot is one dated version of a watched file (ADR 0002). Content is never returned by
// the timeline queries — only metadata — so listing a file's history stays cheap.
type FIMSnapshot struct {
	ID         int64     `json:"id"`
	AgentName  string    `json:"agent_name"`
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	Storage    string    `json:"storage"` // agent | manager
	Trigger    string    `json:"trigger"` // on_change | scheduled
	CapturedAt time.Time `json:"captured_at"`
}

// FIMSnapshotPath summarizes one watched file that has snapshots (for the browser list).
type FIMSnapshotPath struct {
	Path     string    `json:"path"`
	Versions int       `json:"versions"`
	Latest   time.Time `json:"latest"`
}

// RecordSnapshot inserts a version, de-duplicating a metadata upload that repeats the file's
// current latest hash (so re-reporting the same content is a no-op). content may be nil for
// agent-local storage. Returns created=false when the latest version already had this hash.
func (s *Store) RecordSnapshot(ctx context.Context, snap FIMSnapshot, content []byte) (created bool, err error) {
	if snap.AgentName == "" || snap.Path == "" || snap.SHA256 == "" {
		return false, fmt.Errorf("store: snapshot needs agent, path and sha256")
	}
	if snap.Storage == "" {
		snap.Storage = "agent"
	}
	if snap.Trigger == "" {
		snap.Trigger = "on_change"
	}
	var latest string
	err = s.pool.QueryRow(ctx,
		`SELECT sha256 FROM fim_snapshots WHERE agent_name=$1 AND path=$2 ORDER BY captured_at DESC LIMIT 1`,
		snap.AgentName, snap.Path).Scan(&latest)
	if err == nil && latest == snap.SHA256 {
		return false, nil // unchanged since the last version — skip
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO fim_snapshots (agent_name, path, sha256, size, storage, trigger, content)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		snap.AgentName, snap.Path, snap.SHA256, snap.Size, snap.Storage, snap.Trigger, content); err != nil {
		return false, fmt.Errorf("store: record snapshot: %w", err)
	}
	return true, nil
}

// ListSnapshotPaths returns the watched files that have snapshots for an agent, newest first.
func (s *Store) ListSnapshotPaths(ctx context.Context, agentName string) ([]FIMSnapshotPath, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT path, count(*) AS versions, max(captured_at) AS latest
		FROM fim_snapshots WHERE agent_name=$1
		GROUP BY path ORDER BY latest DESC`, agentName)
	if err != nil {
		return nil, fmt.Errorf("store: list snapshot paths: %w", err)
	}
	defer rows.Close()
	out := make([]FIMSnapshotPath, 0, 32)
	for rows.Next() {
		var p FIMSnapshotPath
		if err := rows.Scan(&p.Path, &p.Versions, &p.Latest); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListSnapshots returns the version timeline for one file (agent + path), newest first.
func (s *Store) ListSnapshots(ctx context.Context, agentName, path string, limit int) ([]FIMSnapshot, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_name, path, sha256, size, storage, trigger, captured_at
		FROM fim_snapshots WHERE agent_name=$1 AND path=$2
		ORDER BY captured_at DESC LIMIT $3`, agentName, path, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list snapshots: %w", err)
	}
	defer rows.Close()
	out := make([]FIMSnapshot, 0, limit)
	for rows.Next() {
		var v FIMSnapshot
		if err := rows.Scan(&v.ID, &v.AgentName, &v.Path, &v.SHA256, &v.Size, &v.Storage, &v.Trigger, &v.CapturedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// PruneSnapshots enforces per-file retention: keeps the newest keepVersions rows per (agent,path)
// and deletes older ones. keepVersions <= 0 disables pruning. Returns the number deleted.
func (s *Store) PruneSnapshots(ctx context.Context, agentName, path string, keepVersions int) (int64, error) {
	if keepVersions <= 0 {
		return 0, nil
	}
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM fim_snapshots
		WHERE agent_name=$1 AND path=$2 AND id NOT IN (
		  SELECT id FROM fim_snapshots WHERE agent_name=$1 AND path=$2
		  ORDER BY captured_at DESC LIMIT $3)`,
		agentName, path, keepVersions)
	if err != nil {
		return 0, fmt.Errorf("store: prune snapshots: %w", err)
	}
	return ct.RowsAffected(), nil
}
