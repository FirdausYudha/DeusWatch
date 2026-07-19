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
	Trigger    string    `json:"trigger"` // on_change | scheduled | manual
	Diff       string    `json:"diff,omitempty"` // unified diff vs the previous captured version
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
	var diff *string
	if snap.Diff != "" {
		diff = &snap.Diff
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO fim_snapshots (agent_name, path, sha256, size, storage, trigger, diff, content)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		snap.AgentName, snap.Path, snap.SHA256, snap.Size, snap.Storage, snap.Trigger, diff, content); err != nil {
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
		SELECT id, agent_name, path, sha256, size, storage, trigger, COALESCE(diff,''), captured_at
		FROM fim_snapshots WHERE agent_name=$1 AND path=$2
		ORDER BY captured_at DESC LIMIT $3`, agentName, path, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list snapshots: %w", err)
	}
	defer rows.Close()
	out := make([]FIMSnapshot, 0, limit)
	for rows.Next() {
		var v FIMSnapshot
		if err := rows.Scan(&v.ID, &v.AgentName, &v.Path, &v.SHA256, &v.Size, &v.Storage, &v.Trigger, &v.Diff, &v.CapturedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ── Manager→agent file actions (snapshot_now / quarantine) ────────────────────

// FileAction is one on-demand operation queued for an agent (ADR 0002 Phase 3).
type FileAction struct {
	ID          int64      `json:"id"`
	AgentName   string     `json:"agent_name"`
	Path        string     `json:"path"`
	Action      string     `json:"action"`                   // snapshot_now | quarantine | restore_version
	VersionSHA  string     `json:"version_sha256,omitempty"` // target version for restore_version
	Status      string     `json:"status"`                   // requested | delivered | done | failed
	RequestedBy string     `json:"requested_by,omitempty"`
	Result      string     `json:"result,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ResultAt    *time.Time `json:"result_at,omitempty"`
}

// RequestFileAction queues an action for an agent, de-duplicated against an identical
// still-pending request (same agent+path+action not yet acted on).
func (s *Store) RequestFileAction(ctx context.Context, agentName, path, action, requestedBy string) error {
	if agentName == "" || path == "" {
		return fmt.Errorf("store: file action needs agent and path")
	}
	if action != "snapshot_now" && action != "quarantine" {
		return fmt.Errorf("store: unknown file action %q", action)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_file_actions (agent_name, path, action, requested_by)
		SELECT $1, $2, $3, $4
		WHERE NOT EXISTS (
		  SELECT 1 FROM agent_file_actions
		  WHERE agent_name=$1 AND path=$2 AND action=$3 AND status IN ('requested','delivered'))`,
		agentName, path, action, requestedBy)
	if err != nil {
		return fmt.Errorf("store: request file action: %w", err)
	}
	return nil
}

// RequestRestoreVersion queues a restore of a watched file to a SPECIFIC captured version
// (identified by its content SHA-256), de-duplicated against an identical still-pending request.
func (s *Store) RequestRestoreVersion(ctx context.Context, agentName, path, versionSHA, requestedBy string) error {
	if agentName == "" || path == "" || len(versionSHA) != 64 {
		return fmt.Errorf("store: restore-version needs agent, path and a 64-char sha256")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_file_actions (agent_name, path, action, version_sha256, requested_by)
		SELECT $1, $2, 'restore_version', $3, $4
		WHERE NOT EXISTS (
		  SELECT 1 FROM agent_file_actions
		  WHERE agent_name=$1 AND path=$2 AND action='restore_version' AND version_sha256=$3
		    AND status IN ('requested','delivered'))`,
		agentName, path, versionSHA, requestedBy)
	if err != nil {
		return fmt.Errorf("store: request restore-version: %w", err)
	}
	return nil
}

// PendingFileActions returns an agent's requested actions and marks them delivered (one-shot).
func (s *Store) PendingFileActions(ctx context.Context, agentName string) ([]FileAction, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE agent_file_actions SET status='delivered', delivered_at=now()
		WHERE id IN (SELECT id FROM agent_file_actions WHERE agent_name=$1 AND status='requested')
		RETURNING id, agent_name, path, action, COALESCE(version_sha256,''), status, COALESCE(requested_by,''), COALESCE(result,''), created_at, result_at`,
		agentName)
	if err != nil {
		return nil, fmt.Errorf("store: pending file actions: %w", err)
	}
	defer rows.Close()
	out := make([]FileAction, 0, 8)
	for rows.Next() {
		var a FileAction
		if err := rows.Scan(&a.ID, &a.AgentName, &a.Path, &a.Action, &a.VersionSHA, &a.Status, &a.RequestedBy, &a.Result, &a.CreatedAt, &a.ResultAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetFileActionResult records the outcome an agent reports for an action (status done|failed).
func (s *Store) SetFileActionResult(ctx context.Context, id int64, status, result string) error {
	if status != "done" && status != "failed" {
		return fmt.Errorf("store: bad action status %q", status)
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE agent_file_actions SET status=$2, result=$3, result_at=now() WHERE id=$1`, id, status, result)
	if err != nil {
		return fmt.Errorf("store: set file action result: %w", err)
	}
	return nil
}

// ListFileActions returns recent actions for an agent+path (newest first), for the UI.
func (s *Store) ListFileActions(ctx context.Context, agentName, path string, limit int) ([]FileAction, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_name, path, action, COALESCE(version_sha256,''), status, COALESCE(requested_by,''), COALESCE(result,''), created_at, result_at
		FROM agent_file_actions WHERE agent_name=$1 AND path=$2
		ORDER BY created_at DESC LIMIT $3`, agentName, path, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list file actions: %w", err)
	}
	defer rows.Close()
	out := make([]FileAction, 0, limit)
	for rows.Next() {
		var a FileAction
		if err := rows.Scan(&a.ID, &a.AgentName, &a.Path, &a.Action, &a.VersionSHA, &a.Status, &a.RequestedBy, &a.Result, &a.CreatedAt, &a.ResultAt); err != nil {
			return nil, err
		}
		out = append(out, a)
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
