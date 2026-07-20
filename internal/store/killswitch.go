package store

import (
	"context"
	"fmt"
	"time"
)

// Ransomware kill-switch queue (feature 3).
//
// Kill requests ride the existing agent_file_actions queue - same delivery, one-shot and result
// semantics as snapshot/quarantine/restore - with 'kill_process' naming a process instead of a
// file. `path` carries the executable path, which doubles as corroborating identity.
//
// The safety model is split deliberately across the two sides:
//   - HERE (manager): should this be proposed at all, and has a human approved it?
//   - THERE (agent, internal/agent/killproc.go): is the live process still the one we meant, and
//     is it safe to kill? The agent re-verifies and can refuse; the manager never overrides that.
//
// A detection therefore lands as 'recommended' and is inert until approved. Only KILL_SWITCH_AUTO
// writes 'requested' directly, and even then the agent's own guards still apply.

// KillRequest is one proposed or executed process termination, for the Response UI.
type KillRequest struct {
	ID          int64      `json:"id"`
	AgentName   string     `json:"agent_name"`
	PID         int        `json:"pid"`
	ProcName    string     `json:"proc_name,omitempty"`
	Exe         string     `json:"exe,omitempty"`
	ProcStart   string     `json:"proc_start,omitempty"`
	Status      string     `json:"status"` // recommended | requested | delivered | done | failed
	Reason      string     `json:"reason,omitempty"`
	RequestedBy string     `json:"requested_by,omitempty"`
	Result      string     `json:"result,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ResultAt    *time.Time `json:"result_at,omitempty"`
}

// RecommendKill proposes terminating a process. auto=false (the default) stores it as an inert
// recommendation a human must approve; auto=true queues it for immediate delivery and is only
// reachable with KILL_SWITCH_AUTO=1.
//
// A request with no identity evidence (neither start time nor executable) is rejected here rather
// than queued: the agent would refuse it anyway, and a recommendation an operator cannot safely
// approve is worse than none - it trains people to click through refusals.
func (s *Store) RecommendKill(ctx context.Context, agentName string, pid int, procName, exe, procStart, reason, requestedBy string, auto bool) error {
	if agentName == "" || pid <= 0 {
		return fmt.Errorf("store: kill request needs agent and pid")
	}
	if procStart == "" && exe == "" {
		return fmt.Errorf("store: kill request needs process identity (start time or executable) to be verifiable")
	}
	status := "recommended"
	if auto {
		status = "requested"
	}
	// De-duplicate on the process IDENTITY, not just the pid: the same pid with a different start
	// time is a different process and deserves its own row.
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_file_actions
		  (agent_name, path, action, status, pid, proc_name, proc_start, requested_by, result)
		SELECT $1, $2, 'kill_process', $3, $4, $5, $6, $7, $8
		WHERE NOT EXISTS (
		  SELECT 1 FROM agent_file_actions
		  WHERE agent_name=$1 AND action='kill_process' AND pid=$4
		    AND COALESCE(proc_start,'')=COALESCE($6,'')
		    AND status IN ('recommended','requested','delivered'))`,
		agentName, exe, status, pid, procName, procStart, requestedBy, reason)
	if err != nil {
		return fmt.Errorf("store: recommend kill: %w", err)
	}
	return nil
}

// ApproveKill moves an operator-approved recommendation into the delivery queue. It only ever
// promotes a row that is still 'recommended', so approving twice (or approving something the
// agent already acted on) cannot re-fire a kill.
func (s *Store) ApproveKill(ctx context.Context, id int64, approvedBy string) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE agent_file_actions
		SET status='requested', requested_by=$2
		WHERE id=$1 AND action='kill_process' AND status='recommended'`, id, approvedBy)
	if err != nil {
		return fmt.Errorf("store: approve kill: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DismissKill rejects a recommendation the operator judged a false positive. Recorded rather than
// deleted, so the audit trail shows the call was made and by whom.
func (s *Store) DismissKill(ctx context.Context, id int64, by string) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE agent_file_actions
		SET status='done', result='dismissed by '||COALESCE(NULLIF($2,''),'operator'), result_at=now()
		WHERE id=$1 AND action='kill_process' AND status='recommended'`, id, by)
	if err != nil {
		return fmt.Errorf("store: dismiss kill: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListKillRequests returns recent kill requests across all agents (newest first) for the Response
// page. pendingOnly limits to recommendations still awaiting a human decision.
func (s *Store) ListKillRequests(ctx context.Context, pendingOnly bool, limit int) ([]KillRequest, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where := ""
	if pendingOnly {
		where = " AND status='recommended'"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_name, COALESCE(pid,0), COALESCE(proc_name,''), COALESCE(path,''),
		       COALESCE(proc_start,''), status, COALESCE(requested_by,''), COALESCE(result,''),
		       created_at, result_at
		FROM agent_file_actions
		WHERE action='kill_process'`+where+`
		ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list kill requests: %w", err)
	}
	defer rows.Close()
	out := make([]KillRequest, 0, limit)
	for rows.Next() {
		var k KillRequest
		var res string
		if err := rows.Scan(&k.ID, &k.AgentName, &k.PID, &k.ProcName, &k.Exe, &k.ProcStart,
			&k.Status, &k.RequestedBy, &res, &k.CreatedAt, &k.ResultAt); err != nil {
			return nil, err
		}
		// While pending, `result` holds why we proposed the kill; once acted on it holds the
		// agent's outcome. Keep the two distinct so the UI never shows an outcome that is
		// actually a detection reason.
		if k.Status == "recommended" || k.Status == "requested" || k.Status == "delivered" {
			k.Reason = res
		} else {
			k.Result = res
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
