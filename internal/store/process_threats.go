package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"deuswatch/internal/agent"
)

// ProcessThreats represents a detected threat from process analysis.
type ProcessThreats struct {
	ID                int64             `json:"id"`
	TenantID          string            `json:"tenant_id"`
	AgentID           string            `json:"agent_id"`
	SnapshotID        int64             `json:"snapshot_id"`
	PID               int               `json:"pid"`
	ProcessName       string            `json:"process_name"`
	ProcessPath       string            `json:"process_path"`
	Cmdline           string            `json:"cmdline"`
	FileHash          string            `json:"file_hash"`
	ThreatLevel       string            `json:"threat_level"` // CLEAN, SUSPICIOUS, MALICIOUS
	Reasons           []string          `json:"reasons"`
	YaraMatches       map[string]string `json:"yara_matches"`
	VirusTotalData    map[string]any    `json:"virustotal_data"`
	BehavioralScore   int               `json:"behavioral_score"`
	DetectedAt        time.Time         `json:"detected_at"`
	CreatedAt         time.Time         `json:"created_at"`
	Resolved          bool              `json:"resolved"`
	ResolvedReason    string            `json:"resolved_reason,omitempty"`
	ResolvedBy        string            `json:"resolved_by,omitempty"`
	ResolvedAt        *time.Time        `json:"resolved_at,omitempty"`
}

// InsertProcessSnapshot stores a raw process snapshot batch for audit trail.
// Returns the snapshot ID for linking to threats.
func (s *Store) InsertProcessSnapshot(ctx context.Context, tenantID, agentID string, batch *agent.ProcessSnapshotBatch) (int64, error) {
	processData, err := json.Marshal(batch.Processes)
	if err != nil {
		return 0, fmt.Errorf("marshal processes: %w", err)
	}

	var snapshotID int64
	err = s.q(ctx).QueryRow(ctx,
		`INSERT INTO process_snapshots (tenant_id, agent_id, snapshot_time, process_count, processes)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		tenantID, agentID, batch.Timestamp, len(batch.Processes), processData).Scan(&snapshotID)

	if err != nil {
		return 0, fmt.Errorf("insert process snapshot: %w", err)
	}

	return snapshotID, nil
}

// InsertProcessThreat stores a detected threat record.
func (s *Store) InsertProcessThreat(ctx context.Context, tenantID, agentID string, snapshotID int64, threat *ProcessThreats) error {
	reasonsData, _ := json.Marshal(threat.Reasons)
	yaraData, _ := json.Marshal(threat.YaraMatches)
	vtData, _ := json.Marshal(threat.VirusTotalData)

	_, err := s.q(ctx).Exec(ctx,
		`INSERT INTO process_threats 
		 (tenant_id, agent_id, snapshot_id, pid, process_name, process_path, cmdline, file_hash, 
		  threat_level, reasons, yara_matches, virustotal_data, behavioral_score, detected_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		tenantID, agentID, snapshotID, threat.PID, threat.ProcessName, threat.ProcessPath,
		threat.Cmdline, threat.FileHash, threat.ThreatLevel, reasonsData, yaraData, vtData,
		threat.BehavioralScore, threat.DetectedAt)

	if err != nil {
		return fmt.Errorf("insert process threat: %w", err)
	}

	return nil
}

// GetProcessThreats retrieves threats for a tenant, optionally filtered by threat level.
func (s *Store) GetProcessThreats(ctx context.Context, tenantID string, threatLevel string) ([]ProcessThreats, error) {
	var query string
	var args []any

	if threatLevel != "" {
		query = `SELECT id, tenant_id, agent_id, snapshot_id, pid, process_name, process_path, 
		                cmdline, file_hash, threat_level, reasons, yara_matches, virustotal_data, 
		                behavioral_score, detected_at, created_at, resolved, resolved_reason, 
		                resolved_by, resolved_at
		         FROM process_threats
		         WHERE tenant_id = $1 AND threat_level = $2 AND NOT resolved
		         ORDER BY created_at DESC
		         LIMIT 1000`
		args = []any{tenantID, threatLevel}
	} else {
		query = `SELECT id, tenant_id, agent_id, snapshot_id, pid, process_name, process_path, 
		                cmdline, file_hash, threat_level, reasons, yara_matches, virustotal_data, 
		                behavioral_score, detected_at, created_at, resolved, resolved_reason, 
		                resolved_by, resolved_at
		         FROM process_threats
		         WHERE tenant_id = $1 AND NOT resolved
		         ORDER BY created_at DESC
		         LIMIT 1000`
		args = []any{tenantID}
	}

	rows, err := s.q(ctx).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query process threats: %w", err)
	}
	defer rows.Close()

	var threats []ProcessThreats
	for rows.Next() {
		var t ProcessThreats
		var reasonsData, yaraData, vtData []byte

		err := rows.Scan(&t.ID, &t.TenantID, &t.AgentID, &t.SnapshotID, &t.PID, &t.ProcessName,
			&t.ProcessPath, &t.Cmdline, &t.FileHash, &t.ThreatLevel, &reasonsData, &yaraData, &vtData,
			&t.BehavioralScore, &t.DetectedAt, &t.CreatedAt, &t.Resolved, &t.ResolvedReason,
			&t.ResolvedBy, &t.ResolvedAt)

		if err != nil {
			continue
		}

		json.Unmarshal(reasonsData, &t.Reasons)
		json.Unmarshal(yaraData, &t.YaraMatches)
		json.Unmarshal(vtData, &t.VirusTotalData)

		threats = append(threats, t)
	}

	return threats, rows.Err()
}

// GetProcessThreatsForAgent retrieves threats detected on a specific agent.
func (s *Store) GetProcessThreatsForAgent(ctx context.Context, tenantID, agentID string) ([]ProcessThreats, error) {
	query := `SELECT id, tenant_id, agent_id, snapshot_id, pid, process_name, process_path, 
	                 cmdline, file_hash, threat_level, reasons, yara_matches, virustotal_data, 
	                 behavioral_score, detected_at, created_at, resolved, resolved_reason, 
	                 resolved_by, resolved_at
	          FROM process_threats
	          WHERE tenant_id = $1 AND agent_id = $2
	          ORDER BY created_at DESC
	          LIMIT 500`

	rows, err := s.q(ctx).Query(ctx, query, tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("query agent threats: %w", err)
	}
	defer rows.Close()

	var threats []ProcessThreats
	for rows.Next() {
		var t ProcessThreats
		var reasonsData, yaraData, vtData []byte

		err := rows.Scan(&t.ID, &t.TenantID, &t.AgentID, &t.SnapshotID, &t.PID, &t.ProcessName,
			&t.ProcessPath, &t.Cmdline, &t.FileHash, &t.ThreatLevel, &reasonsData, &yaraData, &vtData,
			&t.BehavioralScore, &t.DetectedAt, &t.CreatedAt, &t.Resolved, &t.ResolvedReason,
			&t.ResolvedBy, &t.ResolvedAt)

		if err != nil {
			continue
		}

		json.Unmarshal(reasonsData, &t.Reasons)
		json.Unmarshal(yaraData, &t.YaraMatches)
		json.Unmarshal(vtData, &t.VirusTotalData)

		threats = append(threats, t)
	}

	return threats, rows.Err()
}

// ResolveProcessThreat marks a threat as resolved (e.g., after manual review or appeal).
func (s *Store) ResolveProcessThreat(ctx context.Context, threatID int64, reason string, resolvedBy string) error {
	_, err := s.q(ctx).Exec(ctx,
		`UPDATE process_threats
		 SET resolved = TRUE, resolved_reason = $1, resolved_by = $2, resolved_at = NOW()
		 WHERE id = $3`,
		reason, resolvedBy, threatID)

	return err
}

// CacheVirusTotalResult stores a VT API response to avoid repeated lookups.
func (s *Store) CacheVirusTotalResult(ctx context.Context, fileHash string, result map[string]any) error {
	malicious, _ := result["malicious"].(float64)
	suspicious, _ := result["suspicious"].(float64)
	undetected, _ := result["undetected"].(float64)

	engineData, _ := json.Marshal(result)

	_, err := s.q(ctx).Exec(ctx,
		`INSERT INTO vt_cache (file_hash, malicious_count, suspicious_count, undetected_count, engine_results, expires_at)
		 VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '30 days')
		 ON CONFLICT (file_hash) DO UPDATE SET
		    checked_count = checked_count + 1,
		    last_checked = NOW(),
		    expires_at = NOW() + INTERVAL '30 days'`,
		fileHash, int(malicious), int(suspicious), int(undetected), engineData)

	return err
}

// GetVirusTotalCached retrieves a cached VT result if it exists and hasn't expired.
func (s *Store) GetVirusTotalCached(ctx context.Context, fileHash string) (map[string]any, bool, error) {
	var result map[string]any
	var engineData []byte

	err := s.q(ctx).QueryRow(ctx,
		`SELECT engine_results FROM vt_cache
		 WHERE file_hash = $1 AND expires_at > NOW()`,
		fileHash).Scan(&engineData)

	if err != nil {
		return nil, false, nil // Cache miss
	}

	json.Unmarshal(engineData, &result)
	return result, true, nil
}

// CleanExpiredVTCache removes cached VT results older than 30 days (called periodically).
func (s *Store) CleanExpiredVTCache(ctx context.Context) error {
	_, err := s.q(ctx).Exec(ctx, `DELETE FROM vt_cache WHERE expires_at < NOW()`)
	return err
}

// LogProcessThreatResponse records a response action taken on a threat.
func (s *Store) LogProcessThreatResponse(ctx context.Context, threatID int64, action, status, result string) error {
	_, err := s.q(ctx).Exec(ctx,
		`INSERT INTO process_threat_responses (threat_id, action, action_status, action_result)
		 VALUES ($1, $2, $3, $4)`,
		threatID, action, status, result)

	return err
}
