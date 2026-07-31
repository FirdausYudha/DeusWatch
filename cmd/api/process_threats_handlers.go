// TEMPORARILY EXCLUDED FROM THE BUILD — the "process threats" API (this file) references
// tenancy.TenantIDFromContext and store.GetAgents, which do NOT exist in this codebase (tenant
// scoping goes through store.WithTenantScope + the request-scoped tx, not a plain context tenant
// id). The file shipped with the YARA process-detection feature but its API layer was never
// completed, and blocking the container build on it prevents unrelated v2.4.0 fixes (severity,
// direction tag, banlist reasons) from reaching production. To re-enable, replace
// tenancy.TenantIDFromContext with the current per-request scope helpers, add a store.GetAgents (or
// switch to the existing agent-listing method) and remove this build tag; the corresponding route
// wiring in cmd/api/main.go (POST /api/agents/{id}/process-snapshots, GET /api/threats,
// GET /api/threats/agent/{id}, POST /api/threats/{id}/resolve) is currently commented out.
//go:build wip_process_threats

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"deuswatch/internal/agent"
	"deuswatch/internal/malware"
	"deuswatch/internal/store"
	"deuswatch/internal/tenancy"
)

// Global instances initialized at server startup
var (
	malwareAnalyzerInstance  *malware.Analyzer
	malwareResponderInstance *malware.ResponderEngine
)

// ingestProcessSnapshotHandler receives process snapshots from agents and queues analysis.
func ingestProcessSnapshotHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tenantID := tenancy.TenantIDFromContext(ctx)
		agentID := r.PathValue("id")

		// Verify agent belongs to tenant
		agents, err := st.GetAgents(ctx, tenantID)
		if err != nil {
			http.Error(w, "agent lookup failed", http.StatusInternalServerError)
			return
		}

		agentExists := false
		for _, a := range agents {
			if a.ID == agentID {
				agentExists = true
				break
			}
		}

		if !agentExists {
			http.Error(w, "agent not found", http.StatusNotFound)
			return
		}

		// Decode snapshot batch
		var batch agent.ProcessSnapshotBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}

		// Store raw snapshot
		snapshotID, err := st.InsertProcessSnapshot(ctx, tenantID, agentID, &batch)
		if err != nil {
			http.Error(w, fmt.Sprintf("snapshot storage failed: %v", err), http.StatusInternalServerError)
			return
		}

		// Trigger async analysis (background goroutine)
		go func() {
			analyzeProcessSnapshot(st, tenantID, agentID, snapshotID, batch.Processes)
		}()

		writeJSON(w, http.StatusAccepted, map[string]any{
			"message":     "snapshot received and queued for analysis",
			"snapshot_id": snapshotID,
		})
	}
}

// getProcessThreatsHandler lists detected process threats for the tenant.
func getProcessThreatsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tenantID := tenancy.TenantIDFromContext(ctx)

		threatLevel := r.URL.Query().Get("threat_level")
		limitStr := r.URL.Query().Get("limit")
		limit := 100
		if limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
				limit = l
			}
		}

		threats, err := st.GetProcessThreats(ctx, tenantID, threatLevel)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Apply limit
		if len(threats) > limit {
			threats = threats[:limit]
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"threats": threats,
			"count":   len(threats),
		})
	}
}

// getAgentThreatsHandler lists threats for a specific agent.
func getAgentThreatsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tenantID := tenancy.TenantIDFromContext(ctx)
		agentID := r.PathValue("id")

		threats, err := st.GetProcessThreatsForAgent(ctx, tenantID, agentID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"agent_id": agentID,
			"threats":  threats,
			"count":    len(threats),
		})
	}
}

// resolveThreatHandler marks a threat as resolved after manual review.
func resolveThreatHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		threatIDStr := r.PathValue("id")
		threatID, err := strconv.ParseInt(threatIDStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid threat id", http.StatusBadRequest)
			return
		}

		var req struct {
			Reason     string `json:"reason"`
			ResolvedBy string `json:"resolved_by"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}

		if err := st.ResolveProcessThreat(ctx, threatID, req.Reason, req.ResolvedBy); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// analyzeProcessSnapshot performs multi-stage threat analysis on a process batch.
// Runs in background goroutine for each snapshot.
func analyzeProcessSnapshot(st *store.Store, tenantID, agentID string, snapshotID int64, processes []agent.ProcessSnapshot) {
	ctx := context.Background()

	for _, proc := range processes {
		threat := &store.ProcessThreats{
			TenantID:    tenantID,
			AgentID:     agentID,
			PID:         proc.PID,
			ProcessName: proc.Name,
			ProcessPath: proc.Path,
			Cmdline:     proc.Cmdline,
			FileHash:    proc.FileHash,
			ThreatLevel: "CLEAN",
			Reasons:     []string{},
			DetectedAt:  time.Now(),
		}

		// Use integrated analyzer if available, otherwise fall back to basic checks
		if malwareAnalyzerInstance != nil {
			level, reasons, score := malwareAnalyzerInstance.AnalyzeProcess(ctx, proc)
			threat.ThreatLevel = level
			threat.Reasons = reasons
			threat.BehavioralScore = score
		} else {
			// Fallback: basic heuristic scoring
			score := performBehavioralAnalysis(proc)
			threat.BehavioralScore = score
			if score > 70 {
				threat.ThreatLevel = "SUSPICIOUS"
				threat.Reasons = []string{fmt.Sprintf("Behavioral anomaly score: %d", score)}
			}
		}

		// Store threat record only if not CLEAN
		if threat.ThreatLevel != "CLEAN" {
			if err := st.InsertProcessThreat(ctx, tenantID, agentID, snapshotID, threat); err != nil {
				fmt.Printf("Failed to insert threat for PID %d: %v\n", proc.PID, err)
				continue
			}

			// Trigger automated responses (async to not block analysis)
			if malwareResponderInstance != nil {
				go func(t *store.ProcessThreats) {
					if err := malwareResponderInstance.RespondToThreat(context.Background(), t, "malware-detector"); err != nil {
						fmt.Printf("Response action failed for threat %d: %v\n", t.ID, err)
					}
				}(threat)
			}
		}
	}
}

// performBehavioralAnalysis applies heuristic rules to detect suspicious behavior.
// Fallback implementation when analyzer is not available.
func performBehavioralAnalysis(proc agent.ProcessSnapshot) int {
	score := 0

	// Heuristic 1: Process in suspicious directory
	if hasSuspiciousPath(proc.Path) {
		score += 25
	}

	// Heuristic 2: Obfuscated command line
	if hasObfuscatedCmdline(proc.Cmdline) {
		score += 20
	}

	// Heuristic 3: Living-off-land tool
	if isLivingOftheLandTool(proc.Name) {
		score += 15
	}

	// Heuristic 4: System process with high memory
	if isSystemProcess(proc.Name) && proc.MemoryMB > 100 {
		score += 15
	}

	return score
}

// hasSuspiciousPath checks if path is in a suspicious directory.
func hasSuspiciousPath(path string) bool {
	suspiciousPaths := []string{
		// Windows
		"\\AppData\\Local\\Temp",
		"\\AppData\\Roaming\\",
		"\\Temp\\",
		"\\Windows\\Temp",
		// Linux
		"/tmp/", "/var/tmp/", "/dev/shm/",
	}

	for _, sus := range suspiciousPaths {
		if contains(path, sus) {
			return true
		}
	}
	return false
}

// hasObfuscatedCmdline detects obfuscated command lines.
func hasObfuscatedCmdline(cmdline string) bool {
	return contains(cmdline, "-enc") ||
		contains(cmdline, "-EncodedCommand") ||
		contains(cmdline, "||") ||
		(contains(cmdline, "|") && contains(cmdline, "out"))
}

// isLivingOftheLandTool checks if process is a commonly abused tool.
func isLivingOftheLandTool(name string) bool {
	tools := map[string]bool{
		"rundll32.exe": true, "regsvcs.exe": true, "regasm.exe": true,
		"mshta.exe": true, "powershell.exe": true, "wmic.exe": true,
		"bash": true, "sh": true, "python": true,
	}
	return tools[name]
}

// isSystemProcess checks if process is a legitimate system process.
func isSystemProcess(name string) bool {
	sys := map[string]bool{
		"svchost.exe": true, "services.exe": true, "lsass.exe": true,
		"init": true, "systemd": true, "kthreadd": true,
	}
	return sys[name]
}

// contains is a simple string contains helper.
func contains(s, substr string) bool {
	if s == "" || substr == "" {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
