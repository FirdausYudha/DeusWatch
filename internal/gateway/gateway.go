// Package gateway is the DeusWatch ingest gateway: it receives raw logs from agents
// (over mTLS), validates them, normalizes them to DCS, then publishes them to NATS.
package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"deuswatch/internal/bus"
	"deuswatch/internal/ingest"
)

const maxBodyBytes = 8 << 20 // 8 MiB per batch

// Publisher publishes a payload to a subject (satisfied by *bus.Bus).
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// RevokedFunc reports whether a presented client certificate must be rejected -
// either the agent (by CN) is revoked, or the certificate serial was superseded by a
// re-enrollment (the serial pin keeps an old cert dead after its name is re-used).
// nil = skip.
type RevokedFunc func(ctx context.Context, agentName, certSerial string) (bool, error)

// ConfigFunc returns the push-config JSON for an agent (by CN). nil/len 0 = none yet.
type ConfigFunc func(ctx context.Context, agentName string) ([]byte, error)

// SeenFunc marks an agent (by CN) as just seen (heartbeat). nil = skip.
type SeenFunc func(ctx context.Context, agentName string) error

// HealthFunc records an agent's self-reported health alongside last_seen (heartbeat
// with a JSON body). nil = fall back to SeenFunc-only behaviour.
type HealthFunc func(ctx context.Context, agentName string, degraded bool, detail string) error

// heartbeatBody is the OPTIONAL heartbeat payload. Old agents POST an empty body,
// which decodes to the zero value (healthy) - fully backward compatible.
type heartbeatBody struct {
	Degraded bool   `json:"degraded"`
	Detail   string `json:"detail"`
}

// BlocklistFunc returns the source IPs agents should block (empty when none/disabled).
type BlocklistFunc func(ctx context.Context) ([]string, error)

// FileTarget is a known-bad file (path + hash) the agent should quarantine/delete.
type FileTarget struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// QuarantineFunc returns the known-bad files agents should remediate (empty when disabled).
type QuarantineFunc func(ctx context.Context) ([]FileTarget, error)

// RestoreFunc returns the file paths a specific agent (by CN) should restore to their
// known-good snapshot, marking each delivered (one-shot). nil = feed disabled.
type RestoreFunc func(ctx context.Context, agentName string) ([]string, error)

// RestoreHandler serves the per-agent one-click-restore list over mTLS. Agents that opted
// in (AGENT_FIM_RESTORE) poll this and write their known-good snapshot back to each path.
func RestoreHandler(fn RestoreFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		paths := []string{}
		if fn != nil {
			var cn string
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				cn = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			if cn != "" {
				if got, err := fn(r.Context(), cn); err == nil && got != nil {
					paths = got
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"paths": paths})
	}
}

// QuarantineHandler serves the known-bad file list over mTLS. Agents that opted in
// (AGENT_FILE_REMEDIATION) poll this and quarantine/delete files whose current hash matches.
func QuarantineHandler(fn QuarantineFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var files []FileTarget
		if fn != nil {
			if got, err := fn(r.Context()); err == nil {
				files = got
			}
		}
		if files == nil {
			files = []FileTarget{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
	}
}

// BlocklistHandler serves the agent-side auto-block list over mTLS. Agents poll this and
// apply the IPs to their local nftables set.
func BlocklistHandler(fn BlocklistFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ips := []string{}
		if fn != nil {
			if list, err := fn(r.Context()); err == nil && list != nil {
				ips = list
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"ips": ips})
	}
}

// SnapshotMeta is one captured FIM version's metadata (ADR 0002 Phase 2), uploaded by the agent.
type SnapshotMeta struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Trigger string `json:"trigger"`           // on_change | scheduled | manual
	Diff    string `json:"diff,omitempty"`    // unified diff vs the previous captured version
	Content string `json:"content,omitempty"` // present only for manager-side storage (Phase 5)
}

// FileActionItem is one manager-requested on-demand file operation served to an agent.
type FileActionItem struct {
	ID            int64  `json:"id"`
	Path          string `json:"path"`
	Action        string `json:"action"`                   // snapshot_now | quarantine | restore_version | kill_process
	VersionSHA256 string `json:"version_sha256,omitempty"` // target version for restore_version
	Content       string `json:"content,omitempty"`        // manager-stored content for restore_version (Phase 5)
	// kill_process only. These MUST survive the trip: the agent refuses to kill on a bare PID,
	// so dropping the identity here would turn every kill into a refusal.
	PID       int    `json:"pid,omitempty"`
	ProcName  string `json:"proc_name,omitempty"`
	ProcStart string `json:"proc_start,omitempty"`
}

// FileActionsFunc returns the pending actions for an agent (by CN), marking them delivered.
type FileActionsFunc func(ctx context.Context, agentName string) ([]FileActionItem, error)

// FileActionResultFunc records an agent's reported outcome for an action.
type FileActionResultFunc func(ctx context.Context, id int64, status, result string) error

// FileActionsHandler serves an agent its pending on-demand file actions over mTLS (ADR 0002).
func FileActionsHandler(fn FileActionsFunc, revoked RevokedFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var certCN, certSerial string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certCN = r.TLS.PeerCertificates[0].Subject.CommonName
			certSerial = r.TLS.PeerCertificates[0].SerialNumber.String()
		}
		if revoked != nil && certCN != "" {
			if rev, err := revoked(r.Context(), certCN, certSerial); err == nil && rev {
				http.Error(w, "agent revoked", http.StatusGone)
				return
			}
		}
		actions := []FileActionItem{}
		if fn != nil && certCN != "" {
			if got, err := fn(r.Context(), certCN); err == nil && got != nil {
				actions = got
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]FileActionItem{"actions": actions})
	}
}

// FileActionResultHandler receives an agent's outcome for one action (id, status, result).
func FileActionResultHandler(fn FileActionResultFunc, revoked RevokedFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var certCN, certSerial string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certCN = r.TLS.PeerCertificates[0].Subject.CommonName
			certSerial = r.TLS.PeerCertificates[0].SerialNumber.String()
		}
		if revoked != nil && certCN != "" {
			if rev, err := revoked(r.Context(), certCN, certSerial); err == nil && rev {
				http.Error(w, "agent revoked", http.StatusGone)
				return
			}
		}
		var body struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
			Result string `json:"result"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if fn != nil && body.ID != 0 {
			if err := fn(r.Context(), body.ID, body.Status, body.Result); err != nil {
				http.Error(w, "record failed", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// SnapshotFunc records a batch of an agent's captured version metadata. nil = feed disabled.
type SnapshotFunc func(ctx context.Context, agentName string, snaps []SnapshotMeta) error

// SnapshotHandler receives an agent's FIM version metadata over mTLS and records it (the version
// content stays on the agent). Identity is the mTLS CN; a revoked agent gets 410 Gone.
func SnapshotHandler(fn SnapshotFunc, revoked RevokedFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var certCN, certSerial string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certCN = r.TLS.PeerCertificates[0].Subject.CommonName
			certSerial = r.TLS.PeerCertificates[0].SerialNumber.String()
		}
		if revoked != nil && certCN != "" {
			if rev, err := revoked(r.Context(), certCN, certSerial); err == nil && rev {
				http.Error(w, "agent revoked", http.StatusGone)
				return
			}
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		var snaps []SnapshotMeta
		if err := json.Unmarshal(body, &snaps); err != nil {
			http.Error(w, "invalid JSON (expected a SnapshotMeta array)", http.StatusBadRequest)
			return
		}
		if fn != nil && certCN != "" && len(snaps) > 0 {
			if err := fn(r.Context(), certCN, snaps); err != nil {
				http.Error(w, "record failed", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// HeartbeatHandler marks the agent's last_seen (identified by the mTLS CN) and records
// the agent's self-reported health from the optional JSON body (degraded + detail, e.g.
// "217 batches buffered"). A revoked agent gets HTTP 410 Gone — the signal for the
// agent to self-uninstall and stop.
func HeartbeatHandler(seen SeenFunc, health HealthFunc, revoked RevokedFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cn, serial string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
			serial = r.TLS.PeerCertificates[0].SerialNumber.String()
		}
		if revoked != nil && cn != "" {
			if rev, err := revoked(r.Context(), cn, serial); err == nil && rev {
				http.Error(w, "agent revoked", http.StatusGone)
				return
			}
		}
		if cn != "" {
			var hb heartbeatBody
			_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&hb) // empty body = healthy
			switch {
			case health != nil:
				_ = health(r.Context(), cn, hb.Degraded, hb.Detail)
			case seen != nil:
				_ = seen(r.Context(), cn)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ConfigHandler serves the agent's push-config (identified by the mTLS certificate
// CN). 204 when no config exists yet.
func ConfigHandler(cfg ConfigFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var cn string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		if cn == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		raw, err := cfg(r.Context(), cn)
		if err != nil {
			http.Error(w, "failed to fetch config", http.StatusInternalServerError)
			return
		}
		if len(raw) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}
}

// ContainmentDirective tells an agent whether to isolate itself (host network containment)
// and which IPs it must keep reachable (the manager/gateway + allow-list) so its link to the
// manager survives the isolation.
type ContainmentDirective struct {
	Isolate  bool     `json:"isolate"`
	AllowIPs []string `json:"allow_ips"`
	Reason   string   `json:"reason,omitempty"`
}

// ContainmentFunc returns the isolation directive for an agent (by certificate CN). A zero
// value (Isolate=false) means the agent should NOT be isolated.
type ContainmentFunc func(ctx context.Context, agentName string) (ContainmentDirective, error)

// ContainmentHandler serves the per-agent isolation directive over mTLS. Agents that opted
// in (AGENT_CONTAINMENT) poll this; when Isolate is true they firewall themselves off from
// the LAN except AllowIPs. The agent is identified by the mTLS certificate CN, so one agent
// can never read or trigger another's containment.
func ContainmentHandler(fn ContainmentFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d := ContainmentDirective{AllowIPs: []string{}}
		if fn != nil {
			var cn string
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				cn = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			if cn != "" {
				if got, err := fn(r.Context(), cn); err == nil {
					d = got
				}
			}
		}
		if d.AllowIPs == nil {
			d.AllowIPs = []string{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d)
	}
}

// LogsHandler receives a RawLog batch (JSON array) from an agent, normalizes each
// entry to DCS, and publishes them to logs.normalized. The agent identity is taken
// from the client certificate's Common Name (more trustworthy than the submitted value).
// If revoked != nil, connections from revoked agents are rejected (403).
func LogsHandler(pub Publisher, revoked RevokedFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		var raws []ingest.RawLog
		if err := json.Unmarshal(body, &raws); err != nil {
			http.Error(w, "invalid JSON (expected a RawLog array)", http.StatusBadRequest)
			return
		}

		// Identity from the mTLS certificate (binds logs to the authenticated agent).
		var certCN, certSerial string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certCN = r.TLS.PeerCertificates[0].Subject.CommonName
			certSerial = r.TLS.PeerCertificates[0].SerialNumber.String()
		}

		ctx := r.Context()

		// Reject revoked agents — even if their certificate is still cryptographically valid.
		if revoked != nil && certCN != "" {
			if rev, err := revoked(ctx, certCN, certSerial); err == nil && rev {
				http.Error(w, "agent revoked", http.StatusForbidden)
				return
			}
		}
		accepted := 0
		for _, raw := range raws {
			if raw.Message == "" {
				continue // validation: message is required
			}
			if certCN != "" {
				raw.AgentID = certCN
			}
			ev, _ := ingest.Normalize(raw)
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			if err := pub.Publish(ctx, bus.SubjectLogsNormalized, data); err != nil {
				http.Error(w, "publish failed", http.StatusServiceUnavailable)
				return
			}
			accepted++
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": accepted})
	}
}
