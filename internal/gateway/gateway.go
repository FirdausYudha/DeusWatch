// Package gateway is the DeusWatch ingest gateway: it receives raw logs from agents
// (over mTLS), validates them, normalizes them to DCS, then publishes them to NATS.
package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

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
	Version  string `json:"version,omitempty"` // v2.12.0+: reported so UI can gate the Update button
}

// HeartbeatResponse is what the gateway returns on a successful heartbeat. Legacy field-less
// {} is the normal case; when an operator has clicked Update in the UI, Update is populated
// and the agent atomically self-replaces its binary on receipt (v2.12.0+).
type HeartbeatResponse struct {
	Update *UpdateDirective `json:"update,omitempty"`
}

// UpdateDirective tells the agent to fetch a new binary from URL and restart. Version is
// informational — the agent will always use whatever URL returns.
type UpdateDirective struct {
	URL     string `json:"url"`
	Version string `json:"version"`
}

// HealthWithVersionFunc is the v2.12.0 replacement for HealthFunc: also persists the agent's
// self-reported version so the UI can compare fleet vs manager. When set on the handler,
// takes precedence over HealthFunc.
type HealthWithVersionFunc func(ctx context.Context, agentName string, degraded bool, detail, version string) error

// UpdateDirectiveFunc returns a pending update directive for the calling CN, or (nil, nil) when
// no update is pending. Called on every heartbeat.
type UpdateDirectiveFunc func(ctx context.Context, agentName string) (*UpdateDirective, error)

// BlocklistFunc returns the source IPs agents should block (empty when none/disabled).
// LEGACY signature: kept so the interface stays stable while the response envelope evolves
// (see BlocklistConfigFunc below, which lets the manager tell the agent which nftables
// table/set to use and whether the agent-side firewall is enabled AT ALL for this CN).
type BlocklistFunc func(ctx context.Context) ([]string, error)

// BlocklistConfig is what a single agent should apply to its local firewall. Enabled=false
// means the manager has NOT configured the nftables_agent integration for this CN — the
// agent must NOT touch its firewall (leave any pre-existing rules alone; no auto-teardown,
// operators dislike surprises). Table/Set are the integration's chosen names, defaulted
// server-side so the agent never has to know the defaults.
type BlocklistConfig struct {
	Enabled bool     `json:"enabled"`
	Table   string   `json:"table"`
	Set     string   `json:"set"`
	IPs     []string `json:"ips"`
}

// BlocklistConfigFunc resolves the per-agent firewall envelope: the manager checks whether an
// enabled nftables_agent integration covers the calling CN (agent_scope) and returns Enabled
// accordingly, together with the chosen table/set and the current block set.
type BlocklistConfigFunc func(ctx context.Context, agentCN string) (BlocklistConfig, error)

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
//
// LEGACY handler kept for older agents whose parser only expects {"ips": [...]}. New
// deployments should mount BlocklistConfigHandler at the same path instead — it returns the
// same "ips" field for old agents PLUS enabled/table/set for new ones.
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

// BlocklistConfigHandler is the v2.11.0 replacement: response envelope carries not just the
// IPs but the enable flag and the table/set names, so the agent no longer needs a local
// AGENT_FIREWALL env var to activate — the manager's nftables_agent integration is the
// source of truth. Backwards-compatible on the wire: the "ips" field is unchanged, older
// agents ignore the new fields (they simply won't know to activate their firewall from the
// server side, which is the pre-v2.11 behaviour anyway).
func BlocklistConfigHandler(fn BlocklistConfigFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := BlocklistConfig{IPs: []string{}}
		if fn != nil {
			var cn string
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				cn = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			if got, err := fn(r.Context(), cn); err == nil {
				out = got
				if out.IPs == nil {
					out.IPs = []string{}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
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

// InventoryFunc records an agent's reported software inventory. The body is the raw JSON so the
// wiring can unmarshal it into the shared agent.Inventory type without this package importing it
// (kept dependency-free like SnapshotMeta). nil = feed disabled.
type InventoryFunc func(ctx context.Context, agentName string, body []byte) error

// InventoryHandler receives an agent's software inventory (OS release + installed packages) over
// mTLS and records it. Identity is the mTLS CN; a revoked agent gets 410 Gone.
func InventoryHandler(fn InventoryFunc, revoked RevokedFunc) http.HandlerFunc {
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
		// A package list can be large; allow a bigger body than the log-batch cap.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if fn != nil && certCN != "" && len(body) > 0 {
			if err := fn(r.Context(), certCN, body); err != nil {
				http.Error(w, "record failed", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// AgentBinaryHandler serves the fresh agent binary the self-update flow points at. Lives
// on the gateway (not the api) so agents don't need a second network path — they already
// trust the gateway via mTLS. `binDir` is the directory the Dockerfile bakes the
// cross-compiled binaries into (/agents). {arch} path param picks amd64 / arm64;
// {os} is fixed to linux because Windows agents use their own service update pattern.
func AgentBinaryHandler(binDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		arch := r.PathValue("arch")
		// filepath.Base guards against a caller sneaking .. or / into the path param.
		safeArch := filepath.Base(arch)
		if safeArch != "amd64" && safeArch != "arm64" {
			http.Error(w, "unsupported arch (want amd64 or arm64)", http.StatusBadRequest)
			return
		}
		name := "deuswatch-agent-linux-" + safeArch
		f, err := os.Open(filepath.Join(binDir, name))
		if err != nil {
			http.Error(w, "agent binary not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+name)
		http.ServeContent(w, r, name, time.Time{}, f)
	}
}

// HeartbeatHandler marks the agent's last_seen (identified by the mTLS CN) and records
// the agent's self-reported health from the optional JSON body (degraded + detail, e.g.
// "217 batches buffered"). A revoked agent gets HTTP 410 Gone — the signal for the
// agent to self-uninstall and stop. When updFn is non-nil and returns a pending directive
// for the calling CN, the response becomes 200 + JSON {"update":{...}} so the agent can
// atomically self-replace its binary (v2.12.0+).
func HeartbeatHandler(seen SeenFunc, health HealthFunc, revoked RevokedFunc) http.HandlerFunc {
	return HeartbeatHandlerFull(seen, health, nil, revoked, nil)
}

// HeartbeatHandlerFull is the v2.12.0 form that also accepts a version-persisting store and
// an update-directive resolver. The pre-v2.12 HeartbeatHandler delegates to this with nils.
func HeartbeatHandlerFull(seen SeenFunc, health HealthFunc, healthV HealthWithVersionFunc, revoked RevokedFunc, updFn UpdateDirectiveFunc) http.HandlerFunc {
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
		var hb heartbeatBody
		if cn != "" {
			_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&hb) // empty body = healthy
			// Persist the heartbeat, and let the agent KNOW when we couldn't (was silently discarded
			// before — an operator would then see the agent "offline" on the dashboard even though
			// `journalctl -u deuswatch-agent` said the heartbeat was sent, because gateway pool
			// connections that had gone bad returned an error on UPDATE that we then ignored; a
			// `docker compose restart` "fixed" it by re-creating the pool. Now we log and return 503
			// so the operator sees the failure in gateway logs and the agent's next heartbeat is not
			// suppressed by a stale success response).
			var err error
			switch {
			case healthV != nil:
				err = healthV(r.Context(), cn, hb.Degraded, hb.Detail, hb.Version)
			case health != nil:
				err = health(r.Context(), cn, hb.Degraded, hb.Detail)
			case seen != nil:
				err = seen(r.Context(), cn)
			}
			if err != nil {
				log.Printf("gateway: heartbeat DB update failed for agent %q: %v", cn, err)
				http.Error(w, "heartbeat store error", http.StatusServiceUnavailable)
				return
			}
		}
		// Update-directive check happens after we've persisted the heartbeat, so a "fresh"
		// last_seen is recorded even when we're about to tell the agent to restart.
		if updFn != nil && cn != "" {
			if dir, err := updFn(r.Context(), cn); err == nil && dir != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(HeartbeatResponse{Update: dir})
				return
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
