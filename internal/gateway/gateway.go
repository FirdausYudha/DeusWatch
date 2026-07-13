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

// RevokedFunc reports whether an agent (by certificate CN) has been revoked. nil = skip.
type RevokedFunc func(ctx context.Context, agentName string) (bool, error)

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

// HeartbeatHandler marks the agent's last_seen (identified by the mTLS CN) and records
// the agent's self-reported health from the optional JSON body (degraded + detail, e.g.
// "217 batches buffered"). A revoked agent gets HTTP 410 Gone — the signal for the
// agent to self-uninstall and stop.
func HeartbeatHandler(seen SeenFunc, health HealthFunc, revoked RevokedFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cn string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		if revoked != nil && cn != "" {
			if rev, err := revoked(r.Context(), cn); err == nil && rev {
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
		var certCN string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}

		ctx := r.Context()

		// Reject revoked agents — even if their certificate is still cryptographically valid.
		if revoked != nil && certCN != "" {
			if rev, err := revoked(ctx, certCN); err == nil && rev {
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
