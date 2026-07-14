// Package ingesthook is a token-authenticated HTTP webhook that ingests RAW log lines
// from external systems (e.g. a Wazuh manager's integrator) into the normal DeusWatch
// pipeline. Each line becomes a RawLog, is normalized to DCS (custom decoders apply, so
// operators can "parse manually" from the Decoders UI), and is published to
// logs.normalized - exactly like an agent-shipped line, so detection / playbooks /
// response all work on it. The source is tagged (agent = "wazuh-agent/<name>") so it is
// distinguishable on the dashboard.
package ingesthook

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"deuswatch/internal/bus"
	"deuswatch/internal/ingest"
)

// Publisher publishes a payload to a subject (satisfied by *bus.Bus).
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// Handler serves the raw-log ingest webhook.
type Handler struct {
	pub   Publisher
	token string
}

// New builds the handler. An empty token DISABLES the endpoint (returns 404) - the
// operator must set INGEST_WEBHOOK_TOKEN to turn it on, so it is never open by default.
func New(pub Publisher, token string) *Handler {
	return &Handler{pub: pub, token: strings.TrimSpace(token)}
}

// Enabled reports whether a token (and publisher) is configured.
func (h *Handler) Enabled() bool { return h != nil && h.pub != nil && h.token != "" }

const (
	maxBody     = 4 << 20 // 4 MiB per request
	maxLines    = 2000    // per request
	defaultTag  = "wazuh-agent"
	defaultData = "wazuh"
)

// ServeHTTP handles POST /api/ingest/webhook?token=&agent=&dataset=&host=.
// Body: newline-separated raw log lines (text/plain), OR a JSON array of strings.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.Enabled() {
		http.Error(w, "ingest webhook disabled (set INGEST_WEBHOOK_TOKEN)", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Token from query or Authorization: Bearer. Constant-time compare.
	got := r.URL.Query().Get("token")
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(h.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	q := r.URL.Query()
	dataset := strings.TrimSpace(q.Get("dataset"))
	if dataset == "" {
		dataset = defaultData
	}
	tag := defaultTag
	if a := strings.TrimSpace(q.Get("agent")); a != "" {
		tag = defaultTag + "/" + a // dashboard shows this in the Agent column
	}
	host := strings.TrimSpace(q.Get("host"))

	lines, err := readLines(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	accepted := 0
	for _, line := range lines {
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		ev, _ := ingest.Normalize(ingest.RawLog{
			Timestamp: time.Now(), Host: host, AgentID: tag, Dataset: dataset, Message: line,
		})
		data, merr := json.Marshal(ev)
		if merr != nil {
			continue
		}
		if perr := h.pub.Publish(r.Context(), bus.SubjectLogsNormalized, data); perr != nil {
			http.Error(w, "publish failed", http.StatusServiceUnavailable)
			return
		}
		accepted++
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted": accepted})
}

// readLines reads the body as either a JSON array of strings or newline-separated text.
func readLines(r *http.Request) ([]string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var arr []string
		if err := json.NewDecoder(r.Body).Decode(&arr); err != nil {
			return nil, errBadJSON
		}
		return capLines(arr), nil
	}
	var out []string
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // allow long lines (up to 1 MiB)
	for sc.Scan() {
		out = append(out, sc.Text())
		if len(out) >= maxLines {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func capLines(in []string) []string {
	if len(in) > maxLines {
		return in[:maxLines]
	}
	return in
}

type ingestError string

func (e ingestError) Error() string { return string(e) }

const errBadJSON = ingestError("invalid JSON body (expected an array of strings)")
