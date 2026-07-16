// Package ingesthook is a token-authenticated HTTP webhook that ingests RAW log lines
// from external systems (e.g. a Wazuh manager's integrator) into the normal DeusWatch
// pipeline. Each line becomes a RawLog, is normalized to DCS (custom decoders apply, so
// operators can "parse manually" from the Decoders UI), and is published to
// logs.normalized - exactly like an agent-shipped line, so detection / playbooks /
// response all work on it. The source is tagged (agent = "wazuh-agent/<name>") so it is
// distinguishable on the dashboard.
package ingesthook

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
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

// TokenFunc returns the currently-configured webhook token ("" = disabled). It is called
// per request so a UI regenerate/disable takes effect immediately, without a restart.
type TokenFunc func(ctx context.Context) (string, error)

// Handler serves the raw-log ingest webhook.
type Handler struct {
	pub     Publisher
	tokenFn TokenFunc
}

// New builds the handler. tokenFn supplies the token dynamically (from the DB); an empty token
// DISABLES the endpoint (returns 404), so it is never open by default. A static token can be
// passed with NewStatic.
func New(pub Publisher, tokenFn TokenFunc) *Handler {
	return &Handler{pub: pub, tokenFn: tokenFn}
}

// NewStatic builds a handler with a fixed token (used in tests). An empty token disables it.
func NewStatic(pub Publisher, token string) *Handler {
	token = strings.TrimSpace(token)
	return &Handler{pub: pub, tokenFn: func(context.Context) (string, error) { return token, nil }}
}

// token resolves the current token, treating any lookup error as "disabled" (fail closed).
func (h *Handler) token(ctx context.Context) string {
	if h == nil || h.tokenFn == nil {
		return ""
	}
	tok, err := h.tokenFn(ctx)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(tok)
}

// Enabled reports whether the webhook is usable right now (publisher present + a token set).
func (h *Handler) Enabled() bool {
	return h != nil && h.pub != nil && h.token(context.Background()) != ""
}

const (
	maxBody     = 4 << 20 // 4 MiB per request
	maxLines    = 2000    // per request
	defaultTag  = "wazuh-agent"
	defaultData = "wazuh"
)

// ServeHTTP handles POST /api/ingest/webhook?token=&agent=&dataset=&host=.
// Body: newline-separated raw log lines (text/plain), OR a JSON array of strings.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.pub == nil {
		http.Error(w, "ingest webhook unavailable", http.StatusNotFound)
		return
	}
	want := h.token(r.Context())
	if want == "" {
		http.Error(w, "ingest webhook disabled (enable it on the Integrations page)", http.StatusNotFound)
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
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
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

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request too large", http.StatusBadRequest)
		return
	}
	events, err := decodeEvents(body, tag, dataset, host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	accepted := 0
	for _, ev := range events {
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

// decodeEvents turns a request body into normalized events. It accepts three shapes:
//   - a Wazuh alert JSON object, or an array of them (rich fields mapped straight to DCS);
//   - a JSON array of raw log-line strings;
//   - newline-separated raw log lines (text/plain).
//
// For raw lines, tag/dataset/host from the query are applied; Wazuh alerts carry their own.
func decodeEvents(body []byte, tag, dataset, host string) ([]*ingest.Event, error) {
	trimmed := bytesTrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		var elems []json.RawMessage
		if trimmed[0] == '{' {
			elems = []json.RawMessage{trimmed} // a single JSON object
		} else if err := json.Unmarshal(trimmed, &elems); err != nil {
			return nil, errBadJSON
		}
		out := make([]*ingest.Event, 0, len(elems))
		for _, el := range elems {
			el = bytesTrimSpace(el)
			if len(el) == 0 {
				continue
			}
			switch el[0] {
			case '"': // a JSON string -> a raw log line
				var s string
				if json.Unmarshal(el, &s) == nil && strings.TrimSpace(s) != "" {
					out = append(out, rawLineEvent(s, tag, dataset, host))
				}
			case '{': // a JSON object -> a Wazuh alert (fall back to skipping if unrecognized)
				if ev, ok := ingest.NormalizeWazuh(el); ok {
					out = append(out, ev)
				}
			}
		}
		return out, nil
	}
	// Plain text: newline-separated raw lines.
	var out []*ingest.Event
	for i, line := range strings.Split(string(body), "\n") {
		if i >= maxLines {
			break
		}
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, rawLineEvent(line, tag, dataset, host))
	}
	return out, nil
}

func rawLineEvent(line, tag, dataset, host string) *ingest.Event {
	ev, _ := ingest.Normalize(ingest.RawLog{
		Timestamp: time.Now(), Host: host, AgentID: tag, Dataset: dataset, Message: line,
	})
	return ev
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

type ingestError string

func (e ingestError) Error() string { return string(e) }

const errBadJSON = ingestError("invalid JSON body (expected an array of strings)")
