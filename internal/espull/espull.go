// Package espull pulls documents from an existing Elasticsearch / OpenSearch cluster and
// feeds them into the DeusWatch pipeline. The #1 use case is the Wazuh indexer (which *is*
// OpenSearch): DeusWatch tails the wazuh-alerts-* index and maps each alert to DCS via the
// existing Wazuh normalizer, so detection / playbooks / response run on it - no agent, no
// webhook wiring on the Wazuh side.
//
// Tailing strategy: sort by the timestamp field ascending and page forward with search_after,
// persisting the last sort value as a cursor so a restart resumes without replaying or losing
// data. Limitation: progress is timestamp-based, so out-of-order indexing (a document indexed
// late with an older timestamp) or several documents sharing the exact same timestamp at a
// batch boundary can be missed. Fine for append-mostly alert streams; documented for honesty.
package espull

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"deuswatch/internal/ingest"
)

// Mode controls how a pulled document is mapped to a DCS event.
const (
	ModeAuto  = "auto"  // try the Wazuh mapping, else treat as a raw line (default)
	ModeWazuh = "wazuh" // always the Wazuh alert mapping
	ModeRaw   = "raw"   // always a raw log line (custom decoders / built-in parsers apply)
)

// Config is one cluster-pull connector (built from an Integrations row).
type Config struct {
	Address         string // https://opensearch:9200
	Index           string // wazuh-alerts-* | filebeat-* | ...
	Username        string
	Password        string
	APIKey          string // alternative to user/pass (ES/OpenSearch API key)
	TimestampField  string // default @timestamp
	Query           string // optional Lucene query_string filter
	Mode            string // auto | wazuh | raw
	Dataset         string // dataset label for raw/auto-fallback lines (default: derived from index)
	Insecure        bool   // skip TLS verify (self-signed cluster cert)
	Interval        time.Duration
	BatchSize       int
	InitialLookback time.Duration // how far back to start when there is no cursor
	AgentTag        string        // agent id for raw lines (e.g. "opensearch/<name>")
}

func (c *Config) applyDefaults() {
	if c.TimestampField == "" {
		c.TimestampField = "@timestamp"
	}
	if c.Mode == "" {
		c.Mode = ModeAuto
	}
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 500
	}
	if c.InitialLookback <= 0 {
		c.InitialLookback = 5 * time.Minute
	}
	if c.Dataset == "" {
		// "wazuh-alerts-*" -> "wazuh"; "filebeat-7.17" -> "filebeat".
		base := strings.TrimSpace(c.Index)
		for _, sep := range []string{"-", "*", "_"} {
			if i := strings.IndexAny(base, sep); i > 0 {
				base = base[:i]
			}
		}
		if base == "" {
			base = "opensearch"
		}
		c.Dataset = base
	}
	if c.AgentTag == "" {
		c.AgentTag = "opensearch"
	}
}

// Poller tails one index. It is not safe for concurrent use; run one goroutine per Poller.
type Poller struct {
	cfg    Config
	hc     *http.Client
	cursor []json.RawMessage // last sort value (search_after); nil = start fresh
}

// New builds a Poller. cursor is the persisted search_after value (nil/empty = start fresh).
func New(cfg Config, cursor []json.RawMessage) *Poller {
	cfg.applyDefaults()
	cfg.Address = strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	hc := &http.Client{Timeout: 20 * time.Second}
	if cfg.Insecure {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return &Poller{cfg: cfg, hc: hc, cursor: cursor}
}

// Cursor returns the current search_after value so the caller can persist it.
func (p *Poller) Cursor() []json.RawMessage { return p.cursor }

type searchResponse struct {
	Hits struct {
		Hits []struct {
			ID     string            `json:"_id"`
			Source json.RawMessage   `json:"_source"`
			Sort   []json.RawMessage `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
	Error json.RawMessage `json:"error"`
}

// buildQuery assembles the _search body for the next page.
func (p *Poller) buildQuery() ([]byte, error) {
	filters := []any{}
	// Only bound with a range on the first page (no cursor); afterwards search_after drives it.
	if len(p.cursor) == 0 {
		since := time.Now().Add(-p.cfg.InitialLookback).UTC().Format(time.RFC3339)
		filters = append(filters, map[string]any{
			"range": map[string]any{p.cfg.TimestampField: map[string]any{"gte": since}},
		})
	}
	must := []any{}
	if q := strings.TrimSpace(p.cfg.Query); q != "" {
		must = append(must, map[string]any{"query_string": map[string]any{"query": q}})
	}
	body := map[string]any{
		"size": p.cfg.BatchSize,
		"sort": []any{map[string]any{p.cfg.TimestampField: map[string]any{"order": "asc"}}},
		"query": map[string]any{
			"bool": map[string]any{"filter": filters, "must": must},
		},
	}
	if len(p.cursor) > 0 {
		body["search_after"] = p.cursor
	}
	return json.Marshal(body)
}

func (p *Poller) search(ctx context.Context, body []byte) (*searchResponse, error) {
	url := p.cfg.Address + "/" + strings.TrimPrefix(p.cfg.Index, "/") + "/_search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case p.cfg.APIKey != "":
		req.Header.Set("Authorization", "ApiKey "+p.cfg.APIKey)
	case p.cfg.Username != "":
		req.SetBasicAuth(p.cfg.Username, p.cfg.Password)
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("espull: search %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("espull: search %s HTTP %d: %s", url, resp.StatusCode, snippet(raw))
	}
	var sr searchResponse
	if err := json.Unmarshal(raw, &sr); err != nil {
		return nil, fmt.Errorf("espull: decode search response: %w", err)
	}
	if len(sr.Error) > 0 {
		return nil, fmt.Errorf("espull: cluster error: %s", snippet(sr.Error))
	}
	return &sr, nil
}

// Poll fetches one batch and maps it to events, advancing the cursor. It returns the events
// (already DCS-normalized) and the number of raw hits seen (0 = nothing new).
func (p *Poller) Poll(ctx context.Context) ([]*ingest.Event, int, error) {
	body, err := p.buildQuery()
	if err != nil {
		return nil, 0, err
	}
	sr, err := p.search(ctx, body)
	if err != nil {
		return nil, 0, err
	}
	hits := sr.Hits.Hits
	out := make([]*ingest.Event, 0, len(hits))
	for _, h := range hits {
		if ev := p.mapHit(h.Source); ev != nil {
			out = append(out, ev)
		}
		if len(h.Sort) > 0 {
			p.cursor = h.Sort // advance the cursor to the last hit's sort value
		}
	}
	return out, len(hits), nil
}

// mapHit turns one document's _source into a DCS event per the configured mode.
func (p *Poller) mapHit(source json.RawMessage) *ingest.Event {
	if len(source) == 0 {
		return nil
	}
	switch p.cfg.Mode {
	case ModeWazuh:
		if ev, ok := ingest.NormalizeWazuh(source); ok {
			return ev
		}
		return nil
	case ModeRaw:
		return p.rawEvent(source)
	default: // auto
		if ev, ok := ingest.NormalizeWazuh(source); ok {
			return ev
		}
		return p.rawEvent(source)
	}
}

// rawEvent maps an arbitrary document to a raw log line: it prefers a human "message"/"full_log"
// field if present, else the whole _source JSON, then runs it through the normal parser chain
// (built-in decoders + operator-defined custom decoders) under the configured dataset.
func (p *Poller) rawEvent(source json.RawMessage) *ingest.Event {
	msg := extractMessage(source)
	ev, _ := ingest.Normalize(ingest.RawLog{
		Timestamp: time.Now(),
		AgentID:   p.cfg.AgentTag,
		Dataset:   p.cfg.Dataset,
		Message:   msg,
	})
	return ev
}

// extractMessage pulls a log line out of a document, falling back to the raw JSON.
func extractMessage(source json.RawMessage) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(source, &m) == nil {
		for _, k := range []string{"message", "full_log", "log", "msg"} {
			if v, ok := m[k]; ok {
				var s string
				if json.Unmarshal(v, &s) == nil && strings.TrimSpace(s) != "" {
					return s
				}
			}
		}
	}
	return string(source)
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
