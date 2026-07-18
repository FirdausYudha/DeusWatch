// Package clickhouse is the DeusWatch analytics sink: it streams every normalized event into a
// ClickHouse table so large-scale, columnar analytical queries (top talkers over months, rare
// user-agents, slice-and-dice by any field) run in milliseconds without touching the hot
// TimescaleDB path. It is a SECONDARY store — TimescaleDB stays the operational source of truth;
// ClickHouse is the cheap, wide, long-retention analytics layer and is entirely optional.
//
// It talks to ClickHouse over the HTTP interface (default port 8123) with batched
// `INSERT ... FORMAT JSONEachRow`, so there is no third-party driver dependency: any ClickHouse
// (self-hosted, clickhouse-local, or a managed endpoint) works. The sink is off unless
// CLICKHOUSE_URL is set.
package clickhouse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"deuswatch/internal/ingest"
)

// Config is the sink configuration (resolved from the environment).
type Config struct {
	URL           string // e.g. http://clickhouse:8123 (required; empty = disabled)
	Database      string // default "deuswatch"
	Table         string // default "events"
	User          string // optional
	Password      string // optional
	BatchSize     int    // flush when the buffer reaches this many rows (default 1000)
	FlushEvery    time.Duration
	RetentionDays int // >0 adds a TTL so ClickHouse ages rows out (0 = keep forever)
}

// ConfigFromEnv reads the sink config. enabled is false (and the sink should not be built) when
// CLICKHOUSE_URL is empty.
func ConfigFromEnv(getenv func(string) string) (Config, bool) {
	u := strings.TrimSpace(getenv("CLICKHOUSE_URL"))
	if u == "" {
		return Config{}, false
	}
	c := Config{
		URL:      strings.TrimRight(u, "/"),
		Database: firstNonEmpty(getenv("CLICKHOUSE_DATABASE"), "deuswatch"),
		Table:    firstNonEmpty(getenv("CLICKHOUSE_TABLE"), "events"),
		User:     strings.TrimSpace(getenv("CLICKHOUSE_USER")),
		Password: getenv("CLICKHOUSE_PASSWORD"),
	}
	if n, err := strconv.Atoi(getenv("CLICKHOUSE_BATCH")); err == nil && n > 0 {
		c.BatchSize = n
	} else {
		c.BatchSize = 1000
	}
	if d, err := time.ParseDuration(getenv("CLICKHOUSE_FLUSH")); err == nil && d > 0 {
		c.FlushEvery = d
	} else {
		c.FlushEvery = 5 * time.Second
	}
	if n, err := strconv.Atoi(getenv("CLICKHOUSE_RETENTION_DAYS")); err == nil && n > 0 {
		c.RetentionDays = n
	}
	return c, true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// Sink batches events and flushes them to ClickHouse. Safe for concurrent Add.
type Sink struct {
	cfg Config
	hc  *http.Client

	mu  sync.Mutex
	buf []Row
}

// New builds a sink from cfg. It does not connect; call EnsureSchema once at startup and Run for
// the periodic flush loop.
func New(cfg Config) *Sink {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1000
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 5 * time.Second
	}
	return &Sink{cfg: cfg, hc: &http.Client{Timeout: 30 * time.Second}, buf: make([]Row, 0, cfg.BatchSize)}
}

// qualified returns the `db`.`table` identifier used in every statement.
func (s *Sink) qualified() string {
	return "`" + s.cfg.Database + "`.`" + s.cfg.Table + "`"
}

// EnsureSchema creates the database and events table if they do not exist (idempotent). The
// table is a MergeTree partitioned by month and ordered for the common (time, source IP)
// access pattern; a TTL is added when a retention window is configured.
func (s *Sink) EnsureSchema(ctx context.Context) error {
	if err := s.exec(ctx, "CREATE DATABASE IF NOT EXISTS `"+s.cfg.Database+"`"); err != nil {
		return err
	}
	return s.exec(ctx, s.createTableDDL())
}

func (s *Sink) createTableDDL() string {
	ttl := ""
	if s.cfg.RetentionDays > 0 {
		ttl = fmt.Sprintf("\nTTL timestamp + INTERVAL %d DAY", s.cfg.RetentionDays)
	}
	return "CREATE TABLE IF NOT EXISTS " + s.qualified() + ` (
	timestamp             DateTime64(3),
	event_category        String,
	event_action          String,
	event_outcome         String,
	severity              Int8,
	dataset               String,
	source_ip             String,
	source_port           UInt16,
	source_country        String,
	source_city           String,
	dest_ip               String,
	dest_port             UInt16,
	host_name             String,
	agent_id              String,
	user_name             String,
	http_method           String,
	http_uri              String,
	http_status           UInt16,
	http_host             String,
	file_path             String,
	file_hash             String,
	process_name          String,
	process_pid           Int32,
	rule_id               String,
	rule_name             String,
	mitre_technique_id    String,
	mitre_technique_name  String,
	mitre_tactic          String,
	threat_indicator_ip   String,
	threat_confidence     Int32,
	threat_feed           String,
	label                 String,
	abuse_confidence      Nullable(Int32),
	otx_pulse_count       Nullable(Int32),
	llm_verdict           String,
	file_hash_verdict     String,
	remediation_action    String,
	remediation_status    String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip)` + ttl
}

// Add flattens an event into a row and buffers it, flushing when the batch is full.
func (s *Sink) Add(ctx context.Context, ev *ingest.Event) {
	if ev == nil {
		return
	}
	row := rowFromEvent(ev)
	s.mu.Lock()
	s.buf = append(s.buf, row)
	full := len(s.buf) >= s.cfg.BatchSize
	s.mu.Unlock()
	if full {
		if err := s.Flush(ctx); err != nil {
			logFlushErr(err)
		}
	}
}

// Run flushes on an interval until ctx is cancelled, then flushes once more so nothing buffered
// is lost on shutdown.
func (s *Sink) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.FlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Best-effort final flush with a short, independent deadline.
			fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.Flush(fctx); err != nil {
				logFlushErr(err)
			}
			cancel()
			return
		case <-t.C:
			if err := s.Flush(ctx); err != nil {
				logFlushErr(err)
			}
		}
	}
}

// Flush inserts the buffered rows in one JSONEachRow request. On failure the rows are put back at
// the front of the buffer so the next tick retries them (bounded by the batch cap on Add).
func (s *Sink) Flush(ctx context.Context) error {
	s.mu.Lock()
	if len(s.buf) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.buf
	s.buf = make([]Row, 0, s.cfg.BatchSize)
	s.mu.Unlock()

	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for i := range batch {
		if err := enc.Encode(&batch[i]); err != nil { // one JSON object per line
			return fmt.Errorf("clickhouse: encode row: %w", err)
		}
	}
	q := "INSERT INTO " + s.qualified() + " FORMAT JSONEachRow"
	if err := s.post(ctx, q, body.Bytes()); err != nil {
		// Requeue so the batch is retried rather than silently dropped.
		s.mu.Lock()
		s.buf = append(batch, s.buf...)
		s.mu.Unlock()
		return err
	}
	return nil
}

// exec runs a statement with no body (DDL).
func (s *Sink) exec(ctx context.Context, stmt string) error { return s.post(ctx, stmt, nil) }

// post sends a query to the ClickHouse HTTP interface. The statement goes in the ?query=
// parameter and any bulk data in the body.
func (s *Sink) post(ctx context.Context, query string, body []byte) error {
	u := s.cfg.URL + "/?query=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	if s.cfg.User != "" {
		req.Header.Set("X-ClickHouse-User", s.cfg.User)
	}
	if s.cfg.Password != "" {
		req.Header.Set("X-ClickHouse-Key", s.cfg.Password)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("clickhouse: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("clickhouse: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
