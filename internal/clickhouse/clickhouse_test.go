package clickhouse

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

func TestConfigFromEnv(t *testing.T) {
	if _, ok := ConfigFromEnv(func(string) string { return "" }); ok {
		t.Fatal("no CLICKHOUSE_URL should disable the sink")
	}
	env := map[string]string{
		"CLICKHOUSE_URL":            "http://ch:8123/",
		"CLICKHOUSE_DATABASE":       "dw",
		"CLICKHOUSE_TABLE":          "ev",
		"CLICKHOUSE_BATCH":          "50",
		"CLICKHOUSE_FLUSH":          "2s",
		"CLICKHOUSE_RETENTION_DAYS": "90",
	}
	c, ok := ConfigFromEnv(func(k string) string { return env[k] })
	if !ok {
		t.Fatal("URL set should enable the sink")
	}
	if c.URL != "http://ch:8123" || c.Database != "dw" || c.Table != "ev" {
		t.Fatalf("unexpected config: %+v", c)
	}
	if c.BatchSize != 50 || c.FlushEvery != 2*time.Second || c.RetentionDays != 90 {
		t.Fatalf("unexpected tunables: %+v", c)
	}
}

func TestCreateTableDDL(t *testing.T) {
	s := New(Config{URL: "http://x", Database: "dw", Table: "ev", RetentionDays: 30})
	ddl := s.createTableDDL()
	for _, want := range []string{"`dw`.`ev`", "ENGINE = MergeTree()", "PARTITION BY toYYYYMM(timestamp)", "TTL timestamp + INTERVAL 30 DAY", "source_ip", "abuse_confidence      Nullable(Int32)"} {
		if !strings.Contains(ddl, want) {
			t.Fatalf("DDL missing %q:\n%s", want, ddl)
		}
	}
	// No retention → no TTL clause.
	if strings.Contains(New(Config{Database: "d", Table: "t"}).createTableDDL(), "TTL ") {
		t.Fatal("retention 0 must not emit a TTL clause")
	}
}

func TestRowFromEvent(t *testing.T) {
	ac := 88
	ev := &ingest.Event{
		Timestamp: time.Date(2026, 7, 18, 10, 30, 0, 0, time.UTC),
		Event:     ingest.EventFields{Category: "intrusion", Severity: 4, Dataset: "modsecurity"},
		Source:    &ingest.Endpoint{IP: "203.0.113.9", Port: 44100, Geo: &ingest.Geo{CountryISOCode: "RU", CityName: "Moscow"}},
		Agent:     &ingest.Agent{ID: "web01"},
		User:      &ingest.User{Name: "deus"},
		HTTP:      &ingest.HTTP{Method: "POST", URI: "/wp-login.php", StatusCode: 403, Host: "site"},
		File:      &ingest.File{HashSHA256: "abc"},
		Rule:      &ingest.Rule{ID: "R1", Name: "SQLi"},
	}
	ev.DeusWatch.Enrichment.AbuseConfidence = &ac
	ev.DeusWatch.Label = "bruteforce"

	r := rowFromEvent(ev)
	if r.Timestamp != "2026-07-18 10:30:00.000" {
		t.Fatalf("timestamp: %q", r.Timestamp)
	}
	if r.SourceIP != "203.0.113.9" || r.SourcePort != 44100 || r.SourceCountry != "RU" {
		t.Fatalf("source flatten wrong: %+v", r)
	}
	if r.AgentID != "web01" || r.UserName != "deus" || r.HTTPStatus != 403 || r.RuleName != "SQLi" {
		t.Fatalf("flatten wrong: %+v", r)
	}
	if r.AbuseConfidence == nil || *r.AbuseConfidence != 88 {
		t.Fatalf("abuse confidence should be 88, got %v", r.AbuseConfidence)
	}
	if r.OTXPulseCount != nil {
		t.Fatal("otx pulse count should stay nil (not looked up)")
	}
}

func TestFlushInsertsJSONEachRow(t *testing.T) {
	var (
		mu       sync.Mutex
		gotQuery string
		gotBody  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotQuery = r.URL.Query().Get("query")
		gotBody = string(body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New(Config{URL: srv.URL, Database: "dw", Table: "ev", BatchSize: 10})
	s.Add(context.Background(), &ingest.Event{Source: &ingest.Endpoint{IP: "1.2.3.4"}, Event: ingest.EventFields{Dataset: "syslog"}})
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(gotQuery, "INSERT INTO `dw`.`ev` FORMAT JSONEachRow") {
		t.Fatalf("unexpected query: %q", gotQuery)
	}
	line := strings.TrimSpace(gotBody)
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("body is not one JSON object per line: %v (%q)", err, line)
	}
	if got["source_ip"] != "1.2.3.4" || got["dataset"] != "syslog" {
		t.Fatalf("row not serialized as expected: %v", got)
	}
}

func TestFlushRequeuesOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := New(Config{URL: srv.URL, Database: "dw", Table: "ev", BatchSize: 10})
	s.Add(context.Background(), &ingest.Event{Source: &ingest.Endpoint{IP: "9.9.9.9"}})
	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("expected flush to fail on HTTP 500")
	}
	s.mu.Lock()
	n := len(s.buf)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("failed batch should be requeued, buffer has %d rows", n)
	}
}
