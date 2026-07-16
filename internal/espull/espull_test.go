package espull

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockES returns a fake _search endpoint that echoes captured request bodies and serves a
// canned page of hits, so tests can assert both the query DeusWatch builds and the mapping.
func mockES(t *testing.T, hits []map[string]any) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var captured []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/_search") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var q map[string]any
		_ = json.Unmarshal(body, &q)
		captured = append(captured, q)
		resp := map[string]any{"hits": map[string]any{"hits": hits}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &captured
}

func TestPollWazuhMappingAndCursor(t *testing.T) {
	wazuhSource := map[string]any{
		"rule": map[string]any{
			"level": 7, "id": "5710", "description": "sshd: brute force",
			"groups": []string{"authentication_failed"},
			"mitre":  map[string]any{"id": []string{"T1110"}, "tactic": []string{"Credential Access"}},
		},
		"data":      map[string]any{"srcip": "203.0.113.9"},
		"agent":     map[string]any{"name": "web-01"},
		"full_log":  "Failed password for root",
		"timestamp": "2026-07-16T03:00:00+0000",
	}
	hits := []map[string]any{{"_id": "a1", "_source": wazuhSource, "sort": []any{1_752_000_000_000}}}
	srv, captured := mockES(t, hits)

	p := New(Config{Address: srv.URL, Index: "wazuh-alerts-*", Mode: ModeAuto}, nil)
	events, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 1 || len(events) != 1 {
		t.Fatalf("want 1 hit/1 event, got %d/%d", n, len(events))
	}
	ev := events[0]
	if ev.Source == nil || ev.Source.IP != "203.0.113.9" {
		t.Fatalf("wazuh srcip not mapped: %+v", ev.Source)
	}
	if ev.Threat == nil || ev.Threat.Technique.ID != "T1110" {
		t.Fatalf("wazuh MITRE not mapped: %+v", ev.Threat)
	}
	// First query bounds with a range (no cursor yet) and has no search_after.
	first := (*captured)[0]
	if _, hasSA := first["search_after"]; hasSA {
		t.Fatal("first poll must not use search_after")
	}
	// Cursor advanced to the hit's sort value.
	if cur := p.Cursor(); len(cur) != 1 {
		t.Fatalf("cursor not advanced: %v", cur)
	}

	// Second poll: cursor set -> search_after present, no range filter.
	if _, _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	second := (*captured)[1]
	if _, hasSA := second["search_after"]; !hasSA {
		t.Fatal("second poll must use search_after")
	}
}

func TestPollRawModeExtractsMessage(t *testing.T) {
	hits := []map[string]any{
		{"_id": "r1", "_source": map[string]any{"message": "hello from filebeat"}, "sort": []any{1}},
		{"_id": "r2", "_source": map[string]any{"foo": "bar"}, "sort": []any{2}}, // no message field
	}
	srv, _ := mockES(t, hits)

	p := New(Config{Address: srv.URL, Index: "filebeat-*", Mode: ModeRaw}, nil)
	events, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 2 || len(events) != 2 {
		t.Fatalf("want 2/2, got %d/%d", n, len(events))
	}
	if events[0].Event.Original != "hello from filebeat" {
		t.Fatalf("message not extracted: %q", events[0].Event.Original)
	}
	if events[0].Event.Dataset != "filebeat" {
		t.Fatalf("dataset not derived from index: %q", events[0].Event.Dataset)
	}
	// The doc without a message field falls back to the raw JSON as the original.
	if !strings.Contains(events[1].Event.Original, "foo") {
		t.Fatalf("raw fallback lost the source JSON: %q", events[1].Event.Original)
	}
}

func TestNewResumeFromCursor(t *testing.T) {
	srv, captured := mockES(t, nil) // no hits
	cursor := []json.RawMessage{json.RawMessage(`1752000000000`)}
	p := New(Config{Address: srv.URL, Index: "wazuh-alerts-*"}, cursor)
	if _, _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	q := (*captured)[0]
	sa, ok := q["search_after"].([]any)
	if !ok || len(sa) != 1 {
		t.Fatalf("resumed poll must send the persisted search_after, got %v", q["search_after"])
	}
}
