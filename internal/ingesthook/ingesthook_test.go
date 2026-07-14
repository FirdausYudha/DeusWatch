package ingesthook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"deuswatch/internal/bus"
	"deuswatch/internal/ingest"
)

type capturePub struct{ msgs [][]byte }

func (c *capturePub) Publish(_ context.Context, subject string, data []byte) error {
	if subject == bus.SubjectLogsNormalized {
		c.msgs = append(c.msgs, append([]byte(nil), data...))
	}
	return nil
}

func TestWebhookAuthAndTag(t *testing.T) {
	pub := &capturePub{}
	h := New(pub, "s3cret")

	// Wrong token -> 401.
	req := httptest.NewRequest(http.MethodPost, "/api/ingest/webhook?token=wrong", strings.NewReader("hello"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", rr.Code)
	}

	// Correct token + agent name -> event published, tagged wazuh-agent/<name>.
	body := "Jan 1 00:00:00 host sshd[1]: Failed password for admin from 1.2.3.4 port 22 ssh2"
	req = httptest.NewRequest(http.MethodPost, "/api/ingest/webhook?token=s3cret&agent=web-01&dataset=wazuh&host=web-01", strings.NewReader(body))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid post: got %d, want 200", rr.Code)
	}
	if len(pub.msgs) != 1 {
		t.Fatalf("want 1 published event, got %d", len(pub.msgs))
	}
	var ev ingest.Event
	if err := json.Unmarshal(pub.msgs[0], &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.Agent == nil || ev.Agent.ID != "wazuh-agent/web-01" {
		t.Fatalf("agent tag = %+v, want wazuh-agent/web-01", ev.Agent)
	}
	if ev.Event.Dataset != "wazuh" || ev.Event.Original != body {
		t.Fatalf("dataset/original not preserved: %+v", ev.Event)
	}
}

func TestWebhookMultiLineAndJSON(t *testing.T) {
	pub := &capturePub{}
	h := New(pub, "t")

	// Newline-separated text: 3 lines, one blank (skipped) -> 2 events.
	req := httptest.NewRequest(http.MethodPost, "/api/ingest/webhook?token=t", strings.NewReader("line one\n\nline two\n"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || len(pub.msgs) != 2 {
		t.Fatalf("text lines: code=%d msgs=%d, want 200/2", rr.Code, len(pub.msgs))
	}

	// JSON array of strings.
	pub.msgs = nil
	req = httptest.NewRequest(http.MethodPost, "/api/ingest/webhook?token=t", strings.NewReader(`["a","b","c"]`))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || len(pub.msgs) != 3 {
		t.Fatalf("json array: code=%d msgs=%d, want 200/3", rr.Code, len(pub.msgs))
	}
}

func TestWebhookDisabledWithoutToken(t *testing.T) {
	h := New(&capturePub{}, "")
	if h.Enabled() {
		t.Fatal("empty token must leave the webhook disabled")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/ingest/webhook", strings.NewReader("x"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("disabled webhook: got %d, want 404", rr.Code)
	}
}
