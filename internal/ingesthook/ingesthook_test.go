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
	h := NewStatic(pub, "s3cret")

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
	h := NewStatic(pub, "t")

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

func TestWebhookWazuhJSON(t *testing.T) {
	pub := &capturePub{}
	h := NewStatic(pub, "t")

	// A Wazuh alert JSON object -> mapped to a rich event (source IP, label, MITRE).
	alert := `{"rule":{"level":5,"id":"5503","description":"PAM: User login failed.","groups":["pam","authentication_failed"],"mitre":{"id":["T1110.001"],"tactic":["Credential Access"]}},"data":{"srcip":"185.150.190.165","dstuser":"root"},"agent":{"name":"DEV-SERVER-DEUS"},"full_log":"pam auth failure","timestamp":"2026-06-28T17:10:06+0000"}`
	req := httptest.NewRequest(http.MethodPost, "/api/ingest/webhook?token=t", strings.NewReader(alert))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || len(pub.msgs) != 1 {
		t.Fatalf("wazuh alert: code=%d msgs=%d, want 200/1", rr.Code, len(pub.msgs))
	}
	var ev ingest.Event
	json.Unmarshal(pub.msgs[0], &ev)
	if ev.Source == nil || ev.Source.IP != "185.150.190.165" {
		t.Fatalf("source IP not mapped from Wazuh JSON: %+v", ev.Source)
	}
	if ev.DeusWatch.Label != "credential_access" || ev.Agent == nil || ev.Agent.ID != "wazuh-agent/DEV-SERVER-DEUS" {
		t.Fatalf("label/agent tag wrong: label=%q agent=%+v", ev.DeusWatch.Label, ev.Agent)
	}

	// An ARRAY of Wazuh alerts.
	pub.msgs = nil
	req = httptest.NewRequest(http.MethodPost, "/api/ingest/webhook?token=t", strings.NewReader("["+alert+","+alert+"]"))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || len(pub.msgs) != 2 {
		t.Fatalf("wazuh array: code=%d msgs=%d, want 200/2", rr.Code, len(pub.msgs))
	}
}

func TestWebhookDisabledWithoutToken(t *testing.T) {
	h := NewStatic(&capturePub{}, "")
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

// The token is read per request (from the DB in production), so a UI enable/regenerate/disable
// takes effect immediately without a restart. Verify the handler honors the live value.
func TestWebhookDynamicToken(t *testing.T) {
	current := "" // starts disabled, as after a fresh install with no INGEST_WEBHOOK_TOKEN
	h := New(&capturePub{}, func(context.Context) (string, error) { return current, nil })

	post := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/ingest/webhook?token="+token, strings.NewReader("x"))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	// Disabled -> 404 regardless of the presented token.
	if code := post("anything"); code != http.StatusNotFound {
		t.Fatalf("disabled: got %d, want 404", code)
	}
	// UI generates a token -> the same handler now accepts it, no restart.
	current = "fresh-token"
	if code := post("fresh-token"); code != http.StatusOK {
		t.Fatalf("after enable: got %d, want 200", code)
	}
	// Regenerate -> the old token is instantly rejected.
	current = "rotated-token"
	if code := post("fresh-token"); code != http.StatusUnauthorized {
		t.Fatalf("old token after regenerate: got %d, want 401", code)
	}
	if code := post("rotated-token"); code != http.StatusOK {
		t.Fatalf("new token: got %d, want 200", code)
	}
	// A lookup error must fail closed (disabled), never open.
	h2 := New(&capturePub{}, func(context.Context) (string, error) { return "x", errBadJSON })
	if h2.Enabled() {
		t.Fatal("token lookup error must fail closed (disabled)")
	}
}
