package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/mtls"
)

func TestHeartbeatHandlerRevoked(t *testing.T) {
	withCN := func(cn string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
		return r
	}
	seen := map[string]bool{}
	seenFn := func(_ context.Context, cn string) error { seen[cn] = true; return nil }
	revokedFn := func(_ context.Context, cn string) (bool, error) { return cn == "bad-agent", nil }
	h := HeartbeatHandler(seenFn, nil, revokedFn)

	// A revoked agent gets 410 Gone (its cue to self-uninstall) and is not marked seen.
	rr := httptest.NewRecorder()
	h(rr, withCN("bad-agent"))
	if rr.Code != http.StatusGone {
		t.Fatalf("revoked agent: got %d, want 410", rr.Code)
	}
	if seen["bad-agent"] {
		t.Fatal("a revoked agent must not be marked seen")
	}

	// A healthy agent gets 204 and is marked seen (no HealthFunc -> SeenFunc fallback).
	rr = httptest.NewRecorder()
	h(rr, withCN("good-agent"))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("healthy agent: got %d, want 204", rr.Code)
	}
	if !seen["good-agent"] {
		t.Fatal("a healthy agent should be marked seen")
	}
}

// TestHeartbeatHandlerHealth verifies the optional JSON body reaches the HealthFunc
// and that an empty body (old agents) decodes as healthy - backward compatible.
func TestHeartbeatHandlerHealth(t *testing.T) {
	withBody := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", strings.NewReader(body))
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "a1"}}}}
		return r
	}
	var gotDegraded bool
	var gotDetail string
	healthFn := func(_ context.Context, _ string, degraded bool, detail string) error {
		gotDegraded, gotDetail = degraded, detail
		return nil
	}
	h := HeartbeatHandler(nil, healthFn, nil)

	rr := httptest.NewRecorder()
	h(rr, withBody(`{"degraded":true,"detail":"12 buffered batch(es) awaiting delivery"}`))
	if rr.Code != http.StatusNoContent || !gotDegraded || gotDetail == "" {
		t.Fatalf("degraded heartbeat not recorded (code=%d degraded=%v detail=%q)", rr.Code, gotDegraded, gotDetail)
	}

	rr = httptest.NewRecorder()
	h(rr, withBody("")) // old agent: empty body = healthy
	if rr.Code != http.StatusNoContent || gotDegraded {
		t.Fatalf("empty-body heartbeat must decode as healthy (code=%d degraded=%v)", rr.Code, gotDegraded)
	}
}

type fakePublisher struct {
	mu   sync.Mutex
	msgs [][]byte
}

func (f *fakePublisher) Publish(_ context.Context, _ string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, append([]byte(nil), data...))
	return nil
}

// TestGatewayMTLSIngest proves the 5.3 chain: a certificated agent POSTs raw logs
// over mTLS -> gateway normalizes to DCS -> publish; and a client without a
// certificate is rejected. Self-contained (no NATS/Postgres).
func TestGatewayMTLSIngest(t *testing.T) {
	dir := t.TempDir()
	paths, err := mtls.GenerateBundle(mtls.Options{
		Dir: dir, ServerDNS: []string{"localhost"},
		ServerIPs: []net.IP{net.ParseIP("127.0.0.1")}, ValidFor: time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	srvCfg, err := mtls.ServerConfig(paths)
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}

	pub := &fakePublisher{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", LogsHandler(pub, nil))

	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = srvCfg
	ts.StartTLS()
	defer ts.Close()

	// Valid mTLS client.
	cliCfg, err := mtls.ClientConfig(paths)
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cliCfg}}

	batch := []ingest.RawLog{
		{Dataset: "sshd", Host: "web01", Message: "Failed password for root from 203.0.113.10 port 54321 ssh2"},
		{Dataset: "sshd", Host: "web01", Message: "Accepted password for deploy from 10.0.0.5 port 22 ssh2"},
	}
	body, _ := json.Marshal(batch)
	resp, err := client.Post(ts.URL+"/v1/logs", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("valid POST failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var out struct {
		Accepted int `json:"accepted"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Accepted != 2 {
		t.Fatalf("accepted=%d, want 2", out.Accepted)
	}
	if len(pub.msgs) != 2 {
		t.Fatalf("published=%d, want 2", len(pub.msgs))
	}

	var e0 ingest.Event
	if err := json.Unmarshal(pub.msgs[0], &e0); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e0.Event.Outcome != "failure" || e0.Source == nil || e0.Source.IP != "203.0.113.10" || e0.User == nil || e0.User.Name != "root" {
		t.Fatalf("wrong sshd normalization: %+v", e0)
	}
	if e0.Agent == nil || e0.Agent.ID != "deuswatch-agent" {
		t.Fatalf("agent id should come from the certificate CN: %+v", e0.Agent)
	}
	t.Logf("OK: 2 logs via mTLS -> DCS (failed login from %s user %s, agent %s)",
		e0.Source.IP, e0.User.Name, e0.Agent.ID)

	// Negative: a client without a certificate is rejected by the gateway.
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: cliCfg.RootCAs, MinVersion: tls.VersionTLS13,
	}}}
	if _, err := anon.Post(ts.URL+"/v1/logs", "application/json", strings.NewReader("[]")); err == nil {
		t.Fatal("a client without a certificate should be REJECTED")
	}
}
