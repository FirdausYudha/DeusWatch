package gateway

import (
	"context"
	"crypto/tls"
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

// TestGatewayMTLSIngest membuktikan rantai 5.3: agent ber-sertifikat POST log
// mentah lewat mTLS -> gateway normalisasi ke DCS -> publish; dan client tanpa
// sertifikat ditolak. Self-contained (tanpa NATS/Postgres).
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
	mux.HandleFunc("/v1/logs", LogsHandler(pub))

	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = srvCfg
	ts.StartTLS()
	defer ts.Close()

	// Client mTLS sah.
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
		t.Fatalf("POST sah gagal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, mau 200", resp.StatusCode)
	}
	var out struct {
		Accepted int `json:"accepted"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Accepted != 2 {
		t.Fatalf("accepted=%d, mau 2", out.Accepted)
	}
	if len(pub.msgs) != 2 {
		t.Fatalf("published=%d, mau 2", len(pub.msgs))
	}

	var e0 ingest.Event
	if err := json.Unmarshal(pub.msgs[0], &e0); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e0.Event.Outcome != "failure" || e0.Source == nil || e0.Source.IP != "203.0.113.10" || e0.User == nil || e0.User.Name != "root" {
		t.Fatalf("normalisasi sshd salah: %+v", e0)
	}
	if e0.Agent == nil || e0.Agent.ID != "deuswatch-agent" {
		t.Fatalf("agent id seharusnya dari CN sertifikat: %+v", e0.Agent)
	}
	t.Logf("OK: 2 log via mTLS -> DCS (failed login dari %s user %s, agent %s)",
		e0.Source.IP, e0.User.Name, e0.Agent.ID)

	// Negatif: client tanpa sertifikat ditolak gateway.
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: cliCfg.RootCAs, MinVersion: tls.VersionTLS13,
	}}}
	if _, err := anon.Post(ts.URL+"/v1/logs", "application/json", strings.NewReader("[]")); err == nil {
		t.Fatal("client tanpa sertifikat seharusnya DITOLAK")
	}
}
