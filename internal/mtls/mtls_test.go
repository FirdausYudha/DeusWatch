package mtls

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestMTLSHandshake proves two things at once over a freshly generated certificate
// bundle:
//   - a client with a valid certificate SUCCEEDS in reaching the mTLS server;
//   - a client WITHOUT a certificate is REJECTED during the handshake.
func TestMTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	paths, err := GenerateBundle(Options{
		Dir:       dir,
		ServerDNS: []string{"localhost"},
		ServerIPs: []net.IP{net.ParseIP("127.0.0.1")},
		ValidFor:  time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	srvCfg, err := ServerConfig(paths)
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	ts.TLS = srvCfg
	ts.StartTLS()
	defer ts.Close()

	// Case 1 — a client with a valid certificate must get through.
	cliCfg, err := ClientConfig(paths)
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	authedClient := &http.Client{Transport: &http.Transport{TLSClientConfig: cliCfg}}
	resp, err := authedClient.Get(ts.URL)
	if err != nil {
		t.Fatalf("valid client should get through, but failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("unexpected body: %q", body)
	}
	t.Log("OK: client with a valid certificate connected successfully")

	// Case 2 — a client WITHOUT a certificate (trusts the server but presents no
	// identity) must be rejected by the server during the handshake.
	pool, err := caPool(paths.CACert)
	if err != nil {
		t.Fatalf("caPool: %v", err)
	}
	noCertCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	anonClient := &http.Client{Transport: &http.Transport{TLSClientConfig: noCertCfg}}
	if _, err := anonClient.Get(ts.URL); err == nil {
		t.Fatal("client WITHOUT a certificate should be REJECTED, but got through")
	} else {
		t.Logf("OK: client without a certificate was rejected as expected (%v)", err)
	}
}
