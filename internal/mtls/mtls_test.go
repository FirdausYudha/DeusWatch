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

// TestMTLSHandshake membuktikan dua hal sekaligus di atas bundel sertifikat
// yang baru di-generate:
//   - client dengan sertifikat sah BERHASIL menembus server mTLS;
//   - client TANPA sertifikat DITOLAK pada saat handshake.
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

	// Kasus 1 — client dengan sertifikat sah harus tembus.
	cliCfg, err := ClientConfig(paths)
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	authedClient := &http.Client{Transport: &http.Transport{TLSClientConfig: cliCfg}}
	resp, err := authedClient.Get(ts.URL)
	if err != nil {
		t.Fatalf("client sah seharusnya tembus, tapi gagal: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body tak terduga: %q", body)
	}
	t.Log("OK: client dengan sertifikat sah berhasil terhubung")

	// Kasus 2 — client TANPA sertifikat (mempercayai server, tapi tak menyodorkan
	// identitas) harus ditolak server pada handshake.
	pool, err := caPool(paths.CACert)
	if err != nil {
		t.Fatalf("caPool: %v", err)
	}
	noCertCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	anonClient := &http.Client{Transport: &http.Transport{TLSClientConfig: noCertCfg}}
	if _, err := anonClient.Get(ts.URL); err == nil {
		t.Fatal("client TANPA sertifikat seharusnya DITOLAK, tapi malah tembus")
	} else {
		t.Logf("OK: client tanpa sertifikat ditolak sebagaimana mestinya (%v)", err)
	}
}
