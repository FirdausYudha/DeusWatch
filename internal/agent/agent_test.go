package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"deuswatch/internal/gateway"
	"deuswatch/internal/ingest"
	"deuswatch/internal/mtls"
)

type capturePub struct {
	mu     sync.Mutex
	events []ingest.Event
}

func (c *capturePub) Publish(_ context.Context, _ string, data []byte) error {
	var e ingest.Event
	if err := json.Unmarshal(data, &e); err != nil {
		return err
	}
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
	return nil
}

func (c *capturePub) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// TestAgentTailAndShipOverMTLS proves the 5.4 slice: the agent tails a log file,
// sends lines over mTLS to the gateway, and the gateway normalizes them. Self-contained.
func TestAgentTailAndShipOverMTLS(t *testing.T) {
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
	pub := &capturePub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", gateway.LogsHandler(pub, nil))
	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = srvCfg
	ts.StartTLS()
	defer ts.Close()

	// Seed an auth.log.
	logPath := filepath.Join(dir, "auth.log")
	content := "Failed password for root from 198.51.100.23 port 4444 ssh2\n" +
		"Failed password for invalid user oracle from 198.51.100.23 port 4445 ssh2\n" +
		"Accepted password for deploy from 10.0.0.9 port 22 ssh2\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Tail from the start (short timeout) then collect into a batch.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	lines := make(chan string, 16)
	go func() {
		_ = FollowFile(ctx, logPath, true, lines)
		close(lines)
	}()
	var batch []ingest.RawLog
	for l := range lines {
		batch = append(batch, ingest.RawLog{Timestamp: time.Now(), Host: "web01", Dataset: "sshd", Message: l})
	}
	if len(batch) != 3 {
		t.Fatalf("tail got %d lines, want 3", len(batch))
	}

	shipper, err := NewShipper(ts.URL, paths)
	if err != nil {
		t.Fatalf("NewShipper: %v", err)
	}
	if err := shipper.Send(context.Background(), batch); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if pub.count() != 3 {
		t.Fatalf("gateway received %d events, want 3", pub.count())
	}
	pub.mu.Lock()
	e0 := pub.events[0]
	pub.mu.Unlock()
	if e0.Event.Outcome != "failure" || e0.Source == nil || e0.Source.IP != "198.51.100.23" {
		t.Fatalf("wrong normalization of the first event: %+v", e0)
	}
	t.Logf("OK: agent tail 3 lines -> ship mTLS -> gateway normalization (failed login from %s)", e0.Source.IP)
}
