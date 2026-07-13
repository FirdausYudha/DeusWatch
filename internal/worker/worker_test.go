package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"deuswatch/internal/bus"
	"deuswatch/internal/detect"
	"deuswatch/internal/ingest"
	"deuswatch/internal/store"
)

// recSink records inserted events (a fake EventSink, no DB).
type recSink struct{ events []*ingest.Event }

func (r *recSink) InsertEvent(_ context.Context, e *ingest.Event) error {
	r.events = append(r.events, e)
	return nil
}

// stubDetector always returns the pre-built alert.
type stubDetector struct{ alert *ingest.Event }

func (d stubDetector) Inspect(_ *ingest.Event) *ingest.Event { return d.alert }

// TestHandlerSuppressesGatedAlert proves the trusted-session gate path: a suppressed alert is
// neither stored nor forwarded to onAlert, while the raw source event still is. The inverse
// case (not suppressed) stores the alert and calls onAlert.
func TestHandlerSuppressesGatedAlert(t *testing.T) {
	raw, _ := json.Marshal(ingest.Event{Event: ingest.EventFields{Category: "file", Action: "file_modified"}})
	alert := &ingest.Event{
		Event: ingest.EventFields{Category: "intrusion_detection", Dataset: "deuswatch.detect"},
		File:  &ingest.File{Path: "/var/www/html/index.php"},
		DeusWatch: ingest.DeusWatch{Label: "impact"},
	}

	for _, tc := range []struct {
		name       string
		suppress   AlertSuppressor
		wantStored int // raw + (alert unless suppressed)
		wantHook   bool
	}{
		{"suppressed", func(context.Context, *ingest.Event) bool { return true }, 1, false},
		{"kept", func(context.Context, *ingest.Event) bool { return false }, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &recSink{}
			hookCalled := false
			h := Handler(context.Background(), sink, nil,
				func(context.Context, *ingest.Event) { hookCalled = true },
				tc.suppress, nil, stubDetector{alert})
			if err := h(bus.SubjectLogsNormalized, raw); err != nil {
				t.Fatalf("handler: %v", err)
			}
			if len(sink.events) != tc.wantStored {
				t.Fatalf("stored %d events, want %d", len(sink.events), tc.wantStored)
			}
			if hookCalled != tc.wantHook {
				t.Fatalf("onAlert called=%v, want %v", hookCalled, tc.wantHook)
			}
		})
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// TestPipelineEndToEnd proves the full chain: publish a normalized event to NATS
// -> worker consumes -> persist + detect -> a brute-force alert stored in events.
// Integration: skipped if NATS or Postgres is unavailable.
func TestPipelineEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.Connect(ctx, envOr("STORE_DSN", "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"))
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer st.Close()

	b, err := bus.Connect(ctx, envOr("NATS_URL", "nats://localhost:4222"))
	if err != nil {
		t.Skipf("NATS unavailable: %v", err)
	}
	defer b.Close()

	// Unique IP (TEST-NET) + unique durable so runs don't collide with each other / the real worker.
	nonce := time.Now().UnixNano() & 0xffff
	ip := fmt.Sprintf("198.18.%d.%d", (nonce>>8)&0xff, nonce&0xff)
	durable := fmt.Sprintf("test-pipeline-%d", nonce)

	det := detect.NewBruteForceDetector(detect.DefaultBruteForceConfig()) // threshold 5
	stop, err := b.Consume(ctx, bus.StreamLogs, durable, bus.SubjectLogsNormalized, Handler(ctx, st, nil, nil, nil, nil, det))
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	defer stop()

	// 6 failed SSH logins from the same IP -> the 5th failure fires an alert.
	now := time.Now()
	for i := 0; i < 6; i++ {
		e := ingest.Event{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Event: ingest.EventFields{
				Category: "authentication", Action: "ssh_login", Outcome: "failure",
				Dataset: "sshd", Severity: ingest.SeverityMedium, Original: "Failed password for root",
			},
			Source: &ingest.Endpoint{IP: ip, Port: 54321},
			Host:   &ingest.Host{Name: "web01", OSType: "linux"},
			User:   &ingest.User{Name: "root"},
		}
		data, _ := json.Marshal(e)
		if err := b.Publish(ctx, bus.SubjectLogsNormalized, data); err != nil {
			t.Fatalf("Publish #%d: %v", i, err)
		}
	}

	var total, alerts int64
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		total, _ = st.CountBySourceIP(ctx, ip)
		alerts, _ = st.CountByLabelAndSourceIP(ctx, "bruteforce", ip)
		if total >= 6 && alerts >= 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if total < 6 {
		t.Fatalf("events stored for %s = %d, want >= 6", ip, total)
	}
	if alerts < 1 {
		t.Fatalf("brute-force alerts for %s = %d, want >= 1", ip, alerts)
	}
	t.Logf("OK: end-to-end — %d events from %s stored, %d brute-force alerts detected", total, ip, alerts)
}
