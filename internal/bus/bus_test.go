package bus

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func natsURL() string {
	if u := os.Getenv("NATS_URL"); u != "" {
		return u
	}
	return "nats://localhost:4222"
}

// TestPublishConsumeRoundTrip proves publish -> JetStream -> consume works against a
// running NATS. Skipped when NATS is unavailable (unit-only run).
func TestPublishConsumeRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	b, err := Connect(ctx, natsURL())
	if err != nil {
		t.Skipf("NATS unavailable at %s — skipping: %v", natsURL(), err)
	}
	defer b.Close()

	got := make(chan string, 1)
	durable := fmt.Sprintf("test-roundtrip-%d", time.Now().UnixNano())
	stop, err := b.Consume(ctx, StreamLogs, durable, SubjectLogsRaw,
		func(_ string, data []byte) error {
			select {
			case got <- string(data):
			default:
			}
			return nil
		})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	defer stop()

	payload := "hello-deuswatch-" + time.Now().Format(time.RFC3339Nano)
	if err := b.Publish(ctx, SubjectLogsRaw, []byte(payload)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case msg := <-got:
		if msg != payload {
			t.Fatalf("payload mismatch: got %q want %q", msg, payload)
		}
		t.Logf("OK: JetStream round-trip succeeded")
	case <-time.After(8 * time.Second):
		t.Fatal("timeout: message not received by consumer")
	}
}
