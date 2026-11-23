package bus

import (
	"context"
	"fmt"
	"os"
	"strings"
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
		t.Skipf("NATS unavailable at %s, skipping: %v", natsURL(), err)
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

// TestPublishBatchRoundTrip proves PublishBatch pipelines many publishes and only returns once
// every one is durably stored: all N show up on the consumer. Skipped without a running NATS.
func TestPublishBatchRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	b, err := Connect(ctx, natsURL())
	if err != nil {
		t.Skipf("NATS unavailable at %s, skipping: %v", natsURL(), err)
	}
	defer b.Close()

	const n = 50
	tag := time.Now().UnixNano()
	prefix := fmt.Sprintf("batch-%d-", tag)
	subject := SubjectLogsRaw
	seen := make(chan struct{}, n)
	durable := fmt.Sprintf("test-batch-%d", tag)
	stop, err := b.Consume(ctx, StreamLogs, durable, subject,
		func(_ string, data []byte) error {
			// Only count this test's own messages (the stream is shared across runs).
			if strings.HasPrefix(string(data), prefix) {
				select {
				case seen <- struct{}{}:
				default:
				}
			}
			return nil
		})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	defer stop()

	payloads := make([][]byte, n)
	for i := range payloads {
		payloads[i] = []byte(fmt.Sprintf("batch-%d-%d", tag, i))
	}
	if err := b.PublishBatch(ctx, subject, payloads); err != nil {
		t.Fatalf("PublishBatch: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for got := 0; got < n; got++ {
		select {
		case <-seen:
		case <-deadline:
			t.Fatalf("timeout: received %d/%d batched messages", got, n)
		}
	}
	t.Logf("OK: all %d batched messages stored and delivered", n)
}
