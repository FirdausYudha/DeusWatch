package bus

import (
	"context"
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

// TestPublishConsumeRoundTrip membuktikan publish -> JetStream -> consume bekerja
// melawan NATS yang sedang berjalan. Di-skip bila NATS tak tersedia (unit-only run).
func TestPublishConsumeRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	b, err := Connect(ctx, natsURL())
	if err != nil {
		t.Skipf("NATS tidak tersedia di %s — lewati: %v", natsURL(), err)
	}
	defer b.Close()

	got := make(chan string, 1)
	stop, err := b.Consume(ctx, StreamLogs, "test-roundtrip", SubjectLogsRaw,
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
			t.Fatalf("payload tak cocok: got %q want %q", msg, payload)
		}
		t.Logf("OK: round-trip JetStream berhasil")
	case <-time.After(8 * time.Second):
		t.Fatal("timeout: pesan tidak diterima consumer")
	}
}
