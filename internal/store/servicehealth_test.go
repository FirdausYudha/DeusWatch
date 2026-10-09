package store

import (
	"context"
	"testing"
	"time"
)

// TestResponderHealthRoundTrip proves the worker's enforcement-backend probe survives the
// service_heartbeats detail column as JSON and reads back intact, and that a component that has
// never reported comes back ok=false (not an error) so the api can fall back rather than claim the
// firewall is down. Integration, skipped if Postgres is down.
func TestResponderHealthRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	st, err := ConnectSuperadmin(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable, skipping: %v", err)
	}
	defer st.Close()

	if _, err := st.pool.Exec(ctx, "DELETE FROM service_heartbeats WHERE service = $1", ServiceResponder); err != nil {
		t.Fatalf("clear responder heartbeat: %v", err)
	}

	// Never reported: a real state, not a lookup failure.
	if _, _, ok, err := st.ResponderHealthNow(ctx); err != nil || ok {
		t.Fatalf("an unreported responder must be ok=false with no error, got ok=%v err=%v", ok, err)
	}

	want := ResponderHealth{
		Backend: "nftables", Live: true, Checked: true, Healthy: false,
		Detail: "nftables set 'inet deuswatch banlist' is not usable",
	}
	if err := st.UpsertResponderHealth(ctx, "test", want); err != nil {
		t.Fatalf("upsert responder health: %v", err)
	}

	got, sh, ok, err := st.ResponderHealthNow(ctx)
	if err != nil || !ok {
		t.Fatalf("read back: ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	if !sh.Alive {
		t.Fatalf("a heartbeat written moments ago must read as alive, got age=%.0fs", sh.Age)
	}
}
