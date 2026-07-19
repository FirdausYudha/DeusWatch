package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"deuswatch/internal/score"
)

// seedEvent inserts one event at `ago` in the past for the given IP/agent.
func seedEvent(t *testing.T, st *Store, ctx context.Context, ip, agent string, ago time.Duration, uri string) {
	t.Helper()
	_, err := st.pool.Exec(ctx, `
		INSERT INTO events (time, event_category, event_severity, source_ip, agent_id, http_uri, event_dataset)
		VALUES (now() - $1::interval, 'network', 1, $2::inet, $3, NULLIF($4,''), 'test')`,
		fmt.Sprintf("%d seconds", int(ago.Seconds())), ip, agent, uri)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSlowScannerDetection proves the multi-day pattern static rules can't catch: a source that
// returns on several separate days at low volume is listed, while a one-day burst is NOT (that is
// the burst rules' job) and a source seen on too few days doesn't qualify at all.
func TestSlowScannerDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	slow, burst, rare := "203.0.113.201", "203.0.113.202", "203.0.113.203"
	cleanup := func() {
		for _, ip := range []string{slow, burst, rare} {
			_, _ = st.pool.Exec(ctx, `DELETE FROM events WHERE source_ip = $1::inet`, ip)
		}
		_, _ = st.pool.Exec(ctx, `DELETE FROM slow_scanners WHERE host(ip) = ANY($1)`, []string{slow, burst, rare})
	}
	cleanup()
	defer cleanup()

	day := 24 * time.Hour
	// The patient scanner: a couple of probes on five separate days.
	for _, d := range []int{1, 3, 4, 7, 9} {
		seedEvent(t, st, ctx, slow, "web01", time.Duration(d)*day, fmt.Sprintf("/probe%d", d))
		seedEvent(t, st, ctx, slow, "web01", time.Duration(d)*day+time.Hour, fmt.Sprintf("/probe%d-b", d))
	}
	// A loud one-day burst: many events, but all on a single day → not a SLOW scanner.
	for i := 0; i < 200; i++ {
		seedEvent(t, st, ctx, burst, "web01", 2*day+time.Duration(i)*time.Second, "/login")
	}
	// Seen on only two days → below the recurrence floor.
	seedEvent(t, st, ctx, rare, "web01", 1*day, "/x")
	seedEvent(t, st, ctx, rare, "web01", 2*day, "/y")

	found, err := st.RefreshSlowScanners(ctx, 14*day, score.DefaultSlowScanWeights())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	byIP := map[string]SlowScanner{}
	for _, r := range found {
		byIP[r.IP] = r
	}

	got, ok := byIP[slow]
	if !ok {
		t.Fatalf("the patient scanner must be listed; got %+v", found)
	}
	if got.ActiveDays != 5 {
		t.Fatalf("expected 5 active days, got %d", got.ActiveDays)
	}
	if got.Score < 40 {
		t.Fatalf("a 5-day low-volume scanner should score meaningfully, got %d", got.Score)
	}
	if _, listed := byIP[rare]; listed {
		t.Fatal("a source seen on only 2 days must not qualify as a slow scanner")
	}
	// The burst is a single day → it either doesn't qualify, or scores below the patient scanner.
	if b, listed := byIP[burst]; listed && b.Score >= got.Score {
		t.Fatalf("a one-day burst must not outrank a multi-day scanner: burst=%d slow=%d", b.Score, got.Score)
	}
}

// TestCrossAgentFanOutRaisesScore proves the new ban rule end-to-end through the real scorer:
// the same activity spread across several agents outscores the same volume against one.
func TestCrossAgentFanOutRaisesScore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	single, spread := "203.0.113.211", "203.0.113.212"
	cleanup := func() {
		for _, ip := range []string{single, spread} {
			_, _ = st.pool.Exec(ctx, `DELETE FROM events WHERE source_ip = $1::inet`, ip)
			_, _ = st.pool.Exec(ctx, `DELETE FROM ip_scores WHERE host(ip) = $1`, ip)
		}
	}
	cleanup()
	defer cleanup()

	// Same event count for both; only the number of distinct agents differs.
	for i := 0; i < 6; i++ {
		seedEvent(t, st, ctx, single, "web01", time.Duration(i)*time.Minute, "/a")
	}
	agents := []string{"web01", "db01", "mail01", "gw01", "app01", "ws01"}
	for i := 0; i < 6; i++ {
		seedEvent(t, st, ctx, spread, agents[i], time.Duration(i)*time.Minute, "/a")
	}

	scores, err := st.RefreshIPScores(ctx, time.Hour, score.DefaultWeights())
	if err != nil {
		t.Fatalf("refresh scores: %v", err)
	}
	byIP := map[string]IPScore{}
	for _, r := range scores {
		byIP[r.IP] = r
	}
	one, many := byIP[single], byIP[spread]
	if one.IP == "" || many.IP == "" {
		t.Fatalf("both IPs should be scored, got %+v", scores)
	}
	if many.Agents != 6 || one.Agents != 1 {
		t.Fatalf("agent fan-out miscounted: single=%d spread=%d", one.Agents, many.Agents)
	}
	if many.Score <= one.Score {
		t.Fatalf("attacking many agents must score higher: single=%d spread=%d", one.Score, many.Score)
	}
}
