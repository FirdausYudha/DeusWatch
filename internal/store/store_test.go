package store

import (
	"context"
	"os"
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

func dsn() string {
	if d := os.Getenv("STORE_DSN"); d != "" {
		return d
	}
	return "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
}

// TestInsertAndCount proves InsertEvent writes to the events hypertable and
// CountByLabel can read labeled events. Integration — skipped if Postgres is down.
func TestInsertAndCount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	if _, err := st.pool.Exec(ctx, "TRUNCATE events"); err != nil {
		t.Fatalf("initial truncate: %v", err)
	}

	rawLog := &ingest.Event{
		Timestamp: time.Now(),
		Event: ingest.EventFields{
			Category: "authentication", Action: "ssh_login", Outcome: "failure",
			Severity: ingest.SeverityMedium, Dataset: "sshd",
			Original: "Failed password for root from 203.0.113.10 port 54321 ssh2",
		},
		Source: &ingest.Endpoint{IP: "203.0.113.10", Port: 54321},
		Host:   &ingest.Host{Name: "web01", OSType: "linux"},
		User:   &ingest.User{Name: "root"},
	}
	if err := st.InsertEvent(ctx, rawLog); err != nil {
		t.Fatalf("insert raw: %v", err)
	}

	alert := &ingest.Event{
		Timestamp: time.Now(),
		Event:     ingest.EventFields{Category: "intrusion_detection", Severity: ingest.SeverityHigh, Dataset: "deuswatch.detect"},
		Source:    &ingest.Endpoint{IP: "203.0.113.10"},
		Rule:      &ingest.Rule{ID: "deuswatch-ssh-bruteforce", Name: "SSH Brute Force"},
		Threat:    &ingest.Threat{Technique: ingest.Technique{ID: "T1110", Name: "Brute Force"}, TacticName: "Credential Access"},
		DeusWatch: ingest.DeusWatch{
			Label:      "bruteforce",
			Severity:   ingest.SeverityMeta{Original: ingest.SeverityHigh},
			Enrichment: ingest.Enrichment{Status: ingest.EnrichmentPending},
		},
	}
	if err := st.InsertEvent(ctx, alert); err != nil {
		t.Fatalf("insert alert: %v", err)
	}

	n, err := st.CountEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("CountEvents=%d, want 2", n)
	}
	bf, err := st.CountByLabel(ctx, "bruteforce")
	if err != nil {
		t.Fatal(err)
	}
	if bf != 1 {
		t.Fatalf("CountByLabel(bruteforce)=%d, want 1", bf)
	}
	t.Logf("OK: 2 events stored in the hypertable, 1 labeled bruteforce")

	_, _ = st.pool.Exec(ctx, "TRUNCATE events")
}
