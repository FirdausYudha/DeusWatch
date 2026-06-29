package enrich

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/ingest"
)

func TestApplyEscalation(t *testing.T) {
	ev := &ingest.Event{
		Event:  ingest.EventFields{Severity: ingest.SeverityLow},
		Source: &ingest.Endpoint{IP: "45.155.205.99"},
	}
	ev.DeusWatch.Severity.Original = ev.Event.Severity // EnrichEvent captures this before escalation
	applyIPIndicator(ev, Indicator{AbuseConfidence: 95, OTXPulseCount: 8, CountryISO: "RU", FeedName: "mock"}, DefaultEscalationRules())

	if ev.Event.Severity != ingest.SeverityHigh { // low +1 (abuse) +1 (otx) = high
		t.Fatalf("wrong escalated severity: %v (want high)", ev.Event.Severity)
	}
	if ev.DeusWatch.Severity.Original != ingest.SeverityLow {
		t.Fatalf("original severity should be kept as low, got %v", ev.DeusWatch.Severity.Original)
	}
	if ev.DeusWatch.Severity.EscalatedBy == "" {
		t.Fatal("escalated_by should be set")
	}
	if ev.DeusWatch.Enrichment.Status != ingest.EnrichmentEnriched {
		t.Fatalf("wrong enrichment status: %v", ev.DeusWatch.Enrichment.Status)
	}
	if ev.DeusWatch.Enrichment.AbuseConfidence == nil || *ev.DeusWatch.Enrichment.AbuseConfidence != 95 {
		t.Fatal("abuse_confidence not set")
	}
	if ev.Threat == nil || ev.Threat.Indicator == nil || ev.Threat.Indicator.IP != "45.155.205.99" {
		t.Fatalf("threat.indicator not set: %+v", ev.Threat)
	}
	if ev.Source.Geo == nil || ev.Source.Geo.CountryISOCode != "RU" {
		t.Fatalf("geo country not set: %+v", ev.Source.Geo)
	}
}

func TestNoEscalationBenign(t *testing.T) {
	ev := &ingest.Event{
		Event:  ingest.EventFields{Severity: ingest.SeverityMedium},
		Source: &ingest.Endpoint{IP: "10.0.0.5"},
	}
	applyIPIndicator(ev, Indicator{AbuseConfidence: 5, OTXPulseCount: 0}, DefaultEscalationRules())
	if ev.Event.Severity != ingest.SeverityMedium || ev.DeusWatch.Severity.EscalatedBy != "" {
		t.Fatal("a benign IP must not escalate severity")
	}
}

func TestCustomEscalationThreshold(t *testing.T) {
	ev := &ingest.Event{
		Event:  ingest.EventFields{Severity: ingest.SeverityLow},
		Source: &ingest.Endpoint{IP: "1.2.3.4"},
	}
	// Stricter thresholds: abuse>=50 triggers escalation; otx>=100 does not.
	applyIPIndicator(ev, Indicator{AbuseConfidence: 60, OTXPulseCount: 3}, EscalationRules{AbuseThreshold: 50, OTXThreshold: 100})
	if ev.Event.Severity != ingest.SeverityMedium { // low +1 (abuse only)
		t.Fatalf("wrong severity: %v (want medium)", ev.Event.Severity)
	}
}

func dsn() string {
	if d := os.Getenv("STORE_DSN"); d != "" {
		return d
	}
	return "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
}

// TestEnricherCacheHit verifies the Postgres cache reduces provider calls.
func TestEnricherCacheHit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	ip := fmt.Sprintf("198.18.%d.%d", time.Now().UnixNano()%256, (time.Now().UnixNano()/256)%256)
	defer pool.Exec(ctx, `DELETE FROM cti_indicators WHERE ip=$1::inet`, ip)

	provider := &MockProvider{Default: Indicator{AbuseConfidence: 77, OTXPulseCount: 3, CountryISO: "NL", FeedName: "mock"}}
	e := NewEnricher(provider, NewCache(pool), time.Hour, DefaultEscalationRules())

	ind1, err := e.lookup(ctx, ip)
	if err != nil {
		t.Fatalf("lookup 1: %v", err)
	}
	ind2, err := e.lookup(ctx, ip)
	if err != nil {
		t.Fatalf("lookup 2: %v", err)
	}
	if provider.Calls != 1 {
		t.Fatalf("provider called %d times, want 1 (second from cache)", provider.Calls)
	}
	if ind1.AbuseConfidence != 77 || ind2.AbuseConfidence != 77 {
		t.Fatalf("inconsistent indicator: %+v / %+v", ind1, ind2)
	}
	t.Logf("OK: TTL cache works — provider 1x, 2nd lookup from Postgres (%s)", ip)
}

// An unknown IP under the mock/demo provider must NOT receive a fabricated abuse score or
// country (it would mislead analysts on real traffic). Guards the honesty fix.
func TestMockUnknownIPHasNoFakeIntel(t *testing.T) {
	ind, _ := NewDemoProvider().Lookup(context.Background(), "154.127.69.8")
	if ind.AbuseConfidence != 0 || ind.CountryISO != "" {
		t.Fatalf("unknown IP must not get a fabricated score/country: %+v", ind)
	}
	ev := &ingest.Event{Source: &ingest.Endpoint{IP: "154.127.69.8"}, Event: ingest.EventFields{Severity: ingest.SeverityLow}}
	applyIPIndicator(ev, ind, DefaultEscalationRules())
	if ev.DeusWatch.Enrichment.AbuseConfidence != nil {
		t.Fatal("abuse confidence must stay nil (shown as — in the UI) for an unknown IP")
	}
	if ev.Source.Geo != nil && ev.Source.Geo.CountryISOCode != "" {
		t.Fatal("country must stay empty for an unknown IP")
	}
}
