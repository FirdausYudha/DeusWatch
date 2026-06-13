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
	applyToEvent(ev, Indicator{AbuseConfidence: 95, OTXPulseCount: 8, CountryISO: "RU", FeedName: "mock"}, DefaultEscalationRules())

	if ev.Event.Severity != ingest.SeverityHigh { // low +1 (abuse) +1 (otx) = high
		t.Fatalf("severity tereskalasi salah: %v (mau high)", ev.Event.Severity)
	}
	if ev.DeusWatch.Severity.Original != ingest.SeverityLow {
		t.Fatalf("severity asli harus tersimpan low, dapat %v", ev.DeusWatch.Severity.Original)
	}
	if ev.DeusWatch.Severity.EscalatedBy == "" {
		t.Fatal("escalated_by harus terisi")
	}
	if ev.DeusWatch.Enrichment.Status != ingest.EnrichmentEnriched {
		t.Fatalf("status enrichment salah: %v", ev.DeusWatch.Enrichment.Status)
	}
	if ev.DeusWatch.Enrichment.AbuseConfidence == nil || *ev.DeusWatch.Enrichment.AbuseConfidence != 95 {
		t.Fatal("abuse_confidence tidak terisi")
	}
	if ev.Threat == nil || ev.Threat.Indicator == nil || ev.Threat.Indicator.IP != "45.155.205.99" {
		t.Fatalf("threat.indicator tidak terisi: %+v", ev.Threat)
	}
	if ev.Source.Geo == nil || ev.Source.Geo.CountryISOCode != "RU" {
		t.Fatalf("geo country tidak terisi: %+v", ev.Source.Geo)
	}
}

func TestNoEscalationBenign(t *testing.T) {
	ev := &ingest.Event{
		Event:  ingest.EventFields{Severity: ingest.SeverityMedium},
		Source: &ingest.Endpoint{IP: "10.0.0.5"},
	}
	applyToEvent(ev, Indicator{AbuseConfidence: 5, OTXPulseCount: 0}, DefaultEscalationRules())
	if ev.Event.Severity != ingest.SeverityMedium || ev.DeusWatch.Severity.EscalatedBy != "" {
		t.Fatal("IP benign tidak boleh mengeskalasi severity")
	}
}

func TestCustomEscalationThreshold(t *testing.T) {
	ev := &ingest.Event{
		Event:  ingest.EventFields{Severity: ingest.SeverityLow},
		Source: &ingest.Endpoint{IP: "1.2.3.4"},
	}
	// Ambang lebih ketat: abuse>=50 memicu eskalasi; otx>=100 tidak.
	applyToEvent(ev, Indicator{AbuseConfidence: 60, OTXPulseCount: 3}, EscalationRules{AbuseThreshold: 50, OTXThreshold: 100})
	if ev.Event.Severity != ingest.SeverityMedium { // low +1 (abuse saja)
		t.Fatalf("severity salah: %v (mau medium)", ev.Event.Severity)
	}
}

func dsn() string {
	if d := os.Getenv("STORE_DSN"); d != "" {
		return d
	}
	return "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
}

// TestEnricherCacheHit memverifikasi cache Postgres mengurangi panggilan provider.
func TestEnricherCacheHit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres tak tersedia: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres tak tersedia: %v", err)
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
		t.Fatalf("provider dipanggil %d kali, mau 1 (kedua dari cache)", provider.Calls)
	}
	if ind1.AbuseConfidence != 77 || ind2.AbuseConfidence != 77 {
		t.Fatalf("indikator tidak konsisten: %+v / %+v", ind1, ind2)
	}
	t.Logf("OK: cache TTL bekerja — provider 1x, lookup ke-2 dari Postgres (%s)", ip)
}
