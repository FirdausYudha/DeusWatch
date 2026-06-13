package enrich

import (
	"context"
	"strings"
	"time"

	"deuswatch/internal/ingest"
)

// DefaultTTL: umur cache CTI sebelum lookup ulang.
const DefaultTTL = 12 * time.Hour

// Enricher menggabungkan Provider + Cache. Cek cache dulu, baru panggil provider.
type Enricher struct {
	provider Provider
	cache    *Cache
	ttl      time.Duration
}

func NewEnricher(provider Provider, cache *Cache, ttl time.Duration) *Enricher {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Enricher{provider: provider, cache: cache, ttl: ttl}
}

// lookup mengembalikan indikator untuk ip: cache-hit bila TTL aktif, selain itu
// panggil provider lalu simpan ke cache (best-effort).
func (e *Enricher) lookup(ctx context.Context, ip string) (Indicator, error) {
	if ind, ok, err := e.cache.Get(ctx, ip); err == nil && ok {
		return ind, nil
	}
	ind, err := e.provider.Lookup(ctx, ip)
	if err != nil {
		return Indicator{}, err
	}
	_ = e.cache.Put(ctx, ip, ind, e.ttl)
	return ind, nil
}

// EnrichEvent melengkapi event berdasarkan source.ip: mengisi threat.* +
// deuswatch.enrichment.* dan mengeskalasi severity (bagian 9). Event tanpa
// source IP ditandai 'skipped'.
func (e *Enricher) EnrichEvent(ctx context.Context, ev *ingest.Event) error {
	if ev.Source == nil || ev.Source.IP == "" {
		ev.DeusWatch.Enrichment.Status = ingest.EnrichmentSkipped
		return nil
	}
	ind, err := e.lookup(ctx, ev.Source.IP)
	if err != nil {
		ev.DeusWatch.Enrichment.Status = ingest.EnrichmentFailed
		return err
	}
	applyToEvent(ev, ind)
	return nil
}

func applyToEvent(ev *ingest.Event, ind Indicator) {
	abuse, otx := ind.AbuseConfidence, ind.OTXPulseCount

	ev.DeusWatch.Enrichment.Status = ingest.EnrichmentEnriched
	ev.DeusWatch.Enrichment.AbuseConfidence = &abuse
	ev.DeusWatch.Enrichment.OTXPulseCount = &otx

	if ev.Threat == nil {
		ev.Threat = &ingest.Threat{}
	}
	now := time.Now()
	ev.Threat.Indicator = &ingest.Indicator{IP: ev.Source.IP, Confidence: abuse, LastSeen: &now}
	ev.Threat.FeedName = ind.FeedName
	if ind.CountryISO != "" {
		if ev.Source.Geo == nil {
			ev.Source.Geo = &ingest.Geo{}
		}
		ev.Source.Geo.CountryISOCode = ind.CountryISO
	}

	// Eskalasi dinamis severity (bagian 9). Severity asli disimpan terpisah.
	orig := ev.Event.Severity
	esc := orig
	var reasons []string
	if abuse >= 90 {
		esc++
		reasons = append(reasons, "abuse_confidence>=90")
	}
	if otx >= 5 {
		esc++
		reasons = append(reasons, "otx_pulse_count>=5")
	}
	if esc > ingest.SeverityCritical {
		esc = ingest.SeverityCritical
	}
	ev.DeusWatch.Severity.Original = orig
	if esc != orig {
		ev.Event.Severity = esc
		ev.DeusWatch.Severity.EscalatedBy = strings.Join(reasons, ",")
	}
}
