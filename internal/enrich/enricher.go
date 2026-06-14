package enrich

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"deuswatch/internal/ingest"
)

// DefaultTTL: how long a CTI cache entry lives before a re-lookup.
const DefaultTTL = 12 * time.Hour

// EscalationRules configures dynamic severity-escalation thresholds (design doc
// section 9). Each threshold crossed raises severity by one level (capped at critical).
type EscalationRules struct {
	AbuseThreshold int // AbuseIPDB score >= this -> +1 severity
	OTXThreshold   int // OTX pulse count >= this -> +1 severity
}

// DefaultEscalationRules: abuse>=90, otx>=5 (historical behavior).
func DefaultEscalationRules() EscalationRules {
	return EscalationRules{AbuseThreshold: 90, OTXThreshold: 5}
}

// EscalationFromEnv reads thresholds from env (ABUSE_ESCALATE_THRESHOLD,
// OTX_ESCALATE_THRESHOLD), falling back to defaults if unset/invalid.
func EscalationFromEnv() EscalationRules {
	r := DefaultEscalationRules()
	if v, err := strconv.Atoi(os.Getenv("ABUSE_ESCALATE_THRESHOLD")); err == nil && v > 0 {
		r.AbuseThreshold = v
	}
	if v, err := strconv.Atoi(os.Getenv("OTX_ESCALATE_THRESHOLD")); err == nil && v > 0 {
		r.OTXThreshold = v
	}
	return r
}

// Enricher combines a Provider + Cache. Check the cache first, then call the provider.
type Enricher struct {
	provider Provider
	cache    *Cache
	ttl      time.Duration
	rules    EscalationRules
}

func NewEnricher(provider Provider, cache *Cache, ttl time.Duration, rules EscalationRules) *Enricher {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if rules.AbuseThreshold <= 0 && rules.OTXThreshold <= 0 {
		rules = DefaultEscalationRules()
	}
	return &Enricher{provider: provider, cache: cache, ttl: ttl, rules: rules}
}

// lookup returns the indicator for ip: a cache hit while the TTL is active, otherwise
// it calls the provider then stores the result in the cache (best-effort).
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

// EnrichEvent enriches an event based on source.ip: it fills threat.* +
// deuswatch.enrichment.* and escalates severity (section 9). Events without a
// source IP are marked 'skipped'.
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
	applyToEvent(ev, ind, e.rules)
	return nil
}

func applyToEvent(ev *ingest.Event, ind Indicator, rules EscalationRules) {
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
	if ind.CountryISO != "" || ind.City != "" {
		if ev.Source.Geo == nil {
			ev.Source.Geo = &ingest.Geo{}
		}
		if ind.CountryISO != "" {
			ev.Source.Geo.CountryISOCode = ind.CountryISO
		}
		if ind.City != "" {
			ev.Source.Geo.CityName = ind.City
		}
	}

	// Dynamic severity escalation (section 9). The original severity is kept separately.
	orig := ev.Event.Severity
	esc := orig
	var reasons []string
	if abuse >= rules.AbuseThreshold {
		esc++
		reasons = append(reasons, "abuse_confidence>="+strconv.Itoa(rules.AbuseThreshold))
	}
	if otx >= rules.OTXThreshold {
		esc++
		reasons = append(reasons, "otx_pulse_count>="+strconv.Itoa(rules.OTXThreshold))
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
