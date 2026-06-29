package enrich

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"deuswatch/internal/hashrep"
	"deuswatch/internal/ingest"
)

// DefaultTTL: how long a CTI cache entry lives before a re-lookup. This is the
// deduplication window — an IP seen again within it is served from cache, NOT re-queried
// against the external API (so the API quota isn't burned on repeat offenders).
const DefaultTTL = 24 * time.Hour

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
// Optionally it also resolves FIM file-hash reputation (hashrep) for file events.
type Enricher struct {
	provider Provider
	cache    *Cache
	rules    EscalationRules

	mu      sync.RWMutex // guards the live-reloadable TTLs
	ttl     time.Duration
	hashTTL time.Duration

	hashProvider hashrep.Provider // optional (FIM file-hash reputation)
	hashCache    *hashrep.Cache
}

// SetTTL live-updates the enrichment cache TTL (the dedup window for IP CTI + file-hash
// lookups): an IP/hash seen again within it is served from cache, not re-queried.
func (e *Enricher) SetTTL(d time.Duration) {
	if d <= 0 {
		return
	}
	e.mu.Lock()
	e.ttl, e.hashTTL = d, d
	e.mu.Unlock()
}

// SetProvider swaps the CTI provider at runtime, so adding/removing an AbuseIPDB/OTX
// integration in the UI takes effect without restarting the worker.
func (e *Enricher) SetProvider(p Provider) {
	if p == nil {
		return
	}
	e.mu.Lock()
	e.provider = p
	e.mu.Unlock()
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

// SetHashReputation enables FIM file-hash reputation lookups for file events.
func (e *Enricher) SetHashReputation(p hashrep.Provider, cache *hashrep.Cache, ttl time.Duration) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	e.hashProvider, e.hashCache, e.hashTTL = p, cache, ttl
}

// lookup returns the indicator for ip: a cache hit while the TTL is active, otherwise
// it calls the provider then stores the result in the cache (best-effort).
func (e *Enricher) lookup(ctx context.Context, ip string) (Indicator, error) {
	if ind, ok, err := e.cache.Get(ctx, ip); err == nil && ok {
		return ind, nil
	}
	e.mu.RLock()
	p, ttl := e.provider, e.ttl
	e.mu.RUnlock()
	ind, err := p.Lookup(ctx, ip)
	if err != nil {
		return Indicator{}, err
	}
	_ = e.cache.Put(ctx, ip, ind, ttl)
	return ind, nil
}

// EnrichEvent enriches an event: it resolves FIM file-hash reputation (file events) and
// CTI for source.ip — filling threat.* + deuswatch.* and escalating severity (section 9).
// Either path can run independently; an event with neither a hash nor an IP is 'skipped'.
func (e *Enricher) EnrichEvent(ctx context.Context, ev *ingest.Event) error {
	hasHash := e.hashProvider != nil && ev.File != nil && hashrep.IsSHA256(ev.File.HashSHA256)
	hasIP := ev.Source != nil && ev.Source.IP != ""
	if !hasHash && !hasIP {
		ev.DeusWatch.Enrichment.Status = ingest.EnrichmentSkipped
		return nil
	}
	// Capture the original severity once, before any escalation path runs.
	ev.DeusWatch.Severity.Original = ev.Event.Severity

	var firstErr error
	enriched := false
	if hasHash {
		if err := e.enrichHash(ctx, ev); err != nil {
			firstErr = err
		} else {
			enriched = true
		}
	}
	if hasIP {
		if ind, err := e.lookup(ctx, ev.Source.IP); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			applyIPIndicator(ev, ind, e.rules)
			enriched = true
		}
	}

	if enriched {
		ev.DeusWatch.Enrichment.Status = ingest.EnrichmentEnriched
	} else {
		ev.DeusWatch.Enrichment.Status = ingest.EnrichmentFailed
	}
	return firstErr
}

// enrichHash looks up the file's SHA-256 reputation (cache-first) and stores the verdict;
// a known-bad file raises severity to at least High.
func (e *Enricher) enrichHash(ctx context.Context, ev *ingest.Event) error {
	h := ev.File.HashSHA256
	ind, ok, _ := e.hashCache.Get(ctx, h)
	if !ok {
		var err error
		if ind, err = e.hashProvider.LookupHash(ctx, h); err != nil {
			return err
		}
		e.mu.RLock()
		httl := e.hashTTL
		e.mu.RUnlock()
		_ = e.hashCache.Put(ctx, h, ind, httl)
	}
	ev.DeusWatch.FileHash.Verdict = string(ind.Verdict)
	ev.DeusWatch.FileHash.Detail = ind.Detail
	if ind.Verdict == hashrep.VerdictKnownBad {
		if ev.Event.Severity < ingest.SeverityHigh {
			ev.Event.Severity = ingest.SeverityHigh
		}
		addEscalationReason(ev, "file_hash_known_bad")
	}
	return nil
}

func applyIPIndicator(ev *ingest.Event, ind Indicator, rules EscalationRules) {
	abuse, otx := ind.AbuseConfidence, ind.OTXPulseCount

	ev.DeusWatch.Enrichment.Status = ingest.EnrichmentEnriched
	// Only record a score when there is actual signal, so an unknown/clean IP shows "—"
	// instead of a misleading "abuse 0" (or a fabricated value from the mock provider).
	if abuse > 0 {
		ev.DeusWatch.Enrichment.AbuseConfidence = &abuse
	}
	if otx > 0 {
		ev.DeusWatch.Enrichment.OTXPulseCount = &otx
	}

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

	// Dynamic severity escalation (section 9); cumulative with any FIM bump.
	esc := ev.Event.Severity
	if abuse >= rules.AbuseThreshold {
		esc++
		addEscalationReason(ev, "abuse_confidence>="+strconv.Itoa(rules.AbuseThreshold))
	}
	if otx >= rules.OTXThreshold {
		esc++
		addEscalationReason(ev, "otx_pulse_count>="+strconv.Itoa(rules.OTXThreshold))
	}
	if esc > ingest.SeverityCritical {
		esc = ingest.SeverityCritical
	}
	ev.Event.Severity = esc
}

// addEscalationReason appends one reason to deuswatch.severity.escalated_by (audit trail).
func addEscalationReason(ev *ingest.Event, reason string) {
	if ev.DeusWatch.Severity.EscalatedBy == "" {
		ev.DeusWatch.Severity.EscalatedBy = reason
	} else {
		ev.DeusWatch.Severity.EscalatedBy += "," + reason
	}
}
