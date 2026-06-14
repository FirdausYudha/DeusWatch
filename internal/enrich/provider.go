// Package enrich performs CTI enrichment: it augments events with IP reputation
// (AbuseIPDB/OTX/GeoIP) and escalates severity (design doc sections 3 & 9).
//
// Lookup results are cached as TTL-bearing Postgres rows (see cache.go), not in
// memory. Real API clients (AbuseIPDB/OTX) live behind the Provider interface;
// MockProvider is used for dev/test without an API key.
package enrich

import (
	"context"
	"sync"
)

// Indicator is the CTI lookup result for an IP.
type Indicator struct {
	AbuseConfidence int    // 0..100
	OTXPulseCount   int    // OTX pulse count
	CountryISO      string // ISO country code (GeoIP)
	City            string // city (GeoIP, optional)
	FeedName        string // source, e.g. "abuseipdb,otx" / "mock"
}

// Provider performs a CTI lookup for one IP.
type Provider interface {
	Lookup(ctx context.Context, ip string) (Indicator, error)
}

// MockProvider: a deterministic provider for dev/test (no external API). Results
// overrides per-IP; otherwise Default is used. Calls counts invocations (to verify
// the cache reduces calls).
type MockProvider struct {
	mu      sync.Mutex
	Calls   int
	Results map[string]Indicator
	Default Indicator
}

func (m *MockProvider) Lookup(_ context.Context, ip string) (Indicator, error) {
	m.mu.Lock()
	m.Calls++
	m.mu.Unlock()
	if r, ok := m.Results[ip]; ok {
		return r, nil
	}
	return m.Default, nil
}

// NewDemoProvider returns a MockProvider with a few known-"malicious" IPs for the
// demo, the rest benign. Replaced by real CTI clients in production.
func NewDemoProvider() *MockProvider {
	return &MockProvider{
		Default: Indicator{AbuseConfidence: 5, OTXPulseCount: 0, CountryISO: "US", FeedName: "mock"},
		Results: map[string]Indicator{
			"45.155.205.99":  {AbuseConfidence: 95, OTXPulseCount: 8, CountryISO: "RU", FeedName: "mock"},
			"185.220.101.1":  {AbuseConfidence: 100, OTXPulseCount: 12, CountryISO: "DE", FeedName: "mock"},
			"203.0.113.10":   {AbuseConfidence: 92, OTXPulseCount: 6, CountryISO: "CN", FeedName: "mock"},
		},
	}
}
