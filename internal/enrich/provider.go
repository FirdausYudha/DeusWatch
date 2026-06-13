// Package enrich melakukan enrichment CTI: melengkapi event dengan reputasi IP
// (AbuseIPDB/OTX/GeoIP) dan mengeskalasi severity (design doc bagian 3 & 9).
//
// Hasil lookup di-cache sebagai baris Postgres ber-TTL (lihat cache.go), bukan
// in-memory. Klien API nyata (AbuseIPDB/OTX) menyusul di balik interface Provider;
// MockProvider dipakai untuk dev/test tanpa API key.
package enrich

import (
	"context"
	"sync"
)

// Indicator adalah hasil lookup CTI untuk sebuah IP.
type Indicator struct {
	AbuseConfidence int    // 0..100
	OTXPulseCount   int    // jumlah pulse OTX
	CountryISO      string // kode negara ISO (GeoIP)
	FeedName        string // sumber, mis. "abuseipdb" / "mock"
}

// Provider melakukan lookup CTI untuk satu IP.
type Provider interface {
	Lookup(ctx context.Context, ip string) (Indicator, error)
}

// MockProvider: provider deterministik untuk dev/test (tanpa API eksternal).
// Results menimpa per-IP; selain itu memakai Default. Calls menghitung pemanggilan
// (untuk memverifikasi cache mengurangi panggilan).
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

// NewDemoProvider mengembalikan MockProvider dengan beberapa IP "berbahaya" yang
// sudah dikenal untuk demo, sisanya benign. Diganti klien CTI nyata di produksi.
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
