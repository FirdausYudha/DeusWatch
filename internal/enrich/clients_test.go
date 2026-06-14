package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"deuswatch/internal/blocklist"
)

func TestAbuseIPDBClientParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "secret" {
			t.Errorf("API key not forwarded: %q", r.Header.Get("Key"))
		}
		if r.URL.Query().Get("ipAddress") != "45.155.205.99" {
			t.Errorf("wrong ipAddress: %q", r.URL.Query().Get("ipAddress"))
		}
		w.Write([]byte(`{"data":{"abuseConfidenceScore":95,"countryCode":"RU"}}`))
	}))
	defer srv.Close()

	c := &AbuseIPDBClient{key: "secret", base: srv.URL, hc: srv.Client()}
	score, country, err := c.Check(context.Background(), "45.155.205.99")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if score != 95 || country != "RU" {
		t.Fatalf("wrong result: score=%d country=%q", score, country)
	}
}

func TestOTXClientParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "k" {
			t.Errorf("OTX key not forwarded")
		}
		w.Write([]byte(`{"pulse_info":{"count":12}}`))
	}))
	defer srv.Close()

	c := &OTXClient{key: "k", base: srv.URL, hc: srv.Client()}
	n, err := c.Pulses(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("Pulses: %v", err)
	}
	if n != 12 {
		t.Fatalf("wrong pulse count: %d", n)
	}
}

func TestGeoClientParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"success","countryCode":"DE","city":"Berlin"}`))
	}))
	defer srv.Close()

	c := &GeoClient{base: srv.URL, hc: srv.Client()}
	country, city, err := c.Geo(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Geo: %v", err)
	}
	if country != "DE" || city != "Berlin" {
		t.Fatalf("wrong geo: %q/%q", country, city)
	}
}

func TestGeoClientFailStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"fail","message":"private range"}`))
	}))
	defer srv.Close()
	c := &GeoClient{base: srv.URL, hc: srv.Client()}
	if _, _, err := c.Geo(context.Background(), "10.0.0.1"); err == nil {
		t.Fatal("a fail status must be an error")
	}
}

func TestCompositeMergesSources(t *testing.T) {
	abuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data":{"abuseConfidenceScore":80,"countryCode":"CN"}}`))
	}))
	defer abuse.Close()
	otx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"pulse_info":{"count":7}}`))
	}))
	defer otx.Close()

	cp := &CompositeProvider{
		Abuse: &AbuseIPDBClient{key: "x", base: abuse.URL, hc: abuse.Client()},
		OTX:   &OTXClient{key: "y", base: otx.URL, hc: otx.Client()},
	}
	ind, err := cp.Lookup(context.Background(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if ind.AbuseConfidence != 80 || ind.OTXPulseCount != 7 || ind.CountryISO != "CN" {
		t.Fatalf("wrong merge: %+v", ind)
	}
	if ind.FeedName != "abuseipdb,otx" {
		t.Fatalf("wrong feed name: %q", ind.FeedName)
	}
}

func TestCompositeSkipsPrivateIP(t *testing.T) {
	cp := &CompositeProvider{
		Abuse: &AbuseIPDBClient{key: "x", base: "http://127.0.0.1:0", hc: newHTTPClient()},
	}
	// A private IP must not trigger any external call (an unreachable base is fine).
	ind, err := cp.Lookup(context.Background(), "10.0.0.5")
	if err != nil {
		t.Fatalf("a private IP should not error: %v", err)
	}
	if ind.AbuseConfidence != 0 || ind.FeedName != "internal" {
		t.Fatalf("a private IP must be skipped: %+v", ind)
	}
}

func TestCompositeAllSourcesFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cp := &CompositeProvider{Abuse: &AbuseIPDBClient{key: "x", base: srv.URL, hc: srv.Client()}}
	if _, err := cp.Lookup(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("all sources failing must return an error")
	}
}

func TestCompositeBlocklistMarksMalicious(t *testing.T) {
	bl := blocklist.NewSet()
	bl.Replace([]string{"45.155.205.99", "185.220.0.0/16"})
	cp := &CompositeProvider{Blocklist: bl}

	ind, err := cp.Lookup(context.Background(), "185.220.5.5")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if ind.AbuseConfidence != 100 || ind.FeedName != "blocklist" {
		t.Fatalf("a blocklisted IP should be abuse=100 feed=blocklist: %+v", ind)
	}
	// A clean IP with no other source → empty (not an error).
	clean, err := cp.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("clean Lookup: %v", err)
	}
	if clean.AbuseConfidence != 0 {
		t.Fatalf("a clean IP must not be flagged: %+v", clean)
	}
}

func TestCompositeBlocklistFloorsAbuse(t *testing.T) {
	// A low AbuseIPDB score must not lower the blocklist floor (100).
	abuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data":{"abuseConfidenceScore":5,"countryCode":"RU"}}`))
	}))
	defer abuse.Close()
	bl := blocklist.NewSet()
	bl.Replace([]string{"45.155.205.99"})
	cp := &CompositeProvider{
		Abuse:     &AbuseIPDBClient{key: "x", base: abuse.URL, hc: abuse.Client()},
		Blocklist: bl,
	}
	ind, err := cp.Lookup(context.Background(), "45.155.205.99")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if ind.AbuseConfidence != 100 {
		t.Fatalf("the blocklist floor should be preserved, got %d", ind.AbuseConfidence)
	}
	if ind.CountryISO != "RU" {
		t.Fatalf("the country from abuse should still be set: %+v", ind)
	}
}

func TestIsPrivateIP(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "garbage"} {
		if !isPrivateIP(ip) {
			t.Errorf("%q should be private/skipped", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "45.155.205.99"} {
		if isPrivateIP(ip) {
			t.Errorf("%q should be public", ip)
		}
	}
}
