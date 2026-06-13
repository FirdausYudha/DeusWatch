package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAbuseIPDBClientParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "secret" {
			t.Errorf("API key tak diteruskan: %q", r.Header.Get("Key"))
		}
		if r.URL.Query().Get("ipAddress") != "45.155.205.99" {
			t.Errorf("ipAddress salah: %q", r.URL.Query().Get("ipAddress"))
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
		t.Fatalf("hasil salah: score=%d country=%q", score, country)
	}
}

func TestOTXClientParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "k" {
			t.Errorf("OTX key tak diteruskan")
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
		t.Fatalf("pulse count salah: %d", n)
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
		t.Fatalf("geo salah: %q/%q", country, city)
	}
}

func TestGeoClientFailStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"fail","message":"private range"}`))
	}))
	defer srv.Close()
	c := &GeoClient{base: srv.URL, hc: srv.Client()}
	if _, _, err := c.Geo(context.Background(), "10.0.0.1"); err == nil {
		t.Fatal("status fail harus error")
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
		t.Fatalf("merge salah: %+v", ind)
	}
	if ind.FeedName != "abuseipdb,otx" {
		t.Fatalf("feed name salah: %q", ind.FeedName)
	}
}

func TestCompositeSkipsPrivateIP(t *testing.T) {
	cp := &CompositeProvider{
		Abuse: &AbuseIPDBClient{key: "x", base: "http://127.0.0.1:0", hc: newHTTPClient()},
	}
	// IP privat tak boleh memicu panggilan eksternal (base tak terjangkau pun tak apa).
	ind, err := cp.Lookup(context.Background(), "10.0.0.5")
	if err != nil {
		t.Fatalf("IP privat seharusnya tak error: %v", err)
	}
	if ind.AbuseConfidence != 0 || ind.FeedName != "internal" {
		t.Fatalf("IP privat harus dilewati: %+v", ind)
	}
}

func TestCompositeAllSourcesFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cp := &CompositeProvider{Abuse: &AbuseIPDBClient{key: "x", base: srv.URL, hc: srv.Client()}}
	if _, err := cp.Lookup(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("semua sumber gagal harus mengembalikan error")
	}
}

func TestIsPrivateIP(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "garbage"} {
		if !isPrivateIP(ip) {
			t.Errorf("%q seharusnya privat/dilewati", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "45.155.205.99"} {
		if isPrivateIP(ip) {
			t.Errorf("%q seharusnya publik", ip)
		}
	}
}
