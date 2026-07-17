package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseReportRange(t *testing.T) {
	get := func(query string) (time.Time, time.Time, bool) {
		r := httptest.NewRequest("GET", "/api/report?"+query, nil)
		return parseReportRange(r)
	}

	// No from -> no range (the caller falls back to ?hours=).
	if _, _, ok := get("hours=24"); ok {
		t.Fatal("without from there is no explicit range")
	}

	// A bare `to` date must cover the WHOLE day: the exclusive end is the next midnight.
	from, to, ok := get("from=2026-07-01&to=2026-07-17")
	if !ok {
		t.Fatal("a from+to date range should parse")
	}
	wantFrom := time.Date(2026, 7, 1, 0, 0, 0, 0, time.Local)
	wantTo := time.Date(2026, 7, 18, 0, 0, 0, 0, time.Local) // exclusive end
	if !from.Equal(wantFrom) || !to.Equal(wantTo) {
		t.Fatalf("range = %v..%v, want %v..%v", from, to, wantFrom, wantTo)
	}

	// RFC3339 is accepted as-is.
	from, to, ok = get("from=2026-07-01T06:00:00Z&to=2026-07-01T18:00:00Z")
	if !ok || from.UTC().Hour() != 6 || to.UTC().Hour() != 18 {
		t.Fatalf("RFC3339 range not honored: %v..%v ok=%v", from, to, ok)
	}

	// from without to runs up to now.
	from, to, ok = get("from=2026-07-01")
	if !ok || to.Before(from) {
		t.Fatalf("from without to should end at now: %v..%v ok=%v", from, to, ok)
	}

	// A swapped range is tolerated rather than returning an empty report.
	from, to, ok = get("from=2026-07-17&to=2026-07-01")
	if !ok || !from.Before(to) {
		t.Fatalf("swapped range should be normalized: %v..%v", from, to)
	}
}
