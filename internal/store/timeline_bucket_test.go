package store

import (
	"testing"
	"time"
)

// TestResolveBucket guards the fix for the demo-day hang: a 1-minute bucket over a 30-day window
// (~43k points) must NOT be honoured; a reasonable override must be. Pure function, no DB.
func TestResolveBucket(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		name     string
		span     time.Duration
		override string
		want     string
	}{
		{"1min over 30d clamps to auto", 30 * day, "1min", "1 day"},     // bucketFor(30d) = 1 day
		{"1min over 24h honoured", 24 * time.Hour, "1min", "1 minute"},  // 1440 buckets, under cap
		{"5min over 7d clamps to auto", 7 * day, "5min", "6 hours"},     // 7d/5min=2016 > cap -> bucketFor(7d)
		{"empty override uses auto", 30 * day, "", "1 day"},
		{"unknown override uses auto", 2 * time.Hour, "nonsense", "1 minute"},
		{"1h over 30d honoured", 30 * day, "1h", "1 hour"}, // 720 buckets
	}
	for _, c := range cases {
		if got := resolveBucket(c.span, c.override); got != c.want {
			t.Errorf("%s: resolveBucket(%v,%q)=%q want %q", c.name, c.span, c.override, got, c.want)
		}
	}
}
