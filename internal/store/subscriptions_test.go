package store

import (
	"testing"
	"time"
)

func TestHashSubscriptionKeyDeterministic(t *testing.T) {
	a := HashSubscriptionKey("dws_abc")
	b := HashSubscriptionKey("dws_abc")
	if a != b {
		t.Fatal("hash must be deterministic")
	}
	if a == HashSubscriptionKey("dws_xyz") {
		t.Fatal("different keys must hash differently")
	}
	if len(a) != 64 {
		t.Fatalf("sha256 hex should be 64 chars, got %d", len(a))
	}
}

func TestEventCursorRoundTrip(t *testing.T) {
	when := time.Date(2026, 7, 18, 10, 30, 15, 123_000_000, time.UTC)
	id := "11111111-2222-3333-4444-555555555555"
	cur := encodeEventCursor(when, id)
	if cur == "" {
		t.Fatal("cursor should not be empty")
	}
	gotT, gotID, err := decodeEventCursor(cur)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !gotT.Equal(when) {
		t.Fatalf("time round-trip: got %v want %v", gotT, when)
	}
	if gotID != id {
		t.Fatalf("id round-trip: got %q want %q", gotID, id)
	}
}

func TestDecodeEmptyCursor(t *testing.T) {
	tm, id, err := decodeEventCursor("")
	if err != nil {
		t.Fatalf("empty cursor should not error: %v", err)
	}
	if !tm.IsZero() || id != zeroUUID {
		t.Fatalf("empty cursor should be (zero time, zero uuid), got (%v, %q)", tm, id)
	}
}

func TestDecodeBadCursor(t *testing.T) {
	if _, _, err := decodeEventCursor("!!!not-base64!!!"); err == nil {
		t.Fatal("malformed cursor should error")
	}
}

func TestSanitizeScopes(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{nil, []string{"events"}},
		{[]string{}, []string{"events"}},
		{[]string{"bogus"}, []string{"events"}},
		{[]string{"EVENTS", "events"}, []string{"events"}}, // dedup + case-fold
		{[]string{"indicators", "events"}, []string{"indicators", "events"}},
	}
	for _, c := range cases {
		got := sanitizeScopes(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("sanitizeScopes(%v) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("sanitizeScopes(%v) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestHasScope(t *testing.T) {
	sub := &Subscription{Scopes: []string{"events"}}
	if !sub.HasScope("events") {
		t.Fatal("should have events scope")
	}
	if sub.HasScope("indicators") {
		t.Fatal("should not have indicators scope")
	}
}
