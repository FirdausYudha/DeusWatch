package main

import (
	"testing"
	"time"
)

// TestDashboardCache covers the behaviour the dashboard handler relies on: a hit within the TTL, a
// miss after it expires, and - the isolation-critical part - that entries stored under different
// keys (the handler keys on tenant scope) never read each other's bodies.
func TestDashboardCache(t *testing.T) {
	c := newDashboardCache(50 * time.Millisecond)

	c.put("tenantA|w", []byte("A"))
	c.put("tenantB|w", []byte("B"))

	if b, ok := c.get("tenantA|w"); !ok || string(b) != "A" {
		t.Fatalf("tenantA: got %q ok=%v, want \"A\" true", b, ok)
	}
	if b, ok := c.get("tenantB|w"); !ok || string(b) != "B" {
		t.Fatalf("tenantB: got %q ok=%v, want \"B\" true", b, ok)
	}
	if _, ok := c.get("tenantC|w"); ok {
		t.Fatal("tenantC must miss: a scope with no entry must never read another's body")
	}

	time.Sleep(70 * time.Millisecond)
	if _, ok := c.get("tenantA|w"); ok {
		t.Fatal("entry must expire after the TTL")
	}
}
