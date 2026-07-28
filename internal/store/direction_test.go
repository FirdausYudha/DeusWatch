package store

import (
	"net"
	"testing"
)

// TestAttachDirection covers the four direction cases the SOAR uses to tag events on the dashboard:
// inbound (attack from the outside — the common case), lateral (attacker moving inside our network —
// the highest-value signal), outbound (our host reaching out — possible C2/exfil), and the fallback
// where a source with no context stays unclassified.
func TestAttachDirection(t *testing.T) {
	_, our, _ := net.ParseCIDR("10.10.0.0/16")
	rows := []EventRow{
		// external → agent (no explicit destination) — the SSH-brute-force shape.
		{SourceIP: "160.119.71.211", AgentID: "linux"},
		// external → internal explicit destination.
		{SourceIP: "1.2.3.4", DestinationIP: "10.10.5.5"},
		// internal → internal (LATERAL).
		{SourceIP: "10.10.1.1", DestinationIP: "10.10.2.2"},
		// internal → external (OUTBOUND / possible C2).
		{SourceIP: "10.10.1.1", DestinationIP: "203.0.113.9"},
		// external → external (both unclassifiable, no agent) — stays empty.
		{SourceIP: "8.8.8.8", DestinationIP: "1.1.1.1"},
		// no source at all — stays empty.
		{},
	}
	AttachDirection(rows, []*net.IPNet{our})
	want := []string{"inbound", "inbound", "lateral", "outbound", "", ""}
	for i, w := range want {
		if rows[i].Direction != w {
			t.Errorf("row %d: got %q, want %q (src=%q dst=%q agent=%q)",
				i, rows[i].Direction, w, rows[i].SourceIP, rows[i].DestinationIP, rows[i].AgentID)
		}
	}
}

// TestAttachDirectionRFC1918Fallback proves a fresh install with an empty whitelist still labels
// internal ↔ internal correctly using the built-in RFC1918/loopback ranges.
func TestAttachDirectionRFC1918Fallback(t *testing.T) {
	rows := []EventRow{
		{SourceIP: "192.168.1.10", DestinationIP: "192.168.1.20"},
		{SourceIP: "10.0.0.5", AgentID: "web01"},
		{SourceIP: "8.8.8.8", AgentID: "web01"},
	}
	AttachDirection(rows, nil) // no explicit whitelist — must still work via RFC1918
	if rows[0].Direction != "lateral" {
		t.Fatalf("private ↔ private must be lateral by default, got %q", rows[0].Direction)
	}
	if rows[1].Direction != "lateral" {
		t.Fatalf("private source hitting one of our agents must be lateral, got %q", rows[1].Direction)
	}
	if rows[2].Direction != "inbound" {
		t.Fatalf("external hitting our agent must be inbound, got %q", rows[2].Direction)
	}
}
