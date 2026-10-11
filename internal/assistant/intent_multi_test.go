package assistant

import (
	"fmt"
	"strings"
	"testing"
)

// The reported failure, verbatim. Nine addresses were named and a card was prepared for the first
// one, with a reply that mentioned no others: "Prepared a 7-day block for 43.173.126.86." An
// operator reads that, presses confirm, and comes away believing nine networks are cut off.
func TestParseProposalTakesEveryAddress(t *testing.T) {
	msg := "block 43.173.126.86, 45.55.148.10, 20.217.80.108, 45.148.10.61, 47.251.185.146, " +
		"50.6.111.141, 51.4.104.28, 64.227.122.123, and 68.183.115.64 for 7 days"

	p, ok := ParseProposal(msg)
	if !ok {
		t.Fatal("not recognised as a proposal")
	}
	want := []string{
		"43.173.126.86", "45.55.148.10", "20.217.80.108", "45.148.10.61", "47.251.185.146",
		"50.6.111.141", "51.4.104.28", "64.227.122.123", "68.183.115.64",
	}
	if len(p.Targets) != len(want) {
		t.Fatalf("got %d targets, want %d: %v", len(p.Targets), len(want), p.Targets)
	}
	for i, w := range want {
		if p.Targets[i] != w {
			t.Errorf("target %d = %q, want %q (order must follow the sentence)", i, p.Targets[i], w)
		}
	}
	if p.Minutes != 7*24*60 {
		t.Errorf("minutes = %d, want %d: one duration applies to the whole list", p.Minutes, 7*24*60)
	}
	// The reply must not name one address as though it were the whole request.
	if strings.Contains(p.Reply(), "block for 43.173.126.86") {
		t.Errorf("the reply still describes a single-address block:\n%s", p.Reply())
	}
	if !strings.Contains(p.Reply(), "9 addresses") {
		t.Errorf("the reply should say how many are on the card:\n%s", p.Reply())
	}
}

// Repeating an address in one sentence is one target. Two identical rows on a checklist is a
// question the operator cannot answer ("do I tick both?").
func TestParseProposalDeduplicates(t *testing.T) {
	p, ok := ParseProposal("block 1.2.3.4, 5.6.7.8 and 1.2.3.4 again")
	if !ok {
		t.Fatal("not recognised")
	}
	if len(p.Targets) != 2 {
		t.Errorf("got %v, want 2 unique targets", p.Targets)
	}
}

// Past the cap, the extras are REPORTED. Quietly keeping the first twenty is the same class of bug
// as quietly keeping the first one, just further along.
func TestParseProposalReportsOverflow(t *testing.T) {
	var b strings.Builder
	b.WriteString("block ")
	total := MaxProposalTargets + 5
	for i := 0; i < total; i++ {
		fmt.Fprintf(&b, "10.%d.%d.1 ", i/256, i%256)
	}

	p, ok := ParseProposal(b.String())
	if !ok {
		t.Fatal("not recognised")
	}
	if len(p.Targets) != MaxProposalTargets {
		t.Errorf("got %d targets, want the cap of %d", len(p.Targets), MaxProposalTargets)
	}
	if p.Overflow != 5 {
		t.Errorf("overflow = %d, want 5", p.Overflow)
	}
	if !strings.Contains(p.Reply(), "5 more") {
		t.Errorf("the reply must say what was left out:\n%s", p.Reply())
	}
}

// A CIDR is still refused for a ban even when it sits in a list of valid addresses. Widening a ban
// to a /8 because a prefix was in the middle of a sentence is not a mistake worth allowing.
func TestParseProposalStillRefusesCIDRBansInAList(t *testing.T) {
	p, ok := ParseProposal("block 1.2.3.4 and 10.0.0.0/8")
	if !ok {
		t.Fatal("not recognised")
	}
	for _, target := range p.Targets {
		if strings.Contains(target, "/") {
			t.Errorf("a CIDR reached a ban proposal: %v", p.Targets)
		}
	}
	if len(p.Targets) != 1 {
		t.Errorf("got %v, want only the single address", p.Targets)
	}

	// A whitelist may carry several ranges, which is ordinary.
	w, ok := ParseProposal("whitelist 10.0.0.0/8 and 192.168.0.0/16")
	if !ok {
		t.Fatal("whitelist not recognised")
	}
	if len(w.Targets) != 2 {
		t.Errorf("whitelist got %v, want both ranges", w.Targets)
	}
}
