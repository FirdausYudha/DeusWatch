package tickets

import (
	"strings"
	"testing"
	"time"
)

// The same rule from the same host all afternoon is one problem; the same rule from a different
// host is a different one. Getting this wrong either buries the queue or hides a spreading attack.
func TestDedupeKeyDistinguishesSource(t *testing.T) {
	base := AlertTicket{RuleID: "sigma_bruteforce", SourceIP: "10.0.0.9", Agent: "srv-sim"}
	same := AlertTicket{RuleID: "sigma_bruteforce", SourceIP: "10.0.0.9", Agent: "srv-sim"}
	if base.DedupeKey() != same.DedupeKey() {
		t.Fatal("a repeat of the same alert must collapse onto one ticket")
	}

	for _, other := range []AlertTicket{
		{RuleID: "sigma_bruteforce", SourceIP: "10.0.0.9", Agent: "srv-billing"}, // spreading
		{RuleID: "sigma_bruteforce", SourceIP: "10.0.0.44", Agent: "srv-sim"},    // new attacker
		{RuleID: "sigma_webshell", SourceIP: "10.0.0.9", Agent: "srv-sim"},       // new problem
	} {
		if base.DedupeKey() == other.DedupeKey() {
			t.Fatalf("%+v must not collapse onto the same ticket as %+v", other, base)
		}
	}
}

// A bad config must never silently turn automation ON, and must never store a window that would
// collapse a month of incidents into one ticket.
func TestAutomationConfigDefaultsAreSafe(t *testing.T) {
	c := DefaultAutomationConfig()
	if c.Enabled {
		t.Fatal("automation must be off until an operator switches it on")
	}
	if c.MinSeverity != 3 {
		t.Fatalf("default threshold should be high, got %d", c.MinSeverity)
	}
	if c.DedupeWindowMins <= 0 {
		t.Fatalf("a non-positive dedupe window would defeat deduplication, got %d", c.DedupeWindowMins)
	}
}

func TestResolvedMessageCarriesTheOutcome(t *testing.T) {
	created := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	resolved := created.Add(42 * time.Minute)
	assignee, ip := "dina", "10.0.0.9"
	tk := &Ticket{
		ID: "abc", Title: "Brute force on SIMRS", Severity: 3, Status: "resolved",
		Assignee: &assignee, SourceIP: &ip, CreatedAt: created, ResolvedAt: &resolved,
	}

	subject, body := Message(tk, "resolved")
	if !strings.Contains(subject, "resolved") || !strings.Contains(subject, tk.Title) {
		t.Fatalf("subject should name the event and the ticket, got %q", subject)
	}
	for _, want := range []string{"HIGH", "dina", "10.0.0.9", "42m0s"} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q:\n%s", want, body)
		}
	}
}

// An unassigned ticket must say so rather than render a blank line that reads like a bug.
func TestOpenedMessageOnUnassignedTicket(t *testing.T) {
	tk := &Ticket{ID: "x", Title: "Webshell dropped", Severity: 4, Status: "open"}
	subject, body := Message(tk, "opened")
	if !strings.Contains(subject, "opened") {
		t.Fatalf("subject should name the event, got %q", subject)
	}
	if !strings.Contains(body, "(unassigned)") {
		t.Errorf("an unassigned ticket should say so:\n%s", body)
	}
	if !strings.Contains(body, "CRITICAL") {
		t.Errorf("severity 4 should render as CRITICAL:\n%s", body)
	}
	// No resolve time on a ticket that is not resolved.
	if strings.Contains(body, "Time to resolve") {
		t.Errorf("an open ticket must not claim a resolution time:\n%s", body)
	}
}

func TestSeverityNameOutOfRange(t *testing.T) {
	if got := severityName(9); got != "UNKNOWN" {
		t.Fatalf("an out-of-range severity must not index past the table, got %q", got)
	}
}
