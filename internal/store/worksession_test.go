package store

import (
	"testing"
	"time"
)

// The filter that keeps a workstation's session list readable. A Windows boot produces a stream of
// SYSTEM and service logons, and a domain machine signs in as its own name with a trailing "$".
// None of them is somebody at the keyboard, and all of them would bury the three humans who used
// the machine that day.
func TestIsMachineAccount(t *testing.T) {
	for _, name := range []string{
		"SYSTEM", "system", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
		"WARD3-PC01$", "DC01$", "DWM-1", "UMFD-0", "", "   ", "-",
	} {
		if !isMachineAccount(name) {
			t.Errorf("%q should be filtered out of the session list", name)
		}
	}
	for _, name := range []string{
		"dr.sari", "perawat01", "Administrator", "firdaus", "HOSPITAL\\dr.budi",
	} {
		if isMachineAccount(name) {
			t.Errorf("%q is a person and must appear in the session list", name)
		}
	}
}

// pairSessions runs the same loop WorkSessions runs, against a fixed list of events, so the
// pairing rule can be checked without a database. The rule is "a logoff closes that user's most
// recent open session", and it is the part worth testing: everything else is a query.
func pairSessions(agent string, evs []struct {
	at           time.Time
	user, action string
}) []WorkSession {
	open := map[string]int{}
	out := make([]WorkSession, 0, len(evs))
	for _, e := range evs {
		if isMachineAccount(e.user) {
			continue
		}
		key := lower(e.user)
		if platform, ok := sessionOpen[e.action]; ok {
			if _, already := open[key]; already {
				continue
			}
			out = append(out, WorkSession{Agent: agent, User: e.user, Start: e.at, Platform: platform})
			open[key] = len(out) - 1
			continue
		}
		if _, ok := sessionClose[e.action]; ok {
			if i, ok := open[key]; ok {
				end := e.at
				out[i].End = &end
				delete(open, key)
			}
		}
	}
	return out
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func TestSessionPairing(t *testing.T) {
	base := time.Date(2026, 10, 16, 7, 0, 0, 0, time.UTC)
	at := func(h, m int) time.Time { return base.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }

	type ev = struct {
		at           time.Time
		user, action string
	}
	got := pairSessions("WARD3-PC01", []ev{
		{at(0, 0), "SYSTEM", "windows_logon"},        // boot noise
		{at(0, 1), "WARD3-PC01$", "windows_logon"},   // the machine itself
		{at(0, 5), "dr.sari", "windows_logon"},       // shift one starts
		{at(0, 6), "dr.sari", "windows_logon"},       // Windows raises several 4624s per sign-in
		{at(6, 0), "dr.sari", "windows_logoff"},      // shift one ends
		{at(6, 2), "perawat01", "windows_logon"},     // shift two starts
		{at(7, 0), "unknown.user", "windows_logoff"}, // a logoff whose logon is before the window
	})

	if len(got) != 2 {
		t.Fatalf("expected 2 human sessions, got %d: %+v", len(got), got)
	}

	// The repeated 4624 is the same person still there, not a second visit, so the EARLIER start
	// is kept: a session that appears to begin at 07:06 understates how long the account was on.
	if !got[0].Start.Equal(at(0, 5)) {
		t.Errorf("duplicate logon moved the start: %v, want %v", got[0].Start, at(0, 5))
	}
	if got[0].User != "dr.sari" || got[0].End == nil || !got[0].End.Equal(at(6, 0)) {
		t.Errorf("first session wrong: %+v", got[0])
	}
	// Shift two has not signed off, so it is still open rather than guessed at.
	if got[1].User != "perawat01" || !got[1].Open() {
		t.Errorf("second session should still be open: %+v", got[1])
	}
	// A logoff with no logon in the window invents nothing: a start time nobody observed is
	// invented evidence, and this is an audit trail.
	for _, s := range got {
		if s.User == "unknown.user" {
			t.Error("a logoff with no matching logon must not create a session")
		}
	}
}

// Two people on the same machine at once is normal on Windows: one at the keyboard, one over RDP.
// Closing the wrong one would attribute an action to whoever happened to sign in first.
func TestSessionPairingKeepsUsersApart(t *testing.T) {
	base := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	type ev = struct {
		at           time.Time
		user, action string
	}
	got := pairSessions("WARD3-PC01", []ev{
		{base, "dr.sari", "windows_logon"},
		{base.Add(5 * time.Minute), "it.support", "windows_logon"},
		{base.Add(10 * time.Minute), "it.support", "windows_logoff"},
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(got))
	}
	if !got[0].Open() {
		t.Error("dr.sari never signed off and must stay open")
	}
	if got[1].Open() {
		t.Error("it.support signed off and must be closed")
	}
}
