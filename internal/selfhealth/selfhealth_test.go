package selfhealth

import (
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

func at(t time.Time) *time.Time { return &t }

func TestComputeStates(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		a    AgentHealth
		want string
	}{
		{"never seen", AgentHealth{}, StatusUnknown},
		{"fresh heartbeat", AgentHealth{LastSeen: at(now.Add(-30 * time.Second))}, StatusOnline},
		{"fresh but degraded", AgentHealth{LastSeen: at(now.Add(-30 * time.Second)), Degraded: true}, StatusDegraded},
		{"missed heartbeats", AgentHealth{LastSeen: at(now.Add(-5 * time.Minute))}, StatusDisconnected},
		{"long gone", AgentHealth{LastSeen: at(now.Add(-25 * time.Hour))}, StatusStale},
		// A degraded flag must not mask a disconnect: last_seen wins.
		{"degraded then vanished", AgentHealth{LastSeen: at(now.Add(-10 * time.Minute)), Degraded: true}, StatusDisconnected},
	}
	for _, c := range cases {
		if got := Compute(c.a, now, DefaultDisconnectedAfter, DefaultStaleAfter); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestEvaluateTransitions(t *testing.T) {
	now := time.Now()

	// online -> disconnected: HIGH alert with the Defense Evasion technique.
	tr := Evaluate(AgentHealth{ID: "a1", Name: "web-01", OS: "linux", Status: StatusOnline,
		LastSeen: at(now.Add(-3 * time.Minute))}, now, DefaultDisconnectedAfter, DefaultStaleAfter)
	if tr == nil || tr.To != StatusDisconnected || tr.Event == nil {
		t.Fatalf("disconnect must produce a transition with an event, got %+v", tr)
	}
	if tr.Event.Event.Severity != ingest.SeverityHigh {
		t.Fatalf("disconnect alert must be high severity, got %v", tr.Event.Event.Severity)
	}
	if tr.Event.Threat == nil || tr.Event.Threat.Technique.ID != "T1562.001" {
		t.Fatal("disconnect alert must carry the Impair Defenses technique")
	}
	if tr.Event.Host == nil || tr.Event.Host.Name != "web-01" {
		t.Fatal("disconnect alert must name the agent host")
	}

	// disconnected -> stale: silent (already alerted at disconnect).
	tr = Evaluate(AgentHealth{Status: StatusDisconnected, LastSeen: at(now.Add(-30 * time.Hour))},
		now, DefaultDisconnectedAfter, DefaultStaleAfter)
	if tr == nil || tr.To != StatusStale || tr.Event != nil {
		t.Fatalf("stale must be a silent transition, got %+v", tr)
	}

	// disconnected -> online: informational recovery event.
	tr = Evaluate(AgentHealth{Status: StatusDisconnected, LastSeen: at(now.Add(-10 * time.Second))},
		now, DefaultDisconnectedAfter, DefaultStaleAfter)
	if tr == nil || tr.To != StatusOnline || tr.Event == nil || tr.Event.Event.Severity != ingest.SeverityInfo {
		t.Fatalf("recovery must produce an info event, got %+v", tr)
	}

	// online -> degraded: medium alert carrying the agent's own detail.
	tr = Evaluate(AgentHealth{Status: StatusOnline, LastSeen: at(now.Add(-10 * time.Second)),
		Degraded: true, Detail: "42 buffered batch(es) awaiting delivery"},
		now, DefaultDisconnectedAfter, DefaultStaleAfter)
	if tr == nil || tr.To != StatusDegraded || tr.Event == nil || tr.Event.Event.Severity != ingest.SeverityMedium {
		t.Fatalf("degraded must produce a medium event, got %+v", tr)
	}

	// No change -> nil.
	if tr = Evaluate(AgentHealth{Status: StatusOnline, LastSeen: at(now)},
		now, DefaultDisconnectedAfter, DefaultStaleAfter); tr != nil {
		t.Fatalf("no change must return nil, got %+v", tr)
	}

	// unknown (never seen) stays silent - nothing to alert about yet.
	if tr = Evaluate(AgentHealth{Status: StatusUnknown},
		now, DefaultDisconnectedAfter, DefaultStaleAfter); tr != nil {
		t.Fatalf("never-seen agent must not transition, got %+v", tr)
	}
}

func TestJanitorEvent(t *testing.T) {
	ev := JanitorEvent(time.Now(), 3, time.Now().Add(-40*24*time.Hour), 92, "50 GB")
	if ev.Event.Severity != ingest.SeverityHigh || ev.DeusWatch.Label != "selfhealth" {
		t.Fatalf("janitor event must be a high selfhealth alert, got %+v", ev.Event)
	}
	if ev.Rule == nil || ev.Rule.ID != "deuswatch_disk_janitor" {
		t.Fatal("janitor event must carry its rule id")
	}
}
