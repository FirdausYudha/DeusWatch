package sigma

import "testing"

func TestParseMitigationAction(t *testing.T) {
	r, err := ParseRule([]byte(`title: t
detection:
  selection:
    process.command_line|contains: 'vssadmin delete shadows'
  condition: selection
mitigation_action:
  action_type: network_containment
  timeout: 1800
  criticality_threshold: high
`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Mitigation == nil {
		t.Fatal("mitigation_action not parsed")
	}
	if r.Mitigation.ActionType != "network_containment" || r.Mitigation.TimeoutSeconds != 1800 || r.Mitigation.CriticalityThreshold != "high" {
		t.Fatalf("bad mitigation: %+v", r.Mitigation)
	}
	// a rule without the block must leave Mitigation nil
	r2, _ := ParseRule([]byte("title: t\ndetection:\n  selection:\n    event.action: x\n  condition: selection\n"))
	if r2.Mitigation != nil {
		t.Fatalf("expected nil mitigation, got %+v", r2.Mitigation)
	}
}

// TestParseAggMitigationAction proves an AGGREGATION rule (e.g. a ransomware mass file-change
// burst) also parses mitigation_action, so it can authorize containment.
func TestParseAggMitigationAction(t *testing.T) {
	r, err := ParseAggRule([]byte(`title: ransomware burst
level: critical
detection:
  selection:
    event.category: file
  timeframe: 2m
  condition: selection | count() by host.name > 200
mitigation_action:
  action_type: network_containment
  timeout: 1800
  criticality_threshold: critical
`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Mitigation == nil || r.Mitigation.ActionType != "network_containment" || r.Mitigation.TimeoutSeconds != 1800 {
		t.Fatalf("agg mitigation not parsed: %+v", r.Mitigation)
	}
	// a rule without the block leaves it nil
	r2, _ := ParseAggRule([]byte("title: t\ndetection:\n  selection:\n    event.category: file\n  timeframe: 5m\n  condition: selection | count() by host.name > 100\n"))
	if r2.Mitigation != nil {
		t.Fatalf("expected nil agg mitigation, got %+v", r2.Mitigation)
	}
}
