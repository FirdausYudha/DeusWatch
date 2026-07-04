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
