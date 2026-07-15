package score

import "testing"

func TestCompute(t *testing.T) {
	w := DefaultWeights()

	// Nothing known -> low.
	if r := Compute(Signals{}, w); r.Score != 0 || r.Band != "low" {
		t.Fatalf("empty signals: got %+v", r)
	}

	// Known abuser hammering: abuse 100, 20 fires, otx 10, sev 3.
	r := Compute(Signals{FiredTimes: 20, Abuse: 100, OTX: 10, MaxSeverity: 3}, w)
	if r.Score < 75 || r.Band != "critical" {
		t.Fatalf("heavy attacker should be critical, got %+v", r)
	}

	// Reputation alone high (abuse 100) but quiet -> abuse weight 0.40 -> ~40 -> medium.
	r = Compute(Signals{Abuse: 100}, w)
	if r.Band != "medium" {
		t.Fatalf("abuse-only 100 should be medium (~40), got %+v", r)
	}

	// Caps: 1000 fires saturate to the fired cap, not overflow.
	r = Compute(Signals{FiredTimes: 1000}, w)
	if r.Score > 40 { // fired weight 0.30 -> max ~30
		t.Fatalf("fired_times must saturate, got %+v", r)
	}
}

func TestBands(t *testing.T) {
	cases := map[int]string{0: "low", 24: "low", 25: "medium", 49: "medium", 50: "high", 74: "high", 75: "critical", 100: "critical"}
	for s, want := range cases {
		if got := Band(s); got != want {
			t.Errorf("Band(%d)=%s, want %s", s, got, want)
		}
	}
}
