package score

import "testing"

func TestComposeAnomalyOptIn(t *testing.T) {
	sig := Signals{FiredTimes: 5, Abuse: 10, OTX: 0, MaxSeverity: 2, Anomaly: 100}

	// Default weights (anomaly weight 0) → the ML anomaly must NOT change the score, so existing
	// deployments are unchanged until the operator opts in.
	base := Compute(sig, DefaultWeights())
	noAnom := Compute(Signals{FiredTimes: 5, Abuse: 10, OTX: 0, MaxSeverity: 2, Anomaly: 0}, DefaultWeights())
	if base.Score != noAnom.Score {
		t.Fatalf("anomaly must not affect the score at weight 0: %d vs %d", base.Score, noAnom.Score)
	}

	// With an anomaly weight, a high anomaly_score pulls the composite score UP.
	w := DefaultWeights()
	w.Anomaly = 0.5
	withAnom := Compute(sig, w)
	if withAnom.Score <= base.Score {
		t.Fatalf("a high anomaly with weight should raise the score: %d (was %d)", withAnom.Score, base.Score)
	}
}

func TestComputeSuspicion(t *testing.T) {
	w := DefaultSuspicionWeights()

	// Textbook low-and-slow recon: few requests, but many DISTINCT targets, mostly failing,
	// spread across many hours. Fan-out + failure dominate -> should score high.
	slowScan := ComputeSuspicion(SuspicionSignals{
		Contacts: 15, FanOut: 20, Failures: 14, DistinctHours: 12,
	}, w)
	if slowScan.Score < 75 || slowScan.Band != "critical" {
		t.Fatalf("low-and-slow scanner should score critical, got %d/%s", slowScan.Score, slowScan.Band)
	}

	// A chatty but BENIGN client: lots of contacts, but ONE target, no failures, all in one
	// hour (e.g. an uptime monitor). Fan-out 1 + 0 failures -> should stay low.
	monitor := ComputeSuspicion(SuspicionSignals{
		Contacts: 50, FanOut: 1, Failures: 0, DistinctHours: 1,
	}, w)
	if monitor.Score >= 25 {
		t.Fatalf("a single-target, no-failure client must not look suspicious, got %d/%s", monitor.Score, monitor.Band)
	}

	// Fan-out matters more than raw volume: 8 distinct targets all failing beats 50 hits at one.
	fanout := ComputeSuspicion(SuspicionSignals{Contacts: 8, FanOut: 8, Failures: 8, DistinctHours: 6}, w)
	if fanout.Score <= monitor.Score {
		t.Fatalf("fan-out+failures (%d) should outscore a benign chatty client (%d)", fanout.Score, monitor.Score)
	}

	// Empty signals -> zero, no divide-by-zero.
	if z := ComputeSuspicion(SuspicionSignals{}, w); z.Score != 0 {
		t.Fatalf("no signals should score 0, got %d", z.Score)
	}
}
