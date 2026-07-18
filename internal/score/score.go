// Package score implements DeusWatch's composite threat scoring: a single 0-100 score per
// source IP accumulated from multiple signals over a time window (Multi-Source Event
// Correlation). Unlike a per-rule severity, this is a CONTEXT score for the IP - how bad is
// this source overall right now - combining how often it fired (fired_times), its CTI
// reputation (AbuseIPDB confidence, OTX pulses) and the worst rule severity it triggered.
// It drives the dashboard's per-IP risk indicator and, optionally, a "scenario ban".
package score

// Signals are the accumulated inputs for one source IP over the scoring window.
type Signals struct {
	FiredTimes  int // number of events/alerts from this IP in the window
	Abuse       int // AbuseIPDB confidence 0-100
	OTX         int // AlienVault OTX pulse count
	MaxSeverity int // worst DCS severity seen 0-4 (info..critical)
}

// Weights control the relative contribution of each signal and the caps that saturate the
// unbounded counts (fired_times, OTX pulses) to 100. Weights need not sum to 1 - the result
// is normalized by their sum.
type Weights struct {
	Abuse, FiredTimes, OTX, Severity float64
	OTXCap, FiredCap                 int
}

// DefaultWeights: reputation-forward but repeat-offense still matters. Suricata/WAF
// severity can be folded into MaxSeverity later without changing this shape.
func DefaultWeights() Weights {
	return Weights{Abuse: 0.40, FiredTimes: 0.30, OTX: 0.15, Severity: 0.15, OTXCap: 20, FiredCap: 20}
}

// Result is the computed score + its band.
type Result struct {
	Score int    // 0-100
	Band  string // low | medium | high | critical
}

// Compute folds the signals into a 0-100 score using the weights.
func Compute(s Signals, w Weights) Result {
	cap100 := func(v, c int) float64 {
		if c <= 0 {
			return 0
		}
		f := float64(v) / float64(c) * 100
		if f > 100 {
			f = 100
		}
		return f
	}
	abuse := clamp100(float64(s.Abuse))
	fired := cap100(s.FiredTimes, w.FiredCap)
	otx := cap100(s.OTX, w.OTXCap)
	sev := clamp100(float64(s.MaxSeverity) * 25) // 0..4 -> 0..100

	total := abuse*w.Abuse + fired*w.FiredTimes + otx*w.OTX + sev*w.Severity
	if sum := w.Abuse + w.FiredTimes + w.OTX + w.Severity; sum > 0 {
		total /= sum
	}
	score := int(total + 0.5)
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return Result{Score: score, Band: Band(score)}
}

// Band maps a 0-100 score to a severity band (colored in the UI).
func Band(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

func clamp100(f float64) float64 {
	if f > 100 {
		return 100
	}
	if f < 0 {
		return 0
	}
	return f
}

// ── Suspicious-IP (low-and-slow) behavioral scoring ─────────────────────────
//
// Separate from the composite score above: this catches reconnaissance that stays UNDER the
// radar of CTI feeds, WAF signatures and short-window rules — an IP that touches you a handful
// of times over hours or days. It is deliberately CTI-INDEPENDENT (that's the point) and keys
// off behaviour: how many DISTINCT things it probed (fan-out = the scanner tell), how much of
// its traffic failed / was blocked, how spread out in time it was, and raw volume.

// SuspicionSignals are the behavioral inputs for one source IP over a long window (e.g. 24h).
type SuspicionSignals struct {
	Contacts      int // total events from this IP
	FanOut        int // distinct targets probed (URIs or ports)
	Failures      int // blocked / denied / 4xx / auth-failure events
	DistinctHours int // distinct clock-hours the IP was seen in (spread = deliberate slowness)
}

// SuspicionWeights weight the behavioral signals + the caps that saturate the unbounded counts.
type SuspicionWeights struct {
	FanOut, FailRatio, Spread, Volume float64
	FanOutCap, SpreadCap, VolumeCap   int
}

// DefaultSuspicionWeights emphasizes fan-out and failure ratio (the (a)+(c) approach): a low
// volume that probes many distinct targets and mostly fails is the recon signature.
func DefaultSuspicionWeights() SuspicionWeights {
	return SuspicionWeights{
		FanOut: 0.40, FailRatio: 0.30, Spread: 0.20, Volume: 0.10,
		FanOutCap: 20, SpreadCap: 12, VolumeCap: 50,
	}
}

// ComputeSuspicion folds the behavioral signals into a 0-100 suspicion score + band.
func ComputeSuspicion(s SuspicionSignals, w SuspicionWeights) Result {
	cap := func(v, c int) float64 {
		if c <= 0 || v <= 0 {
			return 0
		}
		return clamp100(float64(v) / float64(c) * 100)
	}
	fanout := cap(s.FanOut, w.FanOutCap)
	spread := cap(s.DistinctHours, w.SpreadCap)
	volume := cap(s.Contacts, w.VolumeCap)
	failRatio := 0.0
	if s.Contacts > 0 {
		failRatio = clamp100(float64(s.Failures) / float64(s.Contacts) * 100)
	}
	total := fanout*w.FanOut + failRatio*w.FailRatio + spread*w.Spread + volume*w.Volume
	if sum := w.FanOut + w.FailRatio + w.Spread + w.Volume; sum > 0 {
		total /= sum
	}
	sc := int(total + 0.5)
	if sc > 100 {
		sc = 100
	}
	if sc < 0 {
		sc = 0
	}
	return Result{Score: sc, Band: Band(sc)}
}
