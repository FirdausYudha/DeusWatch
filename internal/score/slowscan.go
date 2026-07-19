package score

// Slow-scan scoring: catching the reconnaissance that deliberately stays under every static
// threshold — 2 probes today, nothing tomorrow, 5 the day after. No burst rule will ever fire on
// that, because the signal is not volume, it is RECURRENCE AT LOW VOLUME over many days.
//
// The composite score (score.go) looks at a short window and the suspicious-IP watchlist looks at
// ~24h; both miss a source that only wakes up occasionally. This scorer runs over a multi-day
// window and rewards the opposite of what a burst detector rewards: many separate active days,
// FEW events on each of them, spread over a long span.

// SlowScanSignals are the multi-day inputs for one source IP.
type SlowScanSignals struct {
	ActiveDays int // distinct days this IP was seen at all — the recurrence signal
	SpanDays   int // days between first and last sighting (how long it has been coming back)
	Events     int // total events in the window
	Targets    int // distinct things probed (URIs/ports/agents) — breadth of the sweep
}

// SlowScanWeights control the mix. Recurrence dominates: coming back on many separate days is
// what distinguishes a patient scanner from a one-off probe.
type SlowScanWeights struct {
	Recurrence float64 `json:"recurrence"` // how many days it came back
	Stealth    float64 `json:"stealth"`    // how FEW events per active day (low = stealthier)
	Span       float64 `json:"span"`       // how long the campaign has been running
	Breadth    float64 `json:"breadth"`    // how many distinct targets it touched

	DaysCap    int `json:"days_cap"`    // active days that already count as "always coming back"
	SpanCap    int `json:"span_cap"`    // span that counts as a long campaign
	TargetsCap int `json:"targets_cap"` // breadth saturation
	// LoudPerDay is the events/day at which a source stops being "slow" — at or above this the
	// stealth contribution is zero, because a burst detector already covers it.
	LoudPerDay int `json:"loud_per_day"`
	// MinActiveDays is the qualification floor: fewer separate days than this is not a pattern,
	// it is noise, and the IP is not listed at all.
	MinActiveDays int `json:"min_active_days"`
}

func DefaultSlowScanWeights() SlowScanWeights {
	return SlowScanWeights{
		Recurrence: 0.45, Stealth: 0.25, Span: 0.20, Breadth: 0.10,
		DaysCap: 7, SpanCap: 14, TargetsCap: 20, LoudPerDay: 50, MinActiveDays: 3,
	}
}

// Qualifies reports whether the IP shows enough recurrence to be called a slow scanner at all.
// Without this floor the list fills with every IP that appeared twice.
func (w SlowScanWeights) Qualifies(s SlowScanSignals) bool {
	min := w.MinActiveDays
	if min < 2 {
		min = 2
	}
	return s.ActiveDays >= min
}

// ComputeSlowScan folds the multi-day signals into a 0-100 score + band.
func ComputeSlowScan(s SlowScanSignals, w SlowScanWeights) Result {
	ratio := func(v, c int) float64 {
		if c <= 0 || v <= 0 {
			return 0
		}
		f := float64(v) / float64(c) * 100
		if f > 100 {
			f = 100
		}
		return f
	}

	recurrence := ratio(s.ActiveDays, w.DaysCap)
	span := ratio(s.SpanDays, w.SpanCap)
	breadth := ratio(s.Targets, w.TargetsCap)

	// Stealth is INVERTED volume: a handful of events per active day scores high, a flood scores
	// zero (that is a burst, and the burst rules own it).
	stealth := 0.0
	if s.ActiveDays > 0 && w.LoudPerDay > 0 {
		perDay := float64(s.Events) / float64(s.ActiveDays)
		if perDay < float64(w.LoudPerDay) {
			stealth = (1 - perDay/float64(w.LoudPerDay)) * 100
		}
	}

	total := recurrence*w.Recurrence + stealth*w.Stealth + span*w.Span + breadth*w.Breadth
	if sum := w.Recurrence + w.Stealth + w.Span + w.Breadth; sum > 0 {
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
