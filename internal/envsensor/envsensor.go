// Package envsensor evaluates environmental readings against their thresholds.
//
// Gap 6 of the hospital field insight. The driver is accreditation, not comfort:
//
//	"Ruangan suhu... batasnya kan 18 derajat sampai 23 dengan kelembapannya 60%. Karena finger juga
//	 peraturan dari rumah sakit sama BPJS, akreditasinya: CCTV, finger, suhu, APAR, alat kelembapan."
//
// There is no Bardi driver here, for the third time in this codebase and for the same reason it was
// right the first two: the hospital named one brand, every site uses a different one, and a vendor
// integration written from here is a guess about an API nobody on this project can test. Readings
// are PUSHED to DeusWatch instead, by whatever already talks to the device, which is a few lines of
// script against a vendor cloud, a Home Assistant automation, or a Modbus gateway.
//
// This package holds only the judgement: given a reading and a sensor's rules, is this a breach, is
// it a recovery, or is it nothing. No database, no HTTP, no clock beyond what the caller passes, so
// every rule that decides whether somebody gets paged at 3am is testable against a table of
// numbers.
package envsensor

import (
	"fmt"
	"math"
	"time"
)

// Sensor is the operator-defined rule set for one measurement point.
type Sensor struct {
	Name     string
	Location string
	Unit     string
	// WarnAbove and WarnBelow are the accreditation limits. Nil means no rule in that direction.
	// A hospital server room is "18 to 23", which is both at once; a fridge is only an upper
	// bound; a fire-panel pressure gauge is only a lower one.
	WarnAbove *float64
	WarnBelow *float64
	// StaleAfter is how long silence may last before the sensor itself is the alert. Zero means
	// the sensor is never considered stale, which should be rare: see Stale.
	StaleAfter time.Duration
}

// State is what the store keeps between readings, so one breach produces one alert rather than one
// per reading. A probe sampling every 30 seconds in a room that is two degrees too warm would
// otherwise raise 2,880 alerts a day and teach everyone to ignore the channel.
type State struct {
	Alerting bool
	// LastAt is when a reading last arrived. The zero time means never.
	LastAt time.Time
}

// Verdict is what the caller should do about one reading.
type Verdict struct {
	// Breach is non-empty when the reading is outside its limits, and reads as a sentence.
	Breach string
	// Transition is true when this reading CHANGED the alerting state, which is the only time a
	// notification should be sent.
	Transition bool
	// Alerting is the state to store.
	Alerting bool
	// Recovered is true on the transition back to normal, so the recovery notice can say so
	// rather than going silent and leaving somebody wondering.
	Recovered bool
}

// Evaluate judges one reading.
func Evaluate(s Sensor, st State, value float64) Verdict {
	v := Verdict{Alerting: st.Alerting}

	switch {
	case math.IsNaN(value) || math.IsInf(value, 0):
		// A broken probe often reports NaN rather than going silent. Treating it as a number would
		// compare it against the limits and quietly decide everything is fine, because every
		// comparison against NaN is false.
		v.Breach = "the sensor reported a value that is not a number, which usually means the probe has failed"
	case s.WarnAbove != nil && value > *s.WarnAbove:
		v.Breach = fmt.Sprintf("%s is %s, above the %s limit",
			s.Name, format(value, s.Unit), format(*s.WarnAbove, s.Unit))
	case s.WarnBelow != nil && value < *s.WarnBelow:
		v.Breach = fmt.Sprintf("%s is %s, below the %s limit",
			s.Name, format(value, s.Unit), format(*s.WarnBelow, s.Unit))
	}

	nowAlerting := v.Breach != ""
	v.Transition = nowAlerting != st.Alerting
	v.Recovered = v.Transition && !nowAlerting
	v.Alerting = nowAlerting
	return v
}

// Stale reports whether a sensor has gone quiet, and is the reason this package exists rather than
// a threshold check living in a handler.
//
// A PUSHED sensor that stops reporting is the most dangerous state it has. Its last reading sits on
// the board looking perfectly healthy, for days, while the server room it is supposed to be
// watching does whatever it likes. Nothing about that screen says the number is old. A threshold
// breach is loud; silence is not, and silence is the one an accreditation audit would ask about.
//
// So silence is an alert in its own right. StaleAfter of zero disables it, which a sensor pushed on
// a human schedule may want, and nothing else should.
func Stale(s Sensor, st State, now time.Time) (bool, string) {
	if s.StaleAfter <= 0 {
		return false, ""
	}
	if st.LastAt.IsZero() {
		return true, fmt.Sprintf("%s has never reported since it was configured", s.Name)
	}
	silence := now.Sub(st.LastAt)
	if silence < s.StaleAfter {
		return false, ""
	}
	return true, fmt.Sprintf("%s has not reported for %s, so the last reading on the board is that old. "+
		"A sensor that went quiet looks identical to one reporting good numbers", s.Name, roundDuration(silence))
}

func format(v float64, unit string) string {
	s := fmt.Sprintf("%.1f", v)
	if unit == "" {
		return s
	}
	return s + " " + unit
}

// roundDuration drops the noise: "3h12m" reads, "3h12m8.41293s" does not.
func roundDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return d.Round(time.Minute).String()
	default:
		return d.Round(time.Minute).String()
	}
}
