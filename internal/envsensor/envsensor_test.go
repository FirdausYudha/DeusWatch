package envsensor

import (
	"math"
	"strings"
	"testing"
	"time"
)

func f(v float64) *float64 { return &v }

// The hospital's own numbers: a server room held between 18 and 23 degrees.
func TestEvaluateAgainstBothLimits(t *testing.T) {
	s := Sensor{Name: "Server room temperature", Unit: "C", WarnBelow: f(18), WarnAbove: f(23)}

	for _, c := range []struct {
		name   string
		value  float64
		breach bool
	}{
		{"mid range", 21, false},
		{"exactly the lower limit is still inside", 18, false},
		{"exactly the upper limit is still inside", 23, false},
		{"a tenth over", 23.1, true},
		{"a tenth under", 17.9, true},
		{"air conditioning failed", 34.5, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := Evaluate(s, State{}, c.value)
			if (v.Breach != "") != c.breach {
				t.Errorf("value %.1f: breach=%q, want breach=%v", c.value, v.Breach, c.breach)
			}
			if c.breach && !strings.Contains(v.Breach, "C") {
				t.Errorf("the message should carry the unit so a number is readable: %q", v.Breach)
			}
		})
	}
}

// A probe reporting every 30 seconds in a room two degrees too warm would otherwise raise 2,880
// alerts a day, and the channel everyone mutes is worse than no channel.
func TestOnlyTransitionsNotify(t *testing.T) {
	s := Sensor{Name: "Temp", Unit: "C", WarnAbove: f(23)}

	first := Evaluate(s, State{Alerting: false}, 30)
	if !first.Transition || !first.Alerting || first.Recovered {
		t.Fatalf("the first bad reading must notify: %+v", first)
	}
	again := Evaluate(s, State{Alerting: true}, 31)
	if again.Transition {
		t.Error("a second bad reading must not notify again")
	}
	if !again.Alerting {
		t.Error("it is still a breach, so the state must stay alerting")
	}
	back := Evaluate(s, State{Alerting: true}, 21)
	if !back.Transition || !back.Recovered || back.Alerting {
		t.Errorf("the return to normal must notify as a recovery: %+v", back)
	}
	quiet := Evaluate(s, State{Alerting: false}, 21)
	if quiet.Transition {
		t.Error("an ordinary good reading must not notify")
	}
}

// A failed probe often reports NaN rather than going silent, and every comparison against NaN is
// false, so treating it as a number decides silently that everything is fine.
func TestNotANumberIsABreach(t *testing.T) {
	s := Sensor{Name: "Temp", Unit: "C", WarnAbove: f(23), WarnBelow: f(18)}
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		v := Evaluate(s, State{}, bad)
		if v.Breach == "" {
			t.Errorf("%v passed as a valid reading", bad)
		}
		if !strings.Contains(v.Breach, "probe") {
			t.Errorf("the message should point at the probe, not at the room: %q", v.Breach)
		}
	}
}

// A sensor with only one rule must not be judged against the other.
func TestOneSidedLimits(t *testing.T) {
	up := Sensor{Name: "Fridge", Unit: "C", WarnAbove: f(8)}
	if v := Evaluate(up, State{}, -40); v.Breach != "" {
		t.Errorf("no lower limit is set, so cold is not a breach: %q", v.Breach)
	}
	down := Sensor{Name: "Panel pressure", Unit: "bar", WarnBelow: f(4)}
	if v := Evaluate(down, State{}, 900); v.Breach != "" {
		t.Errorf("no upper limit is set, so high is not a breach: %q", v.Breach)
	}
	if v := Evaluate(down, State{}, 3.9); v.Breach == "" {
		t.Error("below the lower limit must breach")
	}
}

// The reason this package exists. A pushed sensor that stops reporting leaves its last reading on
// the board looking healthy, and nothing about that screen says the number is old.
func TestSilenceIsAnAlert(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := Sensor{Name: "Server room temperature", StaleAfter: 15 * time.Minute}

	if stale, _ := Stale(s, State{LastAt: now.Add(-5 * time.Minute)}, now); stale {
		t.Error("five minutes of silence on a fifteen minute budget is not stale")
	}
	stale, why := Stale(s, State{LastAt: now.Add(-3 * time.Hour)}, now)
	if !stale {
		t.Fatal("three hours of silence must be an alert")
	}
	// The message has to say WHY silence matters, or an operator reads "no data" as "no problem".
	for _, want := range []string{"3h0m", "looks identical"} {
		if !strings.Contains(why, want) {
			t.Errorf("the message should contain %q:\n%s", want, why)
		}
	}

	// Never reported at all is the same failure, caught at configuration time rather than after
	// an outage nobody noticed.
	if stale, why := Stale(s, State{}, now); !stale || !strings.Contains(why, "never reported") {
		t.Errorf("a sensor that never reported must be flagged: %v %q", stale, why)
	}

	// Explicitly disabled, for a reading somebody enters by hand.
	if stale, _ := Stale(Sensor{Name: "Manual"}, State{}, now); stale {
		t.Error("StaleAfter of zero disables the check")
	}
}
