package vendorwindow

import (
	"testing"
	"time"
)

// clock parses an RFC3339 time in UTC for the tests.
func clock(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad test time %q: %v", s, err)
	}
	return ts.UTC()
}

func hhmm(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse("15:04", s)
	if err != nil {
		t.Fatalf("bad clock %q: %v", s, err)
	}
	return ts
}

// A standard office window in Jakarta: Mon-Fri 08:00-17:00 WIB (UTC+7).
func officeWIB(t *testing.T) *Window {
	return &Window{
		Account:  "vnd-acme",
		Days:     []int{1, 2, 3, 4, 5},
		Start:    hhmm(t, "08:00"),
		End:      hhmm(t, "17:00"),
		Timezone: "Asia/Jakarta",
	}
}

func TestInsideWindow(t *testing.T) {
	w := officeWIB(t)
	// 2026-11-04 is a Wednesday. 10:00 WIB = 03:00 UTC.
	v, err := w.Outside(clock(t, "2026-11-04T03:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Outside {
		t.Fatalf("a Wednesday 10:00 WIB login was flagged: %s", v.Reason)
	}
}

func TestOutsideByHour(t *testing.T) {
	w := officeWIB(t)
	// 03:00 WIB Wednesday = 2026-11-03T20:00Z. Deep outside the window.
	v, err := w.Outside(clock(t, "2026-11-03T20:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Outside {
		t.Fatal("a 03:00 WIB login was not flagged")
	}
}

// TestTimezoneIsNotUTC is the bug this feature exists to avoid. 08:30 WIB is inside the window,
// but 08:30 UTC is 15:30 WIB (also inside) while 02:00 UTC is 09:00 WIB (inside) and 23:00 UTC is
// 06:00 WIB next day (outside). If the evaluator ignored the zone it would judge the UTC clock and
// get all of these wrong.
func TestTimezoneIsNotUTC(t *testing.T) {
	w := officeWIB(t)
	// 01:30 UTC = 08:30 WIB Wednesday: inside.
	if v, _ := w.Outside(clock(t, "2026-11-04T01:30:00Z")); v.Outside {
		t.Error("08:30 WIB should be inside the 08:00-17:00 window")
	}
	// 23:00 UTC Wednesday = 06:00 WIB Thursday: outside (before 08:00).
	if v, _ := w.Outside(clock(t, "2026-11-04T23:00:00Z")); !v.Outside {
		t.Error("06:00 WIB should be outside the window")
	}
}

func TestDayNotAllowed(t *testing.T) {
	w := officeWIB(t)
	// 2026-11-07 is a Saturday. 10:00 WIB = 03:00 UTC. Right hour, wrong day.
	v, _ := w.Outside(clock(t, "2026-11-07T03:00:00Z"))
	if !v.Outside {
		t.Fatal("a Saturday login was not flagged even though Saturday is not allowed")
	}
}

// TestWrappingWindow covers overnight maintenance, 22:00-06:00, where the allowed minutes span
// midnight and the allowed day is the day the window opened.
func TestWrappingWindow(t *testing.T) {
	w := &Window{
		Account:  "vnd-night",
		Days:     []int{1, 2, 3, 4, 5}, // window OPENS on a weekday
		Start:    hhmm(t, "22:00"),
		End:      hhmm(t, "06:00"),
		Timezone: "Asia/Jakarta",
	}
	// Friday 23:00 WIB = 2026-11-06T16:00Z. Inside (after 22:00 on an allowed opening day).
	if v, _ := w.Outside(clock(t, "2026-11-06T16:00:00Z")); v.Outside {
		t.Errorf("Fri 23:00 WIB should be inside an overnight window: %s", v.Reason)
	}
	// Saturday 02:00 WIB = 2026-11-06T19:00Z. Inside: the window opened Friday, an allowed day.
	if v, _ := w.Outside(clock(t, "2026-11-06T19:00:00Z")); v.Outside {
		t.Errorf("Sat 02:00 WIB should belong to Friday's overnight window: %s", v.Reason)
	}
	// Sunday 02:00 WIB = 2026-11-07T19:00Z. Outside: it would belong to Saturday's window, and
	// Saturday is not an allowed opening day.
	if v, _ := w.Outside(clock(t, "2026-11-07T19:00:00Z")); !v.Outside {
		t.Error("Sun 02:00 WIB should be outside: Saturday is not an allowed opening day")
	}
	// Saturday 12:00 WIB = 2026-11-07T05:00Z. Outside: daytime, no window open.
	if v, _ := w.Outside(clock(t, "2026-11-07T05:00:00Z")); !v.Outside {
		t.Error("Sat 12:00 WIB should be outside an overnight window")
	}
}

// TestUnknownTimezoneIsAnError: a bad zone must not degrade to UTC, which would shift the whole
// window and make every verdict wrong in the same direction.
func TestUnknownTimezoneIsAnError(t *testing.T) {
	w := &Window{Account: "vnd-x", Days: []int{1}, Start: hhmm(t, "08:00"), End: hhmm(t, "17:00"),
		Timezone: "Mars/Olympus"}
	if _, err := w.Outside(clock(t, "2026-11-04T03:00:00Z")); err == nil {
		t.Fatal("an unknown timezone was accepted and silently treated as UTC")
	}
}

// TestZeroLengthWindowAlerts: a window of no length allows no time, so every login is outside.
// The safer reading of that operator mistake is to alert, not to wave everything through.
func TestZeroLengthWindow(t *testing.T) {
	w := &Window{Account: "vnd-z", Days: []int{1, 2, 3, 4, 5}, Start: hhmm(t, "09:00"),
		End: hhmm(t, "09:00"), Timezone: "Asia/Jakarta"}
	if v, _ := w.Outside(clock(t, "2026-11-04T03:00:00Z")); !v.Outside {
		t.Fatal("a zero-length window should treat every login as outside")
	}
}
