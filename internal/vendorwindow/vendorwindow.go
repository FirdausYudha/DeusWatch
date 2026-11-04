// Package vendorwindow decides whether a vendor account's login falls inside its agreed access
// window. It is the judgement half of RV-01 and holds no database and no clock of its own, so the
// rule that governs who may run code on the SIMRS server at 3am can be tested without either.
//
// The field report (C-08) is the reason this is a package and not a Sigma rule: Sigma matches the
// fields of one event and cannot say "the clock now reads outside the window". The worker calls
// Outside on each vendor login; everything hard about time lives here.
package vendorwindow

import (
	"fmt"
	"time"
)

// Window is one vendor account's agreed access hours, as stored in vendor_accounts.
type Window struct {
	Account string
	// Days are the allowed weekdays as ISO numbers, 1=Monday .. 7=Sunday.
	Days      []int
	Start     time.Time // only the clock part is read
	End       time.Time // only the clock part is read
	Timezone  string    // IANA name, e.g. Asia/Jakarta
	loadedLoc *time.Location
}

// Verdict is the outcome of checking one login against a window.
type Verdict struct {
	Outside bool
	// Reason is a short human sentence for the alert, in the account's local time so the operator
	// reads the same clock the vendor contract is written in.
	Reason string
}

// Location resolves the window's timezone once. A timezone that does not load is NOT treated as
// UTC: silently evaluating a WIB contract in UTC would shift the whole window seven hours and
// either miss real out-of-hours access or cry wolf on every normal login. It is an error the
// caller must surface.
func (w *Window) Location() (*time.Location, error) {
	if w.loadedLoc != nil {
		return w.loadedLoc, nil
	}
	tz := w.Timezone
	if tz == "" {
		tz = "UTC"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, fmt.Errorf("vendorwindow: account %q has an unknown timezone %q: %w", w.Account, tz, err)
	}
	w.loadedLoc = loc
	return loc, nil
}

// dayAllowed reports whether an ISO weekday is in the allowed set.
func (w *Window) dayAllowed(d time.Weekday) bool {
	// time.Weekday is 0=Sunday..6=Saturday; the table stores ISO 1=Monday..7=Sunday.
	iso := int(d)
	if iso == 0 {
		iso = 7
	}
	for _, x := range w.Days {
		if x == iso {
			return true
		}
	}
	return false
}

// minutesOfDay returns minutes since midnight for the clock part of t.
func minutesOfDay(t time.Time) int { return t.Hour()*60 + t.Minute() }

// Outside reports whether a login at loginUTC falls outside the window. The login time is given
// in UTC (as events are stored) and converted to the account's local zone here.
//
// A window where Start is after End wraps past midnight, e.g. 22:00 to 06:00 for overnight
// maintenance. That case is the reason this is not a single range comparison: the allowed minutes
// are then the union of [start, end-of-day] and [start-of-day, end], and the allowed DAY is the
// day the window opened, so a login at 02:00 Saturday belongs to a window that opened Friday.
func (w *Window) Outside(loginUTC time.Time) (Verdict, error) {
	loc, err := w.Location()
	if err != nil {
		return Verdict{}, err
	}
	lt := loginUTC.In(loc)
	mins := minutesOfDay(lt)
	start := minutesOfDay(w.Start)
	end := minutesOfDay(w.End)
	human := fmt.Sprintf("%s logged in at %s, outside the allowed window %02d:%02d-%02d:%02d %s",
		w.Account, lt.Format("Mon 15:04 MST"), w.Start.Hour(), w.Start.Minute(),
		w.End.Hour(), w.End.Minute(), w.Timezone)

	if start == end {
		// A zero-length window: no time is ever allowed. Treated as "always outside" rather than
		// "always inside", because an account with no usable window is one that should not be
		// logging in, and the safer reading of an operator mistake is to alert.
		return Verdict{Outside: true, Reason: human}, nil
	}

	if start < end {
		// Same-day window. The login's own weekday must be allowed and its clock within the range.
		if w.dayAllowed(lt.Weekday()) && mins >= start && mins < end {
			return Verdict{}, nil
		}
		return Verdict{Outside: true, Reason: human}, nil
	}

	// Wrapping window (start > end). The login is inside if it is at or after Start on an allowed
	// day, OR before End on the day after an allowed day.
	if mins >= start && w.dayAllowed(lt.Weekday()) {
		return Verdict{}, nil
	}
	if mins < end {
		prevDay := lt.AddDate(0, 0, -1).Weekday()
		if w.dayAllowed(prevDay) {
			return Verdict{}, nil
		}
	}
	return Verdict{Outside: true, Reason: human}, nil
}
