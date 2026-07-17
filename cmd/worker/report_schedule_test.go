package main

import (
	"testing"
	"time"
)

func at(day, hour, min int) time.Time {
	return time.Date(2026, 7, day, hour, min, 0, 0, time.Local)
}

func TestReportDueDriftingInterval(t *testing.T) {
	// atHour = -1 keeps the classic behaviour: fire once the interval has elapsed.
	if reportDue(at(1, 10, 0), time.Time{}, false, 24, -1) != true {
		t.Fatal("no previous summary: should run immediately")
	}
	if reportDue(at(1, 10, 0), at(1, 0, 0), true, 24, -1) {
		t.Fatal("only 10h since the last summary: not due")
	}
	if !reportDue(at(2, 1, 0), at(1, 0, 0), true, 24, -1) {
		t.Fatal("25h since the last summary: due")
	}
	if reportDue(at(1, 10, 0), at(1, 0, 0), true, 0, -1) {
		t.Fatal("interval 0 = disabled: never due")
	}
}

func TestReportDueAtFixedHour(t *testing.T) {
	// Daily at 08:00.
	if reportDue(at(1, 7, 50), at(1, 0, 0), true, 24, 8) {
		t.Fatal("07:50 is not the appointed hour")
	}
	if !reportDue(at(2, 8, 0), at(1, 8, 0), true, 24, 8) {
		t.Fatal("08:00 a day later: due")
	}
	// Must not fire twice within the same hour (the scheduler ticks every 10 min).
	if reportDue(at(2, 8, 10), at(2, 8, 0), true, 24, 8) {
		t.Fatal("already ran at 08:00 today: must not repeat at 08:10")
	}
	// A late previous run (08:05 yesterday) must not skip today's 08:00.
	if !reportDue(at(2, 8, 0), at(1, 8, 5), true, 24, 8) {
		t.Fatal("a slightly-late previous run must not skip the next day")
	}
	// First ever run happens at the appointed hour.
	if !reportDue(at(1, 8, 0), time.Time{}, false, 24, 8) {
		t.Fatal("no previous summary, at the appointed hour: due")
	}
	if reportDue(at(1, 9, 0), time.Time{}, false, 24, 8) {
		t.Fatal("no previous summary but wrong hour: not due")
	}
}

func TestReportDueEveryTwoDaysAtHour(t *testing.T) {
	// interval 48h at 08:00: skip day+1, fire day+2.
	if reportDue(at(2, 8, 0), at(1, 8, 0), true, 48, 8) {
		t.Fatal("only 24h into a 48h interval: not due")
	}
	if !reportDue(at(3, 8, 0), at(1, 8, 0), true, 48, 8) {
		t.Fatal("48h later at the appointed hour: due")
	}
}
