package assistant

import (
	"regexp"
	"strconv"
	"strings"
)

// Time-window parsing for "what happened last week" style questions.
//
// Deterministic, like every other intent in this package. Asking the model to work out a window and
// hand back a number would put arithmetic on the one thing a small model is worst at, and getting
// it wrong is invisible: an answer about the last 7 days when 24 hours were meant looks exactly
// like an answer about the last 24 hours.
//
// Rolling windows only ("the last N hours/days"). Explicit calendar ranges ("1 to 3 October") are
// deliberately out of scope: they need date parsing in two languages and the Report page already
// does them properly with a picker.

const (
	// MinWindowHours is one hour. Shorter windows make the comparison baseline meaningless.
	MinWindowHours = 1
	// MaxWindowHours is 90 days, past which the aggregate queries get expensive enough to notice.
	MaxWindowHours = 24 * 90
)

var (
	reWindowNum = regexp.MustCompile(`(?i)\b(\d{1,4})\s*(jam|hours?|hrs?|hari|days?|minggu|weeks?|bulan|months?)\b`)

	// Bare phrases with no number. Longest first so "dua minggu" is not eaten by "minggu".
	windowPhrases = []struct {
		phrase string
		hours  int
	}{
		{"last 24 hours", 24}, {"24 jam terakhir", 24}, {"sehari", 24}, {"hari ini", 24}, {"today", 24},
		{"last week", 24 * 7}, {"minggu lalu", 24 * 7}, {"minggu ini", 24 * 7}, {"seminggu", 24 * 7},
		{"last month", 24 * 30}, {"bulan lalu", 24 * 30}, {"bulan ini", 24 * 30}, {"sebulan", 24 * 30},
		{"semalam", 12}, {"last night", 12},
	}
)

// ParseWindow extracts a rolling window in hours from the operator's message. ok is false when no
// window was named, and the caller keeps its default.
func ParseWindow(msg string) (hours int, ok bool) {
	low := strings.ToLower(msg)

	if m := reWindowNum.FindStringSubmatch(low); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil || n <= 0 {
			return 0, false
		}
		switch unit := m[2]; {
		case strings.HasPrefix(unit, "jam"), strings.HasPrefix(unit, "hour"), strings.HasPrefix(unit, "hr"):
			hours = n
		case strings.HasPrefix(unit, "hari"), strings.HasPrefix(unit, "day"):
			hours = n * 24
		case strings.HasPrefix(unit, "minggu"), strings.HasPrefix(unit, "week"):
			hours = n * 24 * 7
		case strings.HasPrefix(unit, "bulan"), strings.HasPrefix(unit, "month"):
			hours = n * 24 * 30
		}
		return clampWindow(hours), hours > 0
	}

	for _, p := range windowPhrases {
		if strings.Contains(low, p.phrase) {
			return p.hours, true
		}
	}
	return 0, false
}

func clampWindow(h int) int {
	if h < MinWindowHours {
		return MinWindowHours
	}
	if h > MaxWindowHours {
		return MaxWindowHours
	}
	return h
}

// NeedsComparison reports whether the question is about change rather than state.
//
// The comparison block doubles the report queries, so it is not run for every message. "What
// happened today" wants a description; "is anything unusual" wants a baseline, and without one the
// model has nothing to measure against and will produce an impression instead of a finding.
var comparisonWords = []string{
	"anomal", "unusual", "odd", "strange", "spike", "spiked", "surge", "trend", "change", "changed",
	"different", "compare", "comparison", "increase", "increased", "drop", "dropped", "rise", "risen",
	"worse", "better", "new ", "baseline", "normal",
	"aneh", "janggal", "mencurigakan", "lonjakan", "naik", "turun", "berubah", "perubahan",
	"bandingkan", "dibanding", "tren", "biasa", "tidak biasa", "meningkat", "menurun", "baru",
}

func NeedsComparison(msg string) bool {
	low := strings.ToLower(msg)
	for _, w := range comparisonWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}
