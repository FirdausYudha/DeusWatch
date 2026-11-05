package store

// Importing the controlled-test log into scenario_runs, and the two small writes the scorecard
// needs: a reviewer's false-positive verdict on an alert, and a manual figure (report prep time).
//
// The import is header-driven: it reads catatan_skenario.csv by COLUMN NAME, so the file can carry
// the extra `teknik` column or not and old exports still load. A malformed row is rejected with its
// line number rather than silently dropped, because a test log that quietly loses rows would make
// the detection rate and MTTD wrong in a way nobody would notice.

import (
	"context"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// csvTimeLayout matches the timestamps written into catatan_skenario.csv, e.g.
// "2026-11-05 03:42:13 +0700". An empty cell is a legitimate "did not happen" and becomes NULL.
const csvTimeLayout = "2006-01-02 15:04:05 -0700"

// ImportResult reports what an import did.
type ImportResult struct {
	Imported int      `json:"imported"`
	Rejected []string `json:"rejected"` // human-readable "line N: reason"
}

// ScenarioRunRow is one parsed, validated row ready to upsert.
type ScenarioRunRow struct {
	ScenarioID    string
	Repetition    int
	ExecutedAt    *time.Time
	AlertedAt     *time.Time
	RespondedAt   *time.Time
	RuleOrFeature string
	Technique     string
	Detected      bool
	Note          string
}

// ParseScenarioCSV parses the CSV text into rows, collecting per-line rejections rather than
// failing the whole file on the first bad row. Pure (no DB), so it is unit-tested directly.
func ParseScenarioCSV(text string) ([]ScenarioRunRow, []string, error) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1 // rows may have trailing commas; we index by header, not by count
	records, err := r.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(records) == 0 {
		return nil, nil, fmt.Errorf("csv is empty")
	}
	// Map header name -> column index, then resolve canonical fields through aliases so both the
	// English (product) and Indonesian (capstone) column names load from the same code.
	col := map[string]int{}
	for i, h := range records[0] {
		col[strings.TrimSpace(strings.ToLower(h))] = i
	}
	aliases := map[string][]string{
		"scenario_id":     {"scenario_id", "id_skenario"},
		"repetition":      {"repetition", "ulangan"},
		"executed_at":     {"executed_at", "waktu_eksekusi"},
		"alerted_at":      {"alerted_at", "waktu_alert"},
		"responded_at":    {"responded_at", "waktu_respons"},
		"rule_or_feature": {"rule_or_feature", "aturan_atau_fitur"},
		"technique":       {"technique", "teknik"},
		"detected":        {"detected", "terdeteksi"},
		"note":            {"note", "catatan"},
	}
	idx := map[string]int{}
	for canon, alist := range aliases {
		for _, a := range alist {
			if i, ok := col[a]; ok {
				idx[canon] = i
				break
			}
		}
	}
	for _, n := range []string{"scenario_id", "repetition", "detected"} {
		if _, ok := idx[n]; !ok {
			return nil, nil, fmt.Errorf("csv is missing required column %q (or its alias)", n)
		}
	}
	get := func(rec []string, name string) string {
		if i, ok := idx[name]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	parseTime := func(s string) (*time.Time, error) {
		if s == "" {
			return nil, nil
		}
		t, err := time.Parse(csvTimeLayout, s)
		if err != nil {
			return nil, err
		}
		return &t, nil
	}

	var rows []ScenarioRunRow
	var rejected []string
	for li, rec := range records[1:] {
		line := li + 2 // human line number (1-based, header is line 1)
		sid := get(rec, "scenario_id")
		if sid == "" {
			continue // blank trailing line, not an error
		}
		rep, err := strconv.Atoi(get(rec, "repetition"))
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("line %d: repetition is not a number (%q)", line, get(rec, "repetition")))
			continue
		}
		exec, e1 := parseTime(get(rec, "executed_at"))
		alert, e2 := parseTime(get(rec, "alerted_at"))
		resp, e3 := parseTime(get(rec, "responded_at"))
		if e1 != nil || e2 != nil || e3 != nil {
			rejected = append(rejected, fmt.Sprintf("line %d: bad time format (use 'YYYY-MM-DD HH:MM:SS +0700')", line))
			continue
		}
		det := strings.ToLower(get(rec, "detected"))
		detected := det == "yes" || det == "ya" || det == "true" || det == "1"
		rows = append(rows, ScenarioRunRow{
			ScenarioID:    sid,
			Repetition:    rep,
			ExecutedAt:    exec,
			AlertedAt:     alert,
			RespondedAt:   resp,
			RuleOrFeature: get(rec, "rule_or_feature"),
			Technique:     get(rec, "technique"),
			Detected:      detected,
			Note:          get(rec, "note"),
		})
	}
	return rows, rejected, nil
}

// ImportScenarioRuns parses and upserts the controlled-test log. Rows are keyed by
// (scenario, repetition) so re-importing updates in place instead of duplicating.
func (s *Store) ImportScenarioRuns(ctx context.Context, csvText string) (*ImportResult, error) {
	rows, rejected, err := ParseScenarioCSV(csvText)
	if err != nil {
		return nil, err
	}
	res := &ImportResult{Rejected: rejected}
	for _, row := range rows {
		_, err := s.q(ctx).Exec(ctx, `
			INSERT INTO scenario_runs
			  (scenario_id, repetition, executed_at, alerted_at, responded_at, rule_or_feature, technique, detected, note)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (tenant_id, scenario_id, repetition) DO UPDATE SET
			  executed_at = EXCLUDED.executed_at, alerted_at = EXCLUDED.alerted_at,
			  responded_at = EXCLUDED.responded_at, rule_or_feature = EXCLUDED.rule_or_feature,
			  technique = EXCLUDED.technique, detected = EXCLUDED.detected, note = EXCLUDED.note`,
			row.ScenarioID, row.Repetition, row.ExecutedAt, row.AlertedAt, row.RespondedAt,
			row.RuleOrFeature, row.Technique, row.Detected, row.Note)
		if err != nil {
			return nil, fmt.Errorf("store: import scenario run %s/%d: %w", row.ScenarioID, row.Repetition, err)
		}
		res.Imported++
	}
	return res, nil
}

// MarkAlertReview records a reviewer's verdict on one alert (false positive or not). One verdict
// per event; a changed verdict overwrites.
func (s *Store) MarkAlertReview(ctx context.Context, eventID string, falsePositive bool, by string) error {
	if strings.TrimSpace(eventID) == "" {
		return fmt.Errorf("store: alert review needs an event id")
	}
	_, err := s.q(ctx).Exec(ctx, `
		INSERT INTO alert_reviews (event_id, false_positive, reviewed_by)
		VALUES ($1,$2,$3)
		ON CONFLICT (tenant_id, event_id) DO UPDATE SET
		  false_positive = EXCLUDED.false_positive, reviewed_by = EXCLUDED.reviewed_by, reviewed_at = now()`,
		eventID, falsePositive, by)
	if err != nil {
		return fmt.Errorf("store: mark alert review: %w", err)
	}
	return nil
}

// AddScorecardInput records a manual figure (e.g. report_prep_time, in days). The scorecard reads
// the most recent value per key, so a correction is just another insert.
func (s *Store) AddScorecardInput(ctx context.Context, key string, value float64, by string) error {
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("store: scorecard input needs a key")
	}
	_, err := s.q(ctx).Exec(ctx,
		`INSERT INTO scorecard_inputs (input_key, value, recorded_by) VALUES ($1,$2,$3)`,
		key, value, by)
	if err != nil {
		return fmt.Errorf("store: add scorecard input: %w", err)
	}
	return nil
}
