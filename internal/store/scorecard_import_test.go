package store

import "testing"

// ParseScenarioCSV is the validation boundary for the controlled-test log: a malformed row must be
// rejected with its line number, not silently dropped, or the detection rate and MTTD would be
// wrong in a way nobody sees. Pure, no database.
func TestParseScenarioCSV(t *testing.T) {
	csv := "id_skenario,ulangan,waktu_eksekusi,waktu_alert,waktu_respons,aturan_atau_fitur,teknik,terdeteksi,catatan\n" +
		"S1,1,2026-11-05 03:22:47 +0700,2026-11-05 03:22:48 +0700,,SSH Brute Force,T1110,ya,ok\n" +
		"S5,2,,,,vendor window,T1078,tidak,tanpa waktu\n" +
		"S9,X,2026-11-05 03:00:00 +0700,,,ransomware,T1486,ya,ulangan bukan angka\n" +
		"S2,1,bukan-waktu,,,port scan,T1046,ya,waktu salah\n" +
		"\n"
	rows, rejected, err := ParseScenarioCSV(csv)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("accepted %d rows, want 2 (S1, S5)", len(rows))
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected %d rows, want 2 (bad ulangan, bad time); got %v", len(rejected), rejected)
	}
	// S1 parsed with timestamps and detected true.
	if rows[0].ScenarioID != "S1" || rows[0].ExecutedAt == nil || rows[0].AlertedAt == nil || !rows[0].Detected {
		t.Fatalf("S1 row parsed wrong: %+v", rows[0])
	}
	if rows[0].Technique != "T1110" {
		t.Fatalf("teknik column not read: %q", rows[0].Technique)
	}
	// S5 has empty timestamps (nil) and detected false.
	if rows[1].ScenarioID != "S5" || rows[1].ExecutedAt != nil || rows[1].Detected {
		t.Fatalf("S5 row parsed wrong: %+v", rows[1])
	}
}

// The old export has no `teknik` column; the header-driven parser must still load it.
func TestParseScenarioCSVWithoutTeknik(t *testing.T) {
	csv := "id_skenario,ulangan,waktu_eksekusi,waktu_alert,waktu_respons,aturan_atau_fitur,terdeteksi,catatan\n" +
		"S1,1,2026-11-05 03:22:47 +0700,2026-11-05 03:22:48 +0700,,SSH Brute Force,ya,ok\n"
	rows, rejected, err := ParseScenarioCSV(csv)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 || len(rejected) != 0 {
		t.Fatalf("want 1 row / 0 rejected, got %d / %d", len(rows), len(rejected))
	}
	if rows[0].Technique != "" {
		t.Fatalf("teknik should be empty when column absent, got %q", rows[0].Technique)
	}
}

// English headers (the product format) must load through the alias map.
func TestParseScenarioCSVEnglishHeaders(t *testing.T) {
	csv := "scenario_id,repetition,executed_at,alerted_at,responded_at,rule_or_feature,technique,detected,note\n" +
		"S1,1,2026-11-05 03:22:47 +0700,2026-11-05 03:22:48 +0700,,SSH Brute Force,T1110,yes,ok\n"
	rows, rejected, err := ParseScenarioCSV(csv)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 || len(rejected) != 0 {
		t.Fatalf("want 1 row / 0 rejected, got %d / %d", len(rows), len(rejected))
	}
	if rows[0].ScenarioID != "S1" || !rows[0].Detected || rows[0].Technique != "T1110" {
		t.Fatalf("english-header row parsed wrong: %+v", rows[0])
	}
}

func TestParseScenarioCSVMissingColumn(t *testing.T) {
	// Missing the required id_skenario column is a whole-file error, not a per-row rejection.
	csv := "ulangan,terdeteksi\n1,ya\n"
	if _, _, err := ParseScenarioCSV(csv); err == nil {
		t.Fatal("expected error for missing id_skenario column")
	}
}
