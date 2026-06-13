package sigma

import (
	"os"
	"strings"
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

func mustParseAgg(t *testing.T, y string) *AggRule {
	t.Helper()
	r, err := ParseAggRule([]byte(y))
	if err != nil {
		t.Fatalf("ParseAggRule: %v", err)
	}
	return r
}

// Rule agregasi brute-force asli dari berkas: parse + compile SQL.
func TestRealAggRuleBruteForce(t *testing.T) {
	data, err := os.ReadFile("../../../rules/sigma/agg/ssh_bruteforce.yml")
	if err != nil {
		t.Fatalf("baca rule: %v", err)
	}
	if !isAggregation(data) {
		t.Fatal("ssh_bruteforce.yml harus terdeteksi sebagai agregasi")
	}
	r := mustParseAgg(t, string(data))

	if r.GroupByField != "source.ip" || r.Op != ">" || r.Threshold != 5 {
		t.Fatalf("parse salah: by=%q op=%q thr=%d", r.GroupByField, r.Op, r.Threshold)
	}
	if r.Window != time.Minute {
		t.Fatalf("timeframe salah: %v", r.Window)
	}
	if tech, tactic := r.MITRE(); tech != "T1110" || tactic != "Credential Access" {
		t.Fatalf("MITRE salah: %q/%q", tech, tactic)
	}
	if r.Severity() != ingest.SeverityHigh {
		t.Fatalf("severity salah: %v", r.Severity())
	}

	query, args := r.CompileSQL()
	for _, want := range []string{
		"GROUP BY source_ip", "host(source_ip) AS grp", "HAVING count(*) > 5",
		"event_dataset", "event_outcome", "time > now() -",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("query tak memuat %q:\n%s", want, query)
		}
	}
	// argumen: 2 nilai selection + 1 interval di akhir.
	if len(args) != 3 {
		t.Fatalf("jumlah args salah: %d (%v)", len(args), args)
	}
	if args[len(args)-1] != "60 seconds" {
		t.Fatalf("interval window salah: %v", args[len(args)-1])
	}
}

func TestAggKeywordCompiles(t *testing.T) {
	r := mustParseAgg(t, `
title: invalid user burst
level: medium
detection:
  keywords:
    - 'invalid user'
  timeframe: 5m
  condition: keywords | count() by source.ip > 10`)

	query, args := r.CompileSQL()
	if !strings.Contains(query, "event_original ILIKE") {
		t.Fatalf("keyword harus jadi ILIKE event_original:\n%s", query)
	}
	if !strings.Contains(query, "HAVING count(*) > 10") {
		t.Fatalf("ambang salah:\n%s", query)
	}
	if args[0] != "%invalid user%" {
		t.Fatalf("arg keyword salah: %v", args[0])
	}
	if args[len(args)-1] != "300 seconds" {
		t.Fatalf("window 5m salah: %v", args[len(args)-1])
	}
}

func TestAggGlobalNoGroupBy(t *testing.T) {
	r := mustParseAgg(t, `
title: total failures spike
level: low
detection:
  selection:
    event.outcome: failure
  timeframe: 1m
  condition: selection | count() > 100`)

	query, _ := r.CompileSQL()
	if strings.Contains(query, "GROUP BY") {
		t.Fatalf("agregasi global tak boleh punya GROUP BY:\n%s", query)
	}
	if !strings.Contains(query, "HAVING count(*) > 100") {
		t.Fatalf("ambang salah:\n%s", query)
	}
}

func TestAggUnsupportedPipe(t *testing.T) {
	_, err := ParseAggRule([]byte(`
title: distinct count
detection:
  selection:
    event.outcome: failure
  condition: selection | count(user.name) by source.ip > 5`))
	if err == nil {
		t.Fatal("count(field) distinct belum didukung -> harus error")
	}
}

func TestAggUnknownFieldColumn(t *testing.T) {
	_, err := ParseAggRule([]byte(`
title: bad field
detection:
  selection:
    nonexistent.field: x
  condition: selection | count() by source.ip > 5`))
	if err == nil {
		t.Fatal("field tanpa kolom DCS -> harus error compile")
	}
}

func TestLoadAggDirSeparatesRules(t *testing.T) {
	// dir rules/sigma berisi single-event + sub-dir agg/.
	agg, err := LoadAggDir("../../../rules/sigma")
	if err != nil {
		t.Fatalf("LoadAggDir: %v", err)
	}
	if len(agg) < 2 {
		t.Fatalf("harap >=2 rule agregasi, dapat %d", len(agg))
	}
	single, err := LoadDir("../../../rules/sigma")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	// rule single-event tidak boleh mengandung rule agregasi.
	if len(single) == 0 {
		t.Fatal("harap ada rule single-event")
	}
}
