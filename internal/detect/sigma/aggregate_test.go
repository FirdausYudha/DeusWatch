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

// The real brute-force aggregation rule from file: parse + compile SQL.
func TestRealAggRuleBruteForce(t *testing.T) {
	data, err := os.ReadFile("../../../rules/sigma/agg/ssh_bruteforce.yml")
	if err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if !isAggregation(data) {
		t.Fatal("ssh_bruteforce.yml must be detected as an aggregation")
	}
	r := mustParseAgg(t, string(data))

	if r.GroupByField != "source.ip" || r.Op != ">" || r.Threshold != 5 {
		t.Fatalf("wrong parse: by=%q op=%q thr=%d", r.GroupByField, r.Op, r.Threshold)
	}
	if r.Window != time.Minute {
		t.Fatalf("wrong timeframe: %v", r.Window)
	}
	if tech, tactic := r.MITRE(); tech != "T1110" || tactic != "Credential Access" {
		t.Fatalf("wrong MITRE: %q/%q", tech, tactic)
	}
	if r.Severity() != ingest.SeverityHigh {
		t.Fatalf("wrong severity: %v", r.Severity())
	}

	query, args := r.CompileSQL()
	for _, want := range []string{
		"GROUP BY source_ip", "host(source_ip) AS grp", "HAVING count(*) > 5",
		"event_dataset", "event_outcome", "time > now() -",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("query does not contain %q:\n%s", want, query)
		}
	}
	// arguments: 2 selection values + 1 interval at the end.
	if len(args) != 3 {
		t.Fatalf("wrong number of args: %d (%v)", len(args), args)
	}
	if args[len(args)-1] != "60 seconds" {
		t.Fatalf("wrong window interval: %v", args[len(args)-1])
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
		t.Fatalf("keyword must become ILIKE event_original:\n%s", query)
	}
	if !strings.Contains(query, "HAVING count(*) > 10") {
		t.Fatalf("wrong threshold:\n%s", query)
	}
	if args[0] != "%invalid user%" {
		t.Fatalf("wrong keyword arg: %v", args[0])
	}
	if args[len(args)-1] != "300 seconds" {
		t.Fatalf("wrong 5m window: %v", args[len(args)-1])
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
		t.Fatalf("a global aggregation must not have GROUP BY:\n%s", query)
	}
	if !strings.Contains(query, "HAVING count(*) > 100") {
		t.Fatalf("wrong threshold:\n%s", query)
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
		t.Fatal("distinct count(field) is not yet supported -> must error")
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
		t.Fatal("a field without a DCS column -> must fail to compile")
	}
}

func TestLoadAggDirSeparatesRules(t *testing.T) {
	// the rules/sigma dir contains single-event rules + an agg/ sub-dir.
	agg, err := LoadAggDir("../../../rules/sigma")
	if err != nil {
		t.Fatalf("LoadAggDir: %v", err)
	}
	if len(agg) < 2 {
		t.Fatalf("expected >=2 aggregation rules, got %d", len(agg))
	}
	single, err := LoadDir("../../../rules/sigma")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	// single-event rules must not include aggregation rules.
	if len(single) == 0 {
		t.Fatal("expected at least one single-event rule")
	}
}
