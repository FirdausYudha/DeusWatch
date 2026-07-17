package packs_test

import (
	"testing"

	"deuswatch/internal/detect"
	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/ingest"
	"deuswatch/packs"
)

// Every bundled pack must parse — a pack rule that doesn't classify would break Install.
func TestCatalogRulesParse(t *testing.T) {
	if len(packs.Catalog) == 0 {
		t.Fatal("no bundled packs")
	}
	for _, p := range packs.Catalog {
		files, err := packs.Rules(p.ID)
		if err != nil {
			t.Fatalf("pack %q: %v", p.ID, err)
		}
		if len(files) == 0 {
			t.Fatalf("pack %q ships no rules", p.ID)
		}
		for name, data := range files {
			if _, err := sigma.Classify(data); err != nil {
				t.Errorf("pack %q: %s: does not classify: %v", p.ID, name, err)
			}
			if _, err := sigma.ParseRule(data); err != nil {
				t.Errorf("pack %q: %s: does not parse: %v", p.ID, name, err)
			}
		}
	}
}

// The whole point of curation: a pack rule must actually FIRE on the event DeusWatch produces.
// This guards the field taxonomy (http.uri / rule.id must be in sigma.FlattenEvent) — without
// it a pack would install cleanly and then never match, which is worse than not shipping it.
func TestWAFPackFiresOnModSecurityEvent(t *testing.T) {
	files, err := packs.Rules("waf-essentials")
	if err != nil {
		t.Fatal(err)
	}
	var rs sigma.Ruleset
	for name, data := range files {
		r, perr := sigma.ParseRule(data)
		if perr != nil {
			t.Fatalf("%s: %v", name, perr)
		}
		rs = append(rs, r)
	}
	d := detect.NewSigmaDetector(rs)

	// A CRS 942xxx (SQLi) block, as normalizeModSecurity produces it.
	sqli := &ingest.Event{
		Event:  ingest.EventFields{Category: "web", Action: "waf_block", Outcome: "blocked", Dataset: "modsecurity"},
		Source: &ingest.Endpoint{IP: "203.0.113.9"},
		Rule:   &ingest.Rule{ID: "942100", Name: "SQL Injection Attack Detected via libinjection"},
		HTTP:   &ingest.HTTP{URI: "/search?q=1' OR 1=1--", StatusCode: 403},
	}
	alert := d.Inspect(sqli)
	if alert == nil {
		t.Fatal("the SQLi pack rule must fire on a CRS 942xxx waf_block event")
	}
	if alert.Threat == nil || alert.Threat.Technique.ID != "T1190" {
		t.Fatalf("wrong MITRE on the SQLi alert: %+v", alert.Threat)
	}

	// A scanner probing a known exploit path (matched on http.uri).
	scan := &ingest.Event{
		Event:  ingest.EventFields{Category: "web", Action: "waf_block", Outcome: "blocked", Dataset: "modsecurity"},
		Source: &ingest.Endpoint{IP: "203.0.113.10"},
		Rule:   &ingest.Rule{ID: "920350", Name: "Host header is a numeric IP address"},
		HTTP:   &ingest.HTTP{URI: "/solr/admin/cores", StatusCode: 403},
	}
	if d.Inspect(scan) == nil {
		t.Fatal("the exploit-path rule must fire on a WAF block for /solr/admin/cores")
	}

	// A benign web request must NOT fire any pack rule.
	benign := &ingest.Event{
		Event:  ingest.EventFields{Category: "web", Action: "http_request", Dataset: "web"},
		Source: &ingest.Endpoint{IP: "198.51.100.5"},
		HTTP:   &ingest.HTTP{URI: "/index.html", StatusCode: 200},
	}
	if a := d.Inspect(benign); a != nil {
		t.Fatalf("a normal request must not fire a WAF pack rule: %+v", a.Rule)
	}
}
