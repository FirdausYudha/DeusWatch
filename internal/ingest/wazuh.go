package ingest

import (
	"encoding/json"
	"strings"
	"time"
)

// wazuhAlert is the subset of a Wazuh manager alert we map to DCS. Wazuh has already
// decoded the log (source IP, rule, MITRE, severity, geo), so we map those rich fields
// straight across instead of re-parsing full_log.
type wazuhAlert struct {
	Timestamp string `json:"timestamp"`
	FullLog   string `json:"full_log"`
	Location  string `json:"location"`
	Data      struct {
		SrcIP   string `json:"srcip"`
		DstUser string `json:"dstuser"`
		SrcUser string `json:"srcuser"`
		SrcPort string `json:"srcport"`
	} `json:"data"`
	Agent struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
		ID   string `json:"id"`
	} `json:"agent"`
	Manager struct {
		Name string `json:"name"`
	} `json:"manager"`
	Predecoder struct {
		ProgramName string `json:"program_name"`
		Hostname    string `json:"hostname"`
	} `json:"predecoder"`
	Decoder struct {
		Name string `json:"name"`
	} `json:"decoder"`
	Rule struct {
		Level       int      `json:"level"`
		Description string   `json:"description"`
		Groups      []string `json:"groups"`
		ID          string   `json:"id"`
		MITRE       struct {
			ID     []string `json:"id"`
			Tactic []string `json:"tactic"`
		} `json:"mitre"`
	} `json:"rule"`
	GeoLocation struct {
		CountryName string `json:"country_name"`
	} `json:"GeoLocation"`
}

// esWrapped is the OpenSearch/Elasticsearch index-document envelope (from querying the
// Wazuh indexer). The manager's integrator sends the bare alert, but we unwrap _source
// too so pasting a document from Dev Tools also works.
type esWrapped struct {
	Source json.RawMessage `json:"_source"`
}

// LooksLikeWazuh reports whether a JSON object is a Wazuh alert (has a rule + a log).
func looksLikeWazuh(a *wazuhAlert) bool {
	return a.Rule.ID != "" || a.Rule.Description != "" || a.FullLog != ""
}

// NormalizeWazuh maps one Wazuh alert JSON object to a DCS Event. Returns (event, true)
// when the JSON is a recognizable Wazuh alert; (nil, false) otherwise. The event comes in
// pre-labeled (Wazuh already decided it is an alert), so it flows through the pipeline as
// an alert - shown in Alerts, gets a playbook, can drive response - like a Suricata alert.
func NormalizeWazuh(data []byte) (*Event, bool) {
	// Unwrap an ES _source envelope if present.
	if t := strings.TrimSpace(string(data)); strings.Contains(t, "\"_source\"") {
		var w esWrapped
		if json.Unmarshal(data, &w) == nil && len(w.Source) > 0 {
			data = w.Source
		}
	}
	var a wazuhAlert
	if err := json.Unmarshal(data, &a); err != nil || !looksLikeWazuh(&a) {
		return nil, false
	}

	ts, _ := time.Parse(time.RFC3339, a.Timestamp)
	if ts.IsZero() {
		ts = time.Now()
	}

	e := &Event{
		Timestamp: ts,
		Event: EventFields{
			Category: wazuhCategory(a.Rule.Groups),
			Action:   primaryGroup(a.Rule.Groups),
			Outcome:  wazuhOutcome(a.Rule.Groups),
			Severity: wazuhSeverity(a.Rule.Level),
			Dataset:  "wazuh",
			Original: a.FullLog,
		},
		DeusWatch: DeusWatch{
			Enrichment: Enrichment{Status: EnrichmentSkipped},
			Severity:   SeverityMeta{Original: wazuhSeverity(a.Rule.Level)},
		},
	}

	// The Wazuh rule identity + label (so the dashboard shows the description and a
	// playbook can match). Prefer the MITRE tactic as the label - it matches the
	// tactic-named labels our own rules and playbooks use (e.g. credential_access).
	e.Rule = &Rule{ID: "wazuh:" + a.Rule.ID, Name: a.Rule.Description}
	e.DeusWatch.Label = wazuhLabel(a)

	if len(a.Rule.MITRE.ID) > 0 || len(a.Rule.MITRE.Tactic) > 0 {
		th := &Threat{}
		if len(a.Rule.MITRE.ID) > 0 {
			th.Technique = Technique{ID: a.Rule.MITRE.ID[0]}
		}
		if len(a.Rule.MITRE.Tactic) > 0 {
			th.TacticName = a.Rule.MITRE.Tactic[0]
		}
		e.Threat = th
	}

	// Attacker IP (+ geo country from Wazuh's own GeoLocation).
	if a.Data.SrcIP != "" {
		src := &Endpoint{IP: a.Data.SrcIP}
		if a.GeoLocation.CountryName != "" {
			src.Geo = &Geo{CountryISOCode: a.GeoLocation.CountryName}
		}
		e.Source = src
	}
	// Targeted user.
	if u := firstNonEmpty([]string{a.Data.DstUser, a.Data.SrcUser}); u != "" && u != "-" {
		e.User = &User{Name: u}
	}
	// Monitored host = the Wazuh agent; tag the reporting agent so the dashboard's Agent
	// column shows it came from Wazuh (and which Wazuh agent).
	host := firstNonEmpty([]string{a.Agent.Name, a.Predecoder.Hostname})
	if host != "" {
		e.Host = &Host{Name: host}
	}
	if a.Agent.Name != "" {
		e.Agent = &Agent{ID: "wazuh-agent/" + a.Agent.Name}
	} else {
		e.Agent = &Agent{ID: "wazuh-agent"}
	}
	return e, true
}

// wazuhSeverity maps a Wazuh rule level (0-15) to a DCS severity (0-4).
func wazuhSeverity(level int) Severity {
	switch {
	case level >= 12:
		return SeverityCritical
	case level >= 8:
		return SeverityHigh
	case level >= 5:
		return SeverityMedium
	case level >= 3:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// wazuhLabel derives the deuswatch.label: the MITRE tactic (matching our tactic-named
// labels/playbooks) when present, else a mapping from a few common Wazuh groups, else "wazuh".
func wazuhLabel(a wazuhAlert) string {
	if len(a.Rule.MITRE.Tactic) > 0 && a.Rule.MITRE.Tactic[0] != "" {
		return strings.ToLower(strings.ReplaceAll(a.Rule.MITRE.Tactic[0], " ", "_"))
	}
	for _, g := range a.Rule.Groups {
		switch g {
		case "authentication_failed", "authentication_failures", "invalid_login":
			return "credential_access"
		case "web", "attack", "sql_injection", "web_scan":
			return "initial_access"
		case "rootcheck", "vulnerability-detector", "syscheck":
			return "persistence"
		}
	}
	return "wazuh"
}

// wazuhCategory maps Wazuh groups to a DCS event.category (best-effort, display only).
func wazuhCategory(groups []string) string {
	for _, g := range groups {
		switch {
		case strings.Contains(g, "authentication"), g == "pam", g == "sshd":
			return "authentication"
		case g == "web", g == "attack":
			return "web"
		case g == "firewall":
			return "network"
		case g == "syscheck":
			return "file"
		}
	}
	return ""
}

// wazuhOutcome infers success/failure from the group set (many Wazuh auth rules encode it).
func wazuhOutcome(groups []string) string {
	for _, g := range groups {
		switch {
		case strings.Contains(g, "failed"), strings.Contains(g, "failure"), strings.Contains(g, "invalid"):
			return "failure"
		case strings.Contains(g, "success"):
			return "success"
		}
	}
	return ""
}

// primaryGroup returns the most specific-looking group as the event.action, skipping
// broad transport groups so the action is meaningful (e.g. authentication_failed).
func primaryGroup(groups []string) string {
	skip := map[string]bool{"syslog": true, "pam": true, "sshd": true}
	for _, g := range groups {
		if !skip[g] {
			return g
		}
	}
	if len(groups) > 0 {
		return groups[0]
	}
	return "wazuh_alert"
}
