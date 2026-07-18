package clickhouse

import (
	"log"
	"time"

	"deuswatch/internal/ingest"
)

// Row is one flattened event, laid out as ClickHouse columns. JSON tags are the column names
// used by the JSONEachRow insert, so this struct and the CREATE TABLE DDL must stay in lockstep.
type Row struct {
	Timestamp     string `json:"timestamp"` // "2006-01-02 15:04:05.000" UTC
	EventCategory string `json:"event_category"`
	EventAction   string `json:"event_action"`
	EventOutcome  string `json:"event_outcome"`
	Severity      int8   `json:"severity"`
	Dataset       string `json:"dataset"`

	SourceIP      string `json:"source_ip"`
	SourcePort    uint16 `json:"source_port"`
	SourceCountry string `json:"source_country"`
	SourceCity    string `json:"source_city"`
	DestIP        string `json:"dest_ip"`
	DestPort      uint16 `json:"dest_port"`

	HostName string `json:"host_name"`
	AgentID  string `json:"agent_id"`
	UserName string `json:"user_name"`

	HTTPMethod string `json:"http_method"`
	HTTPURI    string `json:"http_uri"`
	HTTPStatus uint16 `json:"http_status"`
	HTTPHost   string `json:"http_host"`

	FilePath    string `json:"file_path"`
	FileHash    string `json:"file_hash"`
	ProcessName string `json:"process_name"`
	ProcessPID  int32  `json:"process_pid"`

	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`

	MitreTechniqueID   string `json:"mitre_technique_id"`
	MitreTechniqueName string `json:"mitre_technique_name"`
	MitreTactic        string `json:"mitre_tactic"`
	ThreatIndicatorIP  string `json:"threat_indicator_ip"`
	ThreatConfidence   int32  `json:"threat_confidence"`
	ThreatFeed         string `json:"threat_feed"`

	Label           string `json:"label"`
	AbuseConfidence *int   `json:"abuse_confidence"` // nil = never looked up (distinct from 0)
	OTXPulseCount   *int   `json:"otx_pulse_count"`
	LLMVerdict      string `json:"llm_verdict"`
	FileHashVerdict string `json:"file_hash_verdict"`

	RemediationAction string `json:"remediation_action"`
	RemediationStatus string `json:"remediation_status"`
}

// rowFromEvent flattens a DCS event into a ClickHouse row. Absent nested groups become zero
// values; the two CTI confidence fields stay nullable so "not looked up" is distinct from 0.
func rowFromEvent(ev *ingest.Event) Row {
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	r := Row{
		Timestamp:     ts.UTC().Format("2006-01-02 15:04:05.000"),
		EventCategory: ev.Event.Category,
		EventAction:   ev.Event.Action,
		EventOutcome:  ev.Event.Outcome,
		Severity:      int8(ev.Event.Severity),
		Dataset:       ev.Event.Dataset,
	}
	if ev.Source != nil {
		r.SourceIP, r.SourcePort = ev.Source.IP, ev.Source.Port
		if ev.Source.Geo != nil {
			r.SourceCountry, r.SourceCity = ev.Source.Geo.CountryISOCode, ev.Source.Geo.CityName
		}
	}
	if ev.Destination != nil {
		r.DestIP, r.DestPort = ev.Destination.IP, ev.Destination.Port
	}
	if ev.Host != nil {
		r.HostName = ev.Host.Name
	}
	if ev.Agent != nil {
		r.AgentID = ev.Agent.ID
	}
	if ev.User != nil {
		r.UserName = ev.User.Name
	}
	if ev.HTTP != nil {
		r.HTTPMethod, r.HTTPURI, r.HTTPHost = ev.HTTP.Method, ev.HTTP.URI, ev.HTTP.Host
		r.HTTPStatus = uint16(ev.HTTP.StatusCode)
	}
	if ev.File != nil {
		r.FilePath, r.FileHash = ev.File.Path, ev.File.HashSHA256
	}
	if ev.Process != nil {
		r.ProcessName, r.ProcessPID = ev.Process.Name, int32(ev.Process.PID)
	}
	if ev.Rule != nil {
		r.RuleID, r.RuleName = ev.Rule.ID, ev.Rule.Name
	}
	if ev.Threat != nil {
		r.MitreTechniqueID = ev.Threat.Technique.ID
		r.MitreTechniqueName = ev.Threat.Technique.Name
		r.MitreTactic = ev.Threat.TacticName
		r.ThreatFeed = ev.Threat.FeedName
		if ev.Threat.Indicator != nil {
			r.ThreatIndicatorIP = ev.Threat.Indicator.IP
			r.ThreatConfidence = int32(ev.Threat.Indicator.Confidence)
		}
	}
	r.Label = ev.DeusWatch.Label
	r.AbuseConfidence = ev.DeusWatch.Enrichment.AbuseConfidence
	r.OTXPulseCount = ev.DeusWatch.Enrichment.OTXPulseCount
	r.LLMVerdict = string(ev.DeusWatch.LLM.Verdict)
	r.FileHashVerdict = ev.DeusWatch.FileHash.Verdict
	r.RemediationAction = ev.DeusWatch.Remediation.Action
	r.RemediationStatus = string(ev.DeusWatch.Remediation.Status)
	return r
}

// logFlushErr rate-limits nothing but centralizes the flush-error log line.
func logFlushErr(err error) { log.Printf("clickhouse: flush: %v", err) }
