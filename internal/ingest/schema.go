// Package ingest defines the DeusWatch Core Schema (DCS) and log normalization.
//
// DCS = an ECS-named subset (Elastic Common Schema) + the deuswatch.* namespace
// (design doc section 7). This file is the SINGLE SOURCE OF TRUTH for the schema.
//
// Discipline rule (section 7, required): new fields may ONLY be added by changing
// this file plus the matching SQL migration under migrations/. No stray fields may
// appear ad hoc elsewhere in the code. This keeps the schema from rotting.
//
// The mapping to TimescaleDB columns lives in migrations/000001_init_dcs.up.sql —
// column name = the dotted ECS name snake_cased (e.g. source.ip -> source_ip,
// deuswatch.enrichment.status -> dw_enrichment_status).
package ingest

import (
	"strings"
	"time"
)

// Severity follows the 5-level model from design doc section 9, stored numerically
// 0..4 so the dashboard can aggregate it easily. Values intentionally match Sigma levels.
type Severity int8

const (
	SeverityInfo     Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

// Valid reports whether s is within the 0..4 range.
func (s Severity) Valid() bool { return s >= SeverityInfo && s <= SeverityCritical }

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity maps a Sigma level / severity word to a Severity. Unknown/empty values
// return the given fallback so callers can pick a safe default.
func ParseSeverity(s string, fallback Severity) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "informational":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return fallback
	}
}

// EnrichmentStatus = per-log enrichment pipeline status (deuswatch.enrichment.status).
type EnrichmentStatus string

const (
	EnrichmentPending  EnrichmentStatus = "pending"
	EnrichmentEnriched EnrichmentStatus = "enriched"
	EnrichmentFailed   EnrichmentStatus = "failed"
	EnrichmentSkipped  EnrichmentStatus = "skipped"
)

// LLMVerdict = the LLM worker's verdict (deuswatch.llm.verdict).
type LLMVerdict string

const (
	VerdictBenign      LLMVerdict = "benign"
	VerdictSuspicious  LLMVerdict = "suspicious"
	VerdictMalicious   LLMVerdict = "malicious"
	VerdictNeedsReview LLMVerdict = "needs_review"
)

// RemediationSource = origin of a recommendation (deuswatch.remediation.source).
type RemediationSource string

const (
	RemediationPlaybook RemediationSource = "playbook"
	RemediationLLM      RemediationSource = "llm"
)

// RemediationStatus = recommendation lifecycle (deuswatch.remediation.status).
type RemediationStatus string

const (
	RemediationRecommended RemediationStatus = "recommended"
	RemediationApproved    RemediationStatus = "approved"
	RemediationExecuted    RemediationStatus = "executed"
	RemediationDismissed   RemediationStatus = "dismissed"
)

// ── ECS field groups ──────────────────────────────────────

// EventFields = the event.* group (the basis of all dashboard aggregations).
type EventFields struct {
	Category string   `json:"category,omitempty"`
	Action   string   `json:"action,omitempty"`
	Outcome  string   `json:"outcome,omitempty"`
	Severity Severity `json:"severity"`
	Dataset  string   `json:"dataset,omitempty"`
	Original string   `json:"original,omitempty"` // raw log line
}

// Geo = source.geo.* (in Phase 1 only the source is geo-enriched).
type Geo struct {
	CountryISOCode string `json:"country_iso_code,omitempty"`
	CityName       string `json:"city_name,omitempty"`
}

// Endpoint = source.* / destination.*.
type Endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
	Geo  *Geo   `json:"geo,omitempty"`
}

// Host = host.*.
type Host struct {
	Name   string `json:"name,omitempty"`
	OSType string `json:"os.type,omitempty"`
	IP     string `json:"ip,omitempty"`
}

// Agent = agent.*.
type Agent struct {
	ID      string `json:"id,omitempty"`
	Version string `json:"version,omitempty"`
}

// User = user.*.
type User struct {
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// Network = network.*.
type Network struct {
	Protocol  string `json:"protocol,omitempty"`
	Transport string `json:"transport,omitempty"`
}

// File = file.* (File Integrity Monitoring).
type File struct {
	Path       string `json:"path,omitempty"`
	HashSHA256 string `json:"hash.sha256,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Mode       string `json:"mode,omitempty"`
	Diff       string `json:"diff,omitempty"` // unified line diff on a modified text file (superior FIM)
}

// Process = process.* (endpoint context, Phase 2+).
type Process struct {
	Name        string `json:"name,omitempty"`
	PID         int    `json:"pid,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
}

// Rule = rule.* (identity of the detection rule that fired).
type Rule struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Technique / Tactic = threat.technique.* / threat.tactic.* (auto MITRE labeling).
type Technique struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Indicator = threat.indicator.* (CTI lookup result — Phase 2).
type Indicator struct {
	IP         string     `json:"ip,omitempty"`
	Confidence int        `json:"confidence,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
}

// Threat = threat.* (MITRE detection + CTI enrichment).
type Threat struct {
	Technique  Technique  `json:"technique,omitempty"`
	TacticName string     `json:"tactic.name,omitempty"`
	Indicator  *Indicator `json:"indicator,omitempty"`
	FeedName   string     `json:"feed.name,omitempty"`
}

// ── Custom deuswatch.* namespace ──────────────────────────

// Enrichment = deuswatch.enrichment.*.
type Enrichment struct {
	Status          EnrichmentStatus `json:"status,omitempty"`
	AbuseConfidence *int             `json:"abuse_confidence,omitempty"` // 0..100 (AbuseIPDB)
	OTXPulseCount   *int             `json:"otx_pulse_count,omitempty"`
}

// LLM = deuswatch.llm.*.
type LLM struct {
	Verdict    LLMVerdict `json:"verdict,omitempty"`
	Summary    string     `json:"summary,omitempty"` // also embedded into pgvector (Phase 3)
	AnalyzedAt *time.Time `json:"analyzed_at,omitempty"`
}

// SeverityMeta = deuswatch.severity.* (audit trail for dynamic escalation, section 9).
type SeverityMeta struct {
	Original    Severity `json:"original"`
	EscalatedBy string   `json:"escalated_by,omitempty"`
}

// Remediation = deuswatch.remediation.* (playbook/LLM recommendation, section 9).
type Remediation struct {
	Action string            `json:"action,omitempty"`
	Source RemediationSource `json:"source,omitempty"`
	Status RemediationStatus `json:"status,omitempty"`
}

// FileReputation = deuswatch.file_hash.* (FIM file-hash reputation result).
type FileReputation struct {
	Verdict string `json:"verdict,omitempty"` // known_good | known_bad | unknown
	Detail  string `json:"detail,omitempty"`  // e.g. "12/70 engines flagged"
}

// Containment = deuswatch.containment.* — an auto-response directive carried on an alert
// when the matched rule has a `mitigation_action: network_containment` block. The response
// engine reads it to decide whether to isolate the alert's host (see internal/respond).
type Containment struct {
	ActionType     string   `json:"action_type,omitempty"` // network_containment
	TimeoutSeconds int      `json:"timeout,omitempty"`     // auto-release after N seconds (0 = manual)
	Threshold      Severity `json:"criticality_threshold"` // min severity for AUTOMATIC containment
}

// DeusWatch = the entire deuswatch.* namespace.
type DeusWatch struct {
	Enrichment  Enrichment     `json:"enrichment,omitempty"`
	Label       string         `json:"label,omitempty"` // bruteforce, password_guessing, mailscam, ...
	LLM         LLM            `json:"llm,omitempty"`
	Severity    SeverityMeta   `json:"severity,omitempty"`
	Remediation Remediation    `json:"remediation,omitempty"`
	FileHash    FileReputation `json:"file_hash,omitempty"`
	Containment *Containment   `json:"containment,omitempty"`
}

// ── Main record ───────────────────────────────────────────

// Event is a single DCS log record — the internal form after gateway normalization
// and the unit of storage in the TimescaleDB `events` hypertable.
type Event struct {
	Timestamp   time.Time   `json:"@timestamp"`
	Event       EventFields `json:"event"`
	Source      *Endpoint   `json:"source,omitempty"`
	Destination *Endpoint   `json:"destination,omitempty"`
	Host        *Host       `json:"host,omitempty"`
	Agent       *Agent      `json:"agent,omitempty"`
	User        *User       `json:"user,omitempty"`
	Network     *Network    `json:"network,omitempty"`
	File        *File       `json:"file,omitempty"`
	Process     *Process    `json:"process,omitempty"`
	Rule        *Rule       `json:"rule,omitempty"`
	Threat      *Threat     `json:"threat,omitempty"`
	DeusWatch   DeusWatch   `json:"deuswatch,omitempty"`
}
