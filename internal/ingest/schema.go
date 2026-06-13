// Package ingest mendefinisikan DeusWatch Core Schema (DCS) dan normalisasi log.
//
// DCS = subset ber-penamaan ECS (Elastic Common Schema) + namespace deuswatch.*
// (design doc bagian 7). File ini adalah SUMBER KEBENARAN TUNGGAL untuk schema.
//
// Aturan disiplin (bagian 7, wajib): field baru HANYA boleh ditambah lewat
// perubahan file ini + migrasi SQL yang sepadan di migrations/. Tidak boleh ada
// field liar yang muncul dadakan di kode lain. Ini mencegah schema membusuk.
//
// Pemetaan ke kolom TimescaleDB ada di migrations/000001_init_dcs.up.sql —
// nama kolom = nama dotted ECS yang di-snake_case-kan (mis. source.ip -> source_ip,
// deuswatch.enrichment.status -> dw_enrichment_status).
package ingest

import "time"

// Severity mengikuti model 5-level design doc bagian 9, disimpan numerik 0..4
// agar mudah diagregasi dashboard. Nilainya sengaja sama dengan level Sigma.
type Severity int8

const (
	SeverityInfo     Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

// Valid melaporkan apakah s berada dalam rentang 0..4.
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

// EnrichmentStatus = status pipeline enrichment per-log (deuswatch.enrichment.status).
type EnrichmentStatus string

const (
	EnrichmentPending  EnrichmentStatus = "pending"
	EnrichmentEnriched EnrichmentStatus = "enriched"
	EnrichmentFailed   EnrichmentStatus = "failed"
	EnrichmentSkipped  EnrichmentStatus = "skipped"
)

// LLMVerdict = vonis worker LLM (deuswatch.llm.verdict).
type LLMVerdict string

const (
	VerdictBenign      LLMVerdict = "benign"
	VerdictSuspicious  LLMVerdict = "suspicious"
	VerdictMalicious   LLMVerdict = "malicious"
	VerdictNeedsReview LLMVerdict = "needs_review"
)

// RemediationSource = asal rekomendasi (deuswatch.remediation.source).
type RemediationSource string

const (
	RemediationPlaybook RemediationSource = "playbook"
	RemediationLLM      RemediationSource = "llm"
)

// RemediationStatus = siklus hidup rekomendasi (deuswatch.remediation.status).
type RemediationStatus string

const (
	RemediationRecommended RemediationStatus = "recommended"
	RemediationApproved    RemediationStatus = "approved"
	RemediationExecuted    RemediationStatus = "executed"
	RemediationDismissed   RemediationStatus = "dismissed"
)

// ── Grup field ECS ────────────────────────────────────────

// EventFields = grup event.* (dasar semua agregasi dashboard).
type EventFields struct {
	Category string   `json:"category,omitempty"`
	Action   string   `json:"action,omitempty"`
	Outcome  string   `json:"outcome,omitempty"`
	Severity Severity `json:"severity"`
	Dataset  string   `json:"dataset,omitempty"`
	Original string   `json:"original,omitempty"` // baris log mentah
}

// Geo = source.geo.* (di Fase 1 hanya source yang di-enrich geografis).
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
}

// Process = process.* (konteks endpoint, Fase 2+).
type Process struct {
	Name        string `json:"name,omitempty"`
	PID         int    `json:"pid,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
}

// Rule = rule.* (identitas rule deteksi yang memicu).
type Rule struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Technique / Tactic = threat.technique.* / threat.tactic.* (auto-label MITRE).
type Technique struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Indicator = threat.indicator.* (hasil lookup CTI — Fase 2).
type Indicator struct {
	IP         string     `json:"ip,omitempty"`
	Confidence int        `json:"confidence,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
}

// Threat = threat.* (deteksi MITRE + enrichment CTI).
type Threat struct {
	Technique Technique  `json:"technique,omitempty"`
	TacticName string    `json:"tactic.name,omitempty"`
	Indicator *Indicator `json:"indicator,omitempty"`
	FeedName   string    `json:"feed.name,omitempty"`
}

// ── Namespace custom deuswatch.* ──────────────────────────

// Enrichment = deuswatch.enrichment.*.
type Enrichment struct {
	Status          EnrichmentStatus `json:"status,omitempty"`
	AbuseConfidence *int             `json:"abuse_confidence,omitempty"` // 0..100 (AbuseIPDB)
	OTXPulseCount   *int             `json:"otx_pulse_count,omitempty"`
}

// LLM = deuswatch.llm.*.
type LLM struct {
	Verdict    LLMVerdict `json:"verdict,omitempty"`
	Summary    string     `json:"summary,omitempty"` // juga di-embed ke pgvector (Fase 3)
	AnalyzedAt *time.Time `json:"analyzed_at,omitempty"`
}

// SeverityMeta = deuswatch.severity.* (jejak audit eskalasi dinamis, bagian 9).
type SeverityMeta struct {
	Original   Severity `json:"original"`
	EscalatedBy string  `json:"escalated_by,omitempty"`
}

// Remediation = deuswatch.remediation.* (rekomendasi playbook/LLM, bagian 9).
type Remediation struct {
	Action string            `json:"action,omitempty"`
	Source RemediationSource `json:"source,omitempty"`
	Status RemediationStatus `json:"status,omitempty"`
}

// DeusWatch = seluruh namespace deuswatch.*.
type DeusWatch struct {
	Enrichment  Enrichment   `json:"enrichment,omitempty"`
	Label       string       `json:"label,omitempty"` // bruteforce, password_guessing, mailscam, ...
	LLM         LLM          `json:"llm,omitempty"`
	Severity    SeverityMeta `json:"severity,omitempty"`
	Remediation Remediation  `json:"remediation,omitempty"`
}

// ── Rekaman utama ─────────────────────────────────────────

// Event adalah satu rekaman log DCS — bentuk internal setelah normalisasi gateway
// dan unit penyimpanan di hypertable TimescaleDB `events`.
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
