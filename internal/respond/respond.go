// Package respond adalah response engine DeusWatch (Fase 2): mengubah alert menjadi
// rekomendasi blokir, menerapkannya lewat backend firewall (nftables/Mikrotik/
// CrowdSec) di balik antarmuka Responder, dengan approval workflow & ban progresif.
//
// Alur: alert (source IP) -> Engine.Recommend -> baris 'recommended' di
// response_actions. Analyst/admin approve -> Engine.Execute -> Responder.Block ->
// 'executed'. Durasi ban naik bertahap mengikuti riwayat IP (BanPolicy).
package respond

import (
	"context"
	"time"
)

// Status siklus hidup aksi (cermin deuswatch.remediation.status).
type Status string

const (
	StatusRecommended Status = "recommended"
	StatusApproved    Status = "approved"
	StatusExecuted    Status = "executed"
	StatusDismissed   Status = "dismissed"
	StatusFailed      Status = "failed"
)

// Action adalah satu rekomendasi/aksi respons.
type Action struct {
	ID           string     `json:"id"`
	CreatedAt    time.Time  `json:"created_at"`
	SourceIP     string     `json:"source_ip"`
	ActionType   string     `json:"action"` // "block"
	Reason       string     `json:"reason"`
	RuleID       string     `json:"rule_id"`
	BanSeconds   int        `json:"ban_seconds"` // 0 = permanen
	OffenseCount int        `json:"offense_count"`
	Source       string     `json:"source"` // playbook | llm
	Status       Status     `json:"status"`
	Responder    string     `json:"responder"`
	DecidedBy    string     `json:"decided_by"`
	DecidedAt    *time.Time `json:"decided_at"`
	ExecutedAt   *time.Time `json:"executed_at"`
	Error        string     `json:"error"`
}

// BanDuration mengembalikan durasi ban sebagai time.Duration (0 = permanen).
func (a Action) BanDuration() time.Duration { return time.Duration(a.BanSeconds) * time.Second }

// Responder menerapkan aksi blokir ke sebuah backend firewall/IPS.
// d == 0 berarti blokir permanen.
type Responder interface {
	Name() string
	Block(ctx context.Context, ip string, d time.Duration) error
	Unblock(ctx context.Context, ip string) error
}

// BanPolicy menentukan durasi ban progresif berdasarkan jumlah pelanggaran.
type BanPolicy struct {
	Durations []time.Duration // durasi untuk pelanggaran ke-1, ke-2, ...
	Permanent bool            // true: pelanggaran melebihi daftar -> permanen (0)
}

// DefaultBanPolicy: 10m, 1h, 24h, lalu permanen.
func DefaultBanPolicy() BanPolicy {
	return BanPolicy{
		Durations: []time.Duration{10 * time.Minute, time.Hour, 24 * time.Hour},
		Permanent: true,
	}
}

// Duration mengembalikan durasi ban untuk pelanggaran ke-offense (1-based).
// 0 berarti permanen.
func (p BanPolicy) Duration(offense int) time.Duration {
	if len(p.Durations) == 0 {
		return 0
	}
	if offense < 1 {
		offense = 1
	}
	if offense <= len(p.Durations) {
		return p.Durations[offense-1]
	}
	if p.Permanent {
		return 0 // permanen
	}
	return p.Durations[len(p.Durations)-1] // mentok di durasi terpanjang
}
