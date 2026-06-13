// Package store adalah lapisan repository ke PostgreSQL + TimescaleDB.
// Semua tulis log melewati sini; query selalu parameterized (design doc bagian 4).
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/ingest"
)

// Store memegang pool koneksi Postgres.
type Store struct {
	pool *pgxpool.Pool
}

// Connect membuka pool ke dsn dan memverifikasi konektivitas.
func Connect(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: buat pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close menutup pool.
func (s *Store) Close() { s.pool.Close() }

// Pool mengembalikan pool koneksi (dipakai paket auth agar berbagi pool yang sama).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

const insertEventSQL = `
INSERT INTO events (
	time, event_category, event_action, event_outcome, event_severity,
	event_dataset, event_original,
	source_ip, source_port, host_name, host_os_type, agent_id, agent_version,
	user_name, rule_id, rule_name,
	threat_technique_id, threat_technique_name, threat_tactic_name,
	dw_label, dw_severity_original, dw_enrichment_status
) VALUES (
	$1, $2, $3, $4, $5,
	$6, $7,
	$8::inet, $9, $10, $11, $12, $13,
	$14, $15, $16,
	$17, $18, $19,
	$20, $21, $22
)`

// InsertEvent menulis satu event DCS ke hypertable events. Field yang belum diisi
// (enrichment/LLM) dibiarkan NULL/default — Fase 1 hanya mengisi inti + deteksi.
func (s *Store) InsertEvent(ctx context.Context, e *ingest.Event) error {
	var (
		srcIP, srcPort                  any = nil, nil
		hostName, hostOS                any = nil, nil
		agentID, agentVer               any = nil, nil
		userName                        any = nil
		ruleID, ruleName                any = nil, nil
		techID, techName, tacticName    any = nil, nil, nil
	)
	if e.Source != nil {
		srcIP = strOrNil(e.Source.IP)
		srcPort = portOrNil(e.Source.Port)
	}
	if e.Host != nil {
		hostName = strOrNil(e.Host.Name)
		hostOS = strOrNil(e.Host.OSType)
	}
	if e.Agent != nil {
		agentID = strOrNil(e.Agent.ID)
		agentVer = strOrNil(e.Agent.Version)
	}
	if e.User != nil {
		userName = strOrNil(e.User.Name)
	}
	if e.Rule != nil {
		ruleID = strOrNil(e.Rule.ID)
		ruleName = strOrNil(e.Rule.Name)
	}
	if e.Threat != nil {
		techID = strOrNil(e.Threat.Technique.ID)
		techName = strOrNil(e.Threat.Technique.Name)
		tacticName = strOrNil(e.Threat.TacticName)
	}

	_, err := s.pool.Exec(ctx, insertEventSQL,
		e.Timestamp, strOrNil(e.Event.Category), strOrNil(e.Event.Action),
		strOrNil(e.Event.Outcome), int16(e.Event.Severity),
		strOrNil(e.Event.Dataset), strOrNil(e.Event.Original),
		srcIP, srcPort, hostName, hostOS, agentID, agentVer,
		userName, ruleID, ruleName,
		techID, techName, tacticName,
		strOrNil(e.DeusWatch.Label), int16(e.DeusWatch.Severity.Original),
		strOrNil(string(e.DeusWatch.Enrichment.Status)),
	)
	if err != nil {
		return fmt.Errorf("store: insert event: %w", err)
	}
	return nil
}

// CountEvents mengembalikan jumlah baris di tabel events.
func (s *Store) CountEvents(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count events: %w", err)
	}
	return n, nil
}

// CountByLabel menghitung event dengan deuswatch.label tertentu (mis. "bruteforce").
func (s *Store) CountByLabel(ctx context.Context, label string) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE dw_label = $1`, label).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count by label: %w", err)
	}
	return n, nil
}

// CountBySourceIP menghitung event dari source IP tertentu.
func (s *Store) CountBySourceIP(ctx context.Context, ip string) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE source_ip = $1::inet`, ip).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count by source ip: %w", err)
	}
	return n, nil
}

// CountByLabelAndSourceIP menghitung event berlabel tertentu dari source IP tertentu.
func (s *Store) CountByLabelAndSourceIP(ctx context.Context, label, ip string) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM events WHERE dw_label = $1 AND source_ip = $2::inet`, label, ip).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count by label and source ip: %w", err)
	}
	return n, nil
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func portOrNil(p uint16) any {
	if p == 0 {
		return nil
	}
	return int32(p)
}
