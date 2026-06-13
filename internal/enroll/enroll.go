// Package enroll menangani registrasi agent: token enrollment sekali-pakai,
// penerbitan sertifikat client unik per-agent, daftar & pencabutan (design doc
// bagian 4 & 12).
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/agent"
	"deuswatch/internal/mtls"
)

// TTL default.
const (
	TokenTTL  = 1 * time.Hour
	ClientTTL = 825 * 24 * time.Hour
)

var ErrToken = errors.New("enroll: token tidak valid / kedaluwarsa / sudah dipakai")

// Store mengelola agent & token enrollment, menerbitkan cert via CA.
type Store struct {
	pool *pgxpool.Pool
	ca   *mtls.CA
}

func NewStore(pool *pgxpool.Pool, ca *mtls.CA) *Store {
	return &Store{pool: pool, ca: ca}
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// CreateToken membuat token enrollment sekali-pakai. Mengembalikan token MENTAH
// (hanya hash disimpan).
func (s *Store) CreateToken(ctx context.Context, createdBy string) (raw string, expires time.Time, err error) {
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	raw = hex.EncodeToString(b)
	expires = time.Now().Add(TokenTTL)
	_, err = s.pool.Exec(ctx,
		`INSERT INTO agent_enroll_tokens (token_hash, created_by, expires_at) VALUES ($1,$2,$3)`,
		hashToken(raw), createdBy, expires)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: simpan token: %w", err)
	}
	return raw, expires, nil
}

// Bundle adalah materi yang dikembalikan ke agent saat enroll.
type Bundle struct {
	AgentID    string `json:"agent_id"`
	Name       string `json:"name"`
	CACert     string `json:"ca_cert"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
}

// Enroll memvalidasi token (sekali-pakai), menerbitkan sertifikat client unik,
// dan mendaftarkan agent. Dijalankan dalam transaksi agar token & agent atomik.
func (s *Store) Enroll(ctx context.Context, rawToken, name, os string) (*Bundle, error) {
	if name == "" {
		return nil, fmt.Errorf("enroll: nama agent wajib")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Klaim token: hanya yang belum dipakai & belum kedaluwarsa.
	ct, err := tx.Exec(ctx,
		`UPDATE agent_enroll_tokens SET used_at = now()
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`, hashToken(rawToken))
	if err != nil {
		return nil, fmt.Errorf("enroll: klaim token: %w", err)
	}
	if ct.RowsAffected() != 1 {
		return nil, ErrToken
	}

	certPEM, keyPEM, serial, err := s.ca.IssueClient(name, ClientTTL)
	if err != nil {
		return nil, fmt.Errorf("enroll: terbitkan cert: %w", err)
	}

	var agentID string
	err = tx.QueryRow(ctx,
		`INSERT INTO agents (name, os, cert_serial) VALUES ($1,$2,$3) RETURNING id`,
		name, nilIfEmpty(os), serial).Scan(&agentID)
	if err != nil {
		return nil, fmt.Errorf("enroll: daftar agent (nama dipakai?): %w", err)
	}
	_, _ = tx.Exec(ctx, `UPDATE agent_enroll_tokens SET used_by_agent = $1 WHERE token_hash = $2`,
		agentID, hashToken(rawToken))

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Bundle{
		AgentID: agentID, Name: name,
		CACert: string(s.ca.CACertPEM()), ClientCert: string(certPEM), ClientKey: string(keyPEM),
	}, nil
}

// AgentInfo untuk daftar agent.
type AgentInfo struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	OS         string     `json:"os"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	Revoked    bool       `json:"revoked"`
}

func (s *Store) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, COALESCE(os,''), enrolled_at, last_seen_at, revoked FROM agents ORDER BY enrolled_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("enroll: list agents: %w", err)
	}
	defer rows.Close()
	out := make([]AgentInfo, 0, 16)
	for rows.Next() {
		var a AgentInfo
		if err := rows.Scan(&a.ID, &a.Name, &a.OS, &a.EnrolledAt, &a.LastSeenAt, &a.Revoked); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Revoke menandai agent dicabut (gateway akan menolak koneksinya).
func (s *Store) Revoke(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `UPDATE agents SET revoked = true WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("enroll: revoke: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("enroll: agent tidak ditemukan")
	}
	return nil
}

// IsRevoked melaporkan apakah agent dengan name (CN sertifikat) dicabut atau tak
// dikenal. Dipakai gateway untuk menolak koneksi.
func (s *Store) IsRevoked(ctx context.Context, name string) (bool, error) {
	var revoked bool
	err := s.pool.QueryRow(ctx, `SELECT revoked FROM agents WHERE name = $1`, name).Scan(&revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // agent tak terdaftar (mis. cert lama/bersama) — jangan blokir di sini
	}
	if err != nil {
		return false, err
	}
	return revoked, nil
}

// MarkSeen memperbarui last_seen_at agent (dipakai heartbeat / ingest).
func (s *Store) MarkSeen(ctx context.Context, name string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agents SET last_seen_at = now() WHERE name = $1`, name)
	return err
}

// SetConfig menetapkan desired sources untuk agent (config push) dan menaikkan
// versi. Mengembalikan versi baru.
func (s *Store) SetConfig(ctx context.Context, id string, sources []agent.Source) (int, error) {
	var raw *string
	err := s.pool.QueryRow(ctx, `SELECT config FROM agents WHERE id = $1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("enroll: agent tidak ditemukan")
	}
	if err != nil {
		return 0, fmt.Errorf("enroll: baca config: %w", err)
	}
	var cur agent.Config
	if raw != nil {
		_ = json.Unmarshal([]byte(*raw), &cur)
	}
	cfg := agent.Config{Version: cur.Version + 1, Sources: sources}
	b, err := json.Marshal(cfg)
	if err != nil {
		return 0, err
	}
	if _, err := s.pool.Exec(ctx, `UPDATE agents SET config = $1 WHERE id = $2`, b, id); err != nil {
		return 0, fmt.Errorf("enroll: simpan config: %w", err)
	}
	return cfg.Version, nil
}

// GetConfigByName mengembalikan JSON config untuk agent ber-CN name (nil bila
// belum ditetapkan atau agent dicabut).
func (s *Store) GetConfigByName(ctx context.Context, name string) ([]byte, error) {
	var raw *string
	err := s.pool.QueryRow(ctx, `SELECT config FROM agents WHERE name = $1 AND NOT revoked`, name).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) || raw == nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []byte(*raw), nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
