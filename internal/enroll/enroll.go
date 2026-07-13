// Package enroll handles agent registration: single-use enrollment tokens,
// issuing a unique per-agent client certificate, listing & revocation (design doc
// sections 4 & 12).
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

// Default TTLs.
const (
	TokenTTL  = 1 * time.Hour
	ClientTTL = 825 * 24 * time.Hour
)

var ErrToken = errors.New("enroll: invalid / expired / already-used token")

// Store manages agents & enrollment tokens, issuing certs via the CA.
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

// CreateToken creates a single-use enrollment token. Returns the RAW token
// (only the hash is stored).
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
		return "", time.Time{}, fmt.Errorf("enroll: store token: %w", err)
	}
	return raw, expires, nil
}

// Bundle is the material returned to the agent at enroll time.
type Bundle struct {
	AgentID    string `json:"agent_id"`
	Name       string `json:"name"`
	CACert     string `json:"ca_cert"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
}

// Enroll validates the token (single-use), issues a unique client certificate,
// and registers the agent. Runs in a transaction so token & agent are atomic.
func (s *Store) Enroll(ctx context.Context, rawToken, name, os string) (*Bundle, error) {
	if name == "" {
		return nil, fmt.Errorf("enroll: agent name is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Claim the token: only if unused & not expired.
	ct, err := tx.Exec(ctx,
		`UPDATE agent_enroll_tokens SET used_at = now()
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`, hashToken(rawToken))
	if err != nil {
		return nil, fmt.Errorf("enroll: claim token: %w", err)
	}
	if ct.RowsAffected() != 1 {
		return nil, ErrToken
	}

	certPEM, keyPEM, serial, err := s.ca.IssueClient(name, ClientTTL)
	if err != nil {
		return nil, fmt.Errorf("enroll: issue cert: %w", err)
	}

	// A REVOKED agent's name may be re-used: enrollment takes over the old row
	// (new certificate serial, un-revoked, health reset) so a re-deployed host can
	// keep its name. The row must survive revocation rather than be deleted - the
	// old mTLS cert stays cryptographically valid until it expires, and the gateway's
	// serial check against this row is what keeps it locked out. An ACTIVE agent's
	// name stays taken (the DO UPDATE is gated on agents.revoked -> no row -> error).
	var agentID string
	err = tx.QueryRow(ctx,
		`INSERT INTO agents (name, os, cert_serial) VALUES ($1,$2,$3)
		 ON CONFLICT (name) DO UPDATE SET
		     os = EXCLUDED.os, cert_serial = EXCLUDED.cert_serial, revoked = false,
		     enrolled_at = now(), last_seen_at = NULL,
		     status = 'unknown', health_degraded = false, health_detail = ''
		 WHERE agents.revoked
		 RETURNING id`,
		name, nilIfEmpty(os), serial).Scan(&agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("enroll: name %q is taken by an active agent (revoke it first to re-use the name)", name)
	}
	if err != nil {
		return nil, fmt.Errorf("enroll: register agent: %w", err)
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

// AgentInfo for the agent list.
type AgentInfo struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	OS            string         `json:"os"`
	EnrolledAt    time.Time      `json:"enrolled_at"`
	LastSeenAt    *time.Time     `json:"last_seen_at"`
	Revoked       bool           `json:"revoked"`
	Status        string         `json:"status"`                  // unknown|online|degraded|disconnected|stale (worker-maintained)
	HealthDetail  string         `json:"health_detail,omitempty"` // agent's self-reported problem, e.g. "217 batches buffered"
	ConfigVersion int            `json:"config_version"`
	Sources       []agent.Source `json:"sources,omitempty"`
}

func (s *Store) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, COALESCE(os,''), enrolled_at, last_seen_at, revoked, status, health_detail, config
		 FROM agents ORDER BY enrolled_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("enroll: list agents: %w", err)
	}
	defer rows.Close()
	out := make([]AgentInfo, 0, 16)
	for rows.Next() {
		var (
			a   AgentInfo
			raw *string
		)
		if err := rows.Scan(&a.ID, &a.Name, &a.OS, &a.EnrolledAt, &a.LastSeenAt, &a.Revoked, &a.Status, &a.HealthDetail, &raw); err != nil {
			return nil, err
		}
		if raw != nil {
			var cfg agent.Config
			if json.Unmarshal([]byte(*raw), &cfg) == nil {
				a.ConfigVersion = cfg.Version
				a.Sources = cfg.Sources
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Revoke marks an agent as revoked (the gateway will reject its connection).
func (s *Store) Revoke(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `UPDATE agents SET revoked = true WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("enroll: revoke: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("enroll: agent not found")
	}
	return nil
}

// IsRevoked reports whether a presented client certificate (CN + serial) must be
// rejected. Two ways to be dead: the agent row is revoked, or the certificate's
// serial no longer matches the registered one - re-enrolling a name issues a new
// certificate, and the superseded cert must stay locked out even though the row
// itself is active again. Used by the gateway to reject connections.
func (s *Store) IsRevoked(ctx context.Context, name, certSerial string) (bool, error) {
	var revoked bool
	var storedSerial *string
	err := s.pool.QueryRow(ctx, `SELECT revoked, cert_serial FROM agents WHERE name = $1`, name).
		Scan(&revoked, &storedSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // agent not registered (e.g. old/shared cert) — don't block here
	}
	if err != nil {
		return false, err
	}
	if revoked {
		return true, nil
	}
	// Serial pinning: only enforced when both sides are known (old rows without a
	// stored serial, or callers without one, keep the name-only behaviour).
	if storedSerial != nil && *storedSerial != "" && certSerial != "" && certSerial != *storedSerial {
		return true, nil
	}
	return false, nil
}

// MarkSeen updates the agent's last_seen_at (used by heartbeat / ingest).
func (s *Store) MarkSeen(ctx context.Context, name string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agents SET last_seen_at = now() WHERE name = $1`, name)
	return err
}

// MarkHealth updates last_seen_at plus the agent's self-reported health from the
// heartbeat body (degraded = e.g. the offline buffer is piling up). The worker's
// health checker folds this into the agent's status.
func (s *Store) MarkHealth(ctx context.Context, name string, degraded bool, detail string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE agents SET last_seen_at = now(), health_degraded = $2, health_detail = $3 WHERE name = $1`,
		name, degraded, detail)
	return err
}

// SetConfig sets the desired sources for an agent (config push) and bumps the
// version. Returns the new version.
func (s *Store) SetConfig(ctx context.Context, id string, sources []agent.Source) (int, error) {
	var raw *string
	err := s.pool.QueryRow(ctx, `SELECT config FROM agents WHERE id = $1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("enroll: agent not found")
	}
	if err != nil {
		return 0, fmt.Errorf("enroll: read config: %w", err)
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
		return 0, fmt.Errorf("enroll: store config: %w", err)
	}
	return cfg.Version, nil
}

// GetConfigByName returns the config JSON for the agent with CN name (nil if not
// yet set or the agent is revoked).
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
