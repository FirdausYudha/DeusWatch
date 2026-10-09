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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/agent"
	"deuswatch/internal/mtls"
	"deuswatch/internal/tenancy"
)

// Default TTLs.
const (
	TokenTTL  = 1 * time.Hour
	ClientTTL = 825 * 24 * time.Hour
)

var ErrToken = errors.New("enroll: invalid / expired / already-used token")

// ErrUnknownAgent is returned by the heartbeat writers when the certificate CN they were
// handed matches no row in `agents`. Postgres reports a zero-row UPDATE as success, so
// before v2.14.6 this case returned nil: the gateway answered 204, the agent logged a
// clean heartbeat, and last_seen_at stayed NULL forever, the "never connected" badge with
// no error anywhere to explain it. Callers must treat it as a hard configuration fault,
// not a transient one; retrying cannot fix a CN that was never enrolled.
var ErrUnknownAgent = errors.New("enroll: no agent enrolled under that certificate CN")

// Store manages agents & enrollment tokens, issuing certs via the CA.
type Store struct {
	pool *pgxpool.Pool
	ca   *mtls.CA
}

func NewStore(pool *pgxpool.Pool, ca *mtls.CA) *Store {
	return &Store{pool: pool, ca: ca}
}

// queryer is the subset of DB operations enroll uses; both *pgxpool.Pool and pgx.Tx satisfy it.
type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Begin(context.Context) (pgx.Tx, error)
}

// q runs enroll's queries inside the request's scoped transaction when one is present (so RLS on the
// agents / agent_enroll_tokens tables filters to the caller's tenants), else on the raw pool. The
// gateway's enroll store connects with the super-admin pool (ConnectSuperadmin), so its agent auth /
// heartbeat / config paths bypass RLS; the public enrollment handler runs inside a super-admin scope.
func (s *Store) q(ctx context.Context) queryer {
	if tx, ok := tenancy.TxFrom(ctx); ok {
		return tx
	}
	return s.pool
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// CreateToken creates a single-use enrollment token scoped to a tenant: the agent that redeems it
// is registered into that tenant. An empty tenantID falls back to the Default tenant, so existing
// callers keep enrolling into Default. Returns the RAW token (only the hash is stored).
func (s *Store) CreateToken(ctx context.Context, createdBy, tenantID string) (raw string, expires time.Time, err error) {
	if tenantID == "" {
		tenantID = tenancy.DefaultTenantID
	}
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	raw = hex.EncodeToString(b)
	expires = time.Now().Add(TokenTTL)
	_, err = s.q(ctx).Exec(ctx,
		`INSERT INTO agent_enroll_tokens (token_hash, created_by, expires_at, tenant_id) VALUES ($1,$2,$3,$4)`,
		hashToken(raw), createdBy, expires, tenantID)
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
	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Claim the token (single-use) and read the tenant it enrolls into. No matching row (used,
	// expired, or unknown) → ErrToken.
	var tokenTenantID string
	err = tx.QueryRow(ctx,
		`UPDATE agent_enroll_tokens SET used_at = now()
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		 RETURNING COALESCE(tenant_id::text, $2)`, hashToken(rawToken), tenancy.DefaultTenantID).Scan(&tokenTenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrToken
	}
	if err != nil {
		return nil, fmt.Errorf("enroll: claim token: %w", err)
	}

	certPEM, keyPEM, serial, err := s.ca.IssueClient(name, ClientTTL)
	if err != nil {
		return nil, fmt.Errorf("enroll: issue cert: %w", err)
	}

	// Seed the agent with the sensible default sources for its OS, so a freshly-enrolled host is
	// already watching the right logs (SSH/syslog/firewall/web on Linux; the Event Log on Windows)
	// AND those sources are visible and editable in the UI from the start. Previously a new agent
	// had an empty config and only fell back to defaults IMPLICITLY inside the agent binary, the
	// manager showed no sources, so an admin who then configured e.g. a FIM watch would replace the
	// invisible defaults without realizing, and the host would silently stop watching its logs.
	// An unknown OS yields nil, which we store as NULL (no seeding) so the agent's own runtime
	// defaults still apply.
	seededConfig := nilIfEmpty("")
	if srcs := agent.DefaultSourcesFor(os); len(srcs) > 0 {
		if b, merr := json.Marshal(agent.Config{Version: 1, Sources: srcs}); merr == nil {
			seededConfig = string(b)
		}
	}

	// A REVOKED agent's name may be re-used: enrollment takes over the old row
	// (new certificate serial, un-revoked, health reset) so a re-deployed host can
	// keep its name. The row must survive revocation rather than be deleted - the
	// old mTLS cert stays cryptographically valid until it expires, and the gateway's
	// serial check against this row is what keeps it locked out. An ACTIVE agent's
	// name stays taken (the DO UPDATE is gated on agents.revoked -> no row -> error).
	// config is only seeded when the row has none, re-enrolling a host that an admin
	// already customized must never wipe that customization (COALESCE keeps the existing one).
	// The agent inherits the token's tenant. On a revoked-name re-enroll, the new token's tenant is
	// authoritative (a host may be re-homed to a different tenant); past events keep the tenant they
	// were stamped with.
	var agentID string
	err = tx.QueryRow(ctx,
		`INSERT INTO agents (name, os, cert_serial, config, tenant_id) VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (name) DO UPDATE SET
		     os = EXCLUDED.os, cert_serial = EXCLUDED.cert_serial, revoked = false,
		     enrolled_at = now(), last_seen_at = NULL, deleted_at = NULL,
		     status = 'unknown', health_degraded = false, health_detail = '',
		     config = COALESCE(agents.config, EXCLUDED.config),
		     tenant_id = EXCLUDED.tenant_id
		 WHERE agents.revoked
		 RETURNING id`,
		name, nilIfEmpty(os), serial, seededConfig, tokenTenantID).Scan(&agentID)
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
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	OS                string         `json:"os"`
	EnrolledAt        time.Time      `json:"enrolled_at"`
	LastSeenAt        *time.Time     `json:"last_seen_at"`
	Revoked           bool           `json:"revoked"`
	Status            string         `json:"status"`                  // unknown|online|degraded|disconnected|stale (worker-maintained)
	HealthDetail      string         `json:"health_detail,omitempty"` // agent's self-reported problem, e.g. "217 batches buffered"
	ConfigVersion     int            `json:"config_version"`
	Sources           []agent.Source `json:"sources,omitempty"`
	AgentVersion      string         `json:"agent_version,omitempty"`       // v2.12.0+: what the agent last reported
	UpdateRequestedAt *time.Time     `json:"update_requested_at,omitempty"` // v2.12.0+: operator asked for upgrade
}

func (s *Store) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	rows, err := s.q(ctx).Query(ctx,
		`SELECT id, name, COALESCE(os,''), enrolled_at, last_seen_at, revoked, status, health_detail, config,
		         COALESCE(agent_version,''), update_requested_at
		 FROM agents WHERE deleted_at IS NULL ORDER BY enrolled_at DESC`)
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
		if err := rows.Scan(&a.ID, &a.Name, &a.OS, &a.EnrolledAt, &a.LastSeenAt, &a.Revoked, &a.Status, &a.HealthDetail, &raw, &a.AgentVersion, &a.UpdateRequestedAt); err != nil {
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
	ct, err := s.q(ctx).Exec(ctx, `UPDATE agents SET revoked = true WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("enroll: revoke: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("enroll: agent not found")
	}
	return nil
}

// DeleteResult reports what DeleteAgent did, so the UI can tell the operator whether the agent is
// being uninstalled (valid agent) or was just removed from the list (already revoked).
type DeleteResult struct {
	Name          string `json:"name"`
	WasRevoked    bool   `json:"was_revoked"`    // agent was already revoked → hard-deleted immediately
	SelfUninstall bool   `json:"self_uninstall"` // valid agent → revoked+hidden, will uninstall on next contact
}

// DeleteAgent removes an agent from the operator's list. The behaviour depends on the agent's state,
// because self-uninstall relies on the gateway returning 410 (which needs the row to exist + be
// revoked); a bare row delete would return 409 and the agent would keep running:
//
//   - VALID (not revoked): revoke it and tombstone it (deleted_at). It disappears from the list and
//     Inventory immediately (its telemetry is purged now), the gateway keeps 410'ing it so it
//     self-uninstalls on next contact, and the reaper hard-deletes the tombstone once it is gone.
//   - ALREADY REVOKED: it has already been dealt with, so hard-delete the row + telemetry now
//     ("delete list only", per the operator's intent).
func (s *Store) DeleteAgent(ctx context.Context, id string) (DeleteResult, error) {
	var name string
	var revoked bool
	err := s.q(ctx).QueryRow(ctx, `SELECT name, revoked FROM agents WHERE id=$1`, id).Scan(&name, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeleteResult{}, fmt.Errorf("enroll: agent not found")
	}
	if err != nil {
		return DeleteResult{}, fmt.Errorf("enroll: delete lookup: %w", err)
	}

	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return DeleteResult{}, err
	}
	defer tx.Rollback(ctx)

	if err := purgeAgentTelemetry(ctx, tx, name); err != nil {
		return DeleteResult{}, err
	}

	res := DeleteResult{Name: name, WasRevoked: revoked}
	if revoked {
		// Already dealt with: drop the row (cascades process_snapshots/threats via FK).
		if _, err := tx.Exec(ctx, `DELETE FROM agents WHERE id=$1`, id); err != nil {
			return DeleteResult{}, fmt.Errorf("enroll: delete agent: %w", err)
		}
	} else {
		// Valid: keep a revoked tombstone so the gateway 410s it into self-uninstalling; hide it.
		if _, err := tx.Exec(ctx, `UPDATE agents SET revoked=true, deleted_at=now() WHERE id=$1`, id); err != nil {
			return DeleteResult{}, fmt.Errorf("enroll: tombstone agent: %w", err)
		}
		res.SelfUninstall = true
	}
	if err := tx.Commit(ctx); err != nil {
		return DeleteResult{}, err
	}
	return res, nil
}

// purgeAgentTelemetry removes an agent's per-host data keyed by agent name (no FK cascade), so a
// deleted agent leaves nothing behind in Inventory, FIM or the vuln views. Response/containment
// history is deliberately kept as an audit trail (it is IP/action-scoped, not host-scoped).
func purgeAgentTelemetry(ctx context.Context, tx pgx.Tx, name string) error {
	for _, q := range []string{
		`DELETE FROM agent_vulnerabilities WHERE agent_name=$1`,
		`DELETE FROM agent_sca_findings WHERE agent_name=$1`,
		`DELETE FROM agent_manifests WHERE agent_name=$1`,
		`DELETE FROM agent_packages WHERE agent_name=$1`,
		`DELETE FROM agent_os_inventory WHERE agent_name=$1`,
		`DELETE FROM fim_snapshots WHERE agent_name=$1`,
		`DELETE FROM agent_file_actions WHERE agent_name=$1`,
		`DELETE FROM file_restores WHERE agent_name=$1`,
	} {
		if _, err := tx.Exec(ctx, q, name); err != nil {
			return fmt.Errorf("enroll: purge agent telemetry: %w", err)
		}
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
	err := s.q(ctx).QueryRow(ctx, `SELECT revoked, cert_serial FROM agents WHERE name = $1`, name).
		Scan(&revoked, &storedSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // agent not registered (e.g. old/shared cert), don't block here
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

// MarkSeen updates the agent's last_seen_at (used by heartbeat / ingest). A name that
// matches no row yields ErrUnknownAgent rather than a silent success, see that sentinel.
func (s *Store) MarkSeen(ctx context.Context, name string) error {
	tag, err := s.q(ctx).Exec(ctx, `UPDATE agents SET last_seen_at = now() WHERE name = $1`, name)
	if err != nil {
		return err
	}
	return unknownIfNoRows(tag)
}

// unknownIfNoRows converts "the UPDATE matched nothing" into ErrUnknownAgent. Every
// heartbeat writer keys on agents.name, so zero rows can only mean the presented CN is not
// an enrolled agent, a fault worth reporting, never a no-op worth swallowing.
func unknownIfNoRows(tag pgconn.CommandTag) error {
	if tag.RowsAffected() == 0 {
		return ErrUnknownAgent
	}
	return nil
}

// MarkHealth updates last_seen_at plus the agent's self-reported health from the
// heartbeat body (degraded = e.g. The offline buffer is piling up). The worker's
// health checker folds this into the agent's status.
func (s *Store) MarkHealth(ctx context.Context, name string, degraded bool, detail string) error {
	tag, err := s.q(ctx).Exec(ctx,
		`UPDATE agents SET last_seen_at = now(), health_degraded = $2, health_detail = $3 WHERE name = $1`,
		name, degraded, detail)
	if err != nil {
		return err
	}
	return unknownIfNoRows(tag)
}

// MarkHealthWithVersion is v2.12.0's replacement: also persists the agent's self-reported
// build version so the UI can compare against the manager's. When the reported version
// matches managerVersion, any pending update_requested_at is cleared (the upgrade landed).
// managerVersion="" skips the auto-clear so a caller that doesn't know it can still record
// the version safely.
func (s *Store) MarkHealthWithVersion(ctx context.Context, name string, degraded bool, detail, version, managerVersion string) error {
	if version == "" {
		// No version reported → behave exactly like MarkHealth so agents on the wire
		// format that predates v2.12.0 don't have their agent_version wiped to "".
		return s.MarkHealth(ctx, name, degraded, detail)
	}
	if managerVersion != "" && version == managerVersion {
		tag, err := s.q(ctx).Exec(ctx,
			`UPDATE agents SET last_seen_at = now(), health_degraded = $2, health_detail = $3,
			                    agent_version = $4, update_requested_at = NULL
			 WHERE name = $1`,
			name, degraded, detail, version)
		if err != nil {
			return err
		}
		return unknownIfNoRows(tag)
	}
	tag, err := s.q(ctx).Exec(ctx,
		`UPDATE agents SET last_seen_at = now(), health_degraded = $2, health_detail = $3,
		                    agent_version = $4
		 WHERE name = $1`,
		name, degraded, detail, version)
	if err != nil {
		return err
	}
	return unknownIfNoRows(tag)
}

// RequestAgentUpdate flags an agent for a self-update on its next heartbeat. Idempotent:
// re-requesting just refreshes the timestamp (the "still pending" window).
func (s *Store) RequestAgentUpdate(ctx context.Context, name string) error {
	tag, err := s.q(ctx).Exec(ctx,
		`UPDATE agents SET update_requested_at = now() WHERE name = $1`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("enroll: no agent named %q", name)
	}
	return nil
}

// PendingAgentUpdate reports whether name has an unfulfilled update request within the
// staleness window (older requests are ignored, if the agent has been offline for 24h+
// and the operator forgot they clicked, we don't want to auto-fire on the next reappearance).
// Returns (false, nil) when no request or when the agent's version already matches managerVersion.
func (s *Store) PendingAgentUpdate(ctx context.Context, name, managerVersion string) (bool, error) {
	var (
		requestedAt *time.Time
		version     *string
	)
	err := s.q(ctx).QueryRow(ctx,
		`SELECT update_requested_at, agent_version FROM agents WHERE name = $1`, name).Scan(&requestedAt, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if requestedAt == nil {
		return false, nil
	}
	if time.Since(*requestedAt) > 24*time.Hour {
		return false, nil
	}
	if version != nil && managerVersion != "" && *version == managerVersion {
		return false, nil // upgrade already landed; no directive needed
	}
	return true, nil
}

// SetConfig sets the desired sources for an agent (config push) and bumps the
// version. Returns the new version.
func (s *Store) SetConfig(ctx context.Context, id string, sources []agent.Source) (int, error) {
	var raw *string
	err := s.q(ctx).QueryRow(ctx, `SELECT config FROM agents WHERE id = $1`, id).Scan(&raw)
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
	if _, err := s.q(ctx).Exec(ctx, `UPDATE agents SET config = $1 WHERE id = $2`, b, id); err != nil {
		return 0, fmt.Errorf("enroll: store config: %w", err)
	}
	return cfg.Version, nil
}

// GetConfigByName returns the config JSON for the agent with CN name (nil if not
// yet set or the agent is revoked).
func (s *Store) GetConfigByName(ctx context.Context, name string) ([]byte, error) {
	var raw *string
	err := s.q(ctx).QueryRow(ctx, `SELECT config FROM agents WHERE name = $1 AND NOT revoked`, name).Scan(&raw)
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
