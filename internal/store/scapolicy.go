package store

// Centrally managed CIS benchmark policies: upload once, every agent fetches.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// SCAPolicyRow is one stored benchmark policy. YAML is omitted from listings, a CIS policy is
// tens of thousands of lines and the console only needs to know it is there.
type SCAPolicyRow struct {
	ID         string    `json:"id"`
	PolicyID   string    `json:"policy_id"`
	Name       string    `json:"name"`
	CheckCount int       `json:"check_count"`
	Enabled    bool      `json:"enabled"`
	Rev        int64     `json:"rev"`
	UploadedBy string    `json:"uploaded_by"`
	UpdatedAt  time.Time `json:"updated_at"`
	YAML       string    `json:"yaml,omitempty"`
}

// ErrSCAPolicyExists is returned when the tenant already holds that benchmark.
var ErrSCAPolicyExists = errors.New("store: a policy with that id already exists")

// ListSCAPolicies returns the tenant's policies without their YAML.
func (s *Store) ListSCAPolicies(ctx context.Context) ([]SCAPolicyRow, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT id::text, policy_id, name, check_count, enabled, rev, uploaded_by, updated_at
		  FROM sca_policies ORDER BY policy_id`)
	if err != nil {
		return nil, fmt.Errorf("store: list sca policies: %w", err)
	}
	defer rows.Close()
	out := []SCAPolicyRow{}
	for rows.Next() {
		var p SCAPolicyRow
		if err := rows.Scan(&p.ID, &p.PolicyID, &p.Name, &p.CheckCount, &p.Enabled,
			&p.Rev, &p.UploadedBy, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// EnabledSCAPoliciesForAgent returns the YAML of every enabled policy in the tenant that owns
// this agent, ready to serve to it.
//
// The tenant is resolved in SQL from the agent name rather than relying on RLS, because the
// gateway connects with the superadmin pool where RLS does not filter. An agent must only ever
// be served its own workspace's benchmarks: in a multi-tenant deployment the wrong answer here
// hands one customer's hardening posture to another customer's endpoint.
//
// An unknown agent gets nothing. It is not an error, a revoked or not-yet-enrolled CN is handled
// a layer up, but it must not fall back to the Default tenant and quietly serve somebody's
// policies to a machine with no record.
func (s *Store) EnabledSCAPoliciesForAgent(ctx context.Context, agentName string) ([]SCAPolicyRow, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT p.policy_id, p.name, p.rev, p.yaml
		  FROM sca_policies p
		  JOIN agents a ON a.tenant_id = p.tenant_id
		 WHERE p.enabled AND a.name = $1 AND NOT a.revoked
		 ORDER BY p.policy_id`, agentName)
	if err != nil {
		return nil, fmt.Errorf("store: enabled sca policies: %w", err)
	}
	defer rows.Close()
	out := []SCAPolicyRow{}
	for rows.Next() {
		var p SCAPolicyRow
		if err := rows.Scan(&p.PolicyID, &p.Name, &p.Rev, &p.YAML); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpsertSCAPolicy stores a policy, replacing an existing one with the same policy_id and bumping
// its rev so every agent re-fetches.
//
// replace=false refuses to overwrite, so an accidental second upload of a different benchmark
// under a name already in use is an error the operator sees rather than a silent swap of what
// the whole estate is being measured against.
func (s *Store) UpsertSCAPolicy(ctx context.Context, policyID, name, yaml string, checks int, uploadedBy string, replace bool) (int64, error) {
	if policyID == "" || yaml == "" {
		return 0, fmt.Errorf("store: a policy needs an id and a body")
	}
	if !replace {
		var rev int64
		err := s.q(ctx).QueryRow(ctx, `
			INSERT INTO sca_policies (policy_id, name, yaml, check_count, uploaded_by)
			VALUES ($1, $2, $3, $4, $5) RETURNING rev`,
			policyID, name, yaml, checks, uploadedBy).Scan(&rev)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return 0, ErrSCAPolicyExists
		}
		if err != nil {
			return 0, fmt.Errorf("store: insert sca policy: %w", err)
		}
		return rev, nil
	}
	var rev int64
	err := s.q(ctx).QueryRow(ctx, `
		INSERT INTO sca_policies (policy_id, name, yaml, check_count, uploaded_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, policy_id) DO UPDATE
		   SET name = EXCLUDED.name, yaml = EXCLUDED.yaml,
		       check_count = EXCLUDED.check_count, uploaded_by = EXCLUDED.uploaded_by,
		       rev = sca_policies.rev + 1, updated_at = now()
		RETURNING rev`,
		policyID, name, yaml, checks, uploadedBy).Scan(&rev)
	if err != nil {
		return 0, fmt.Errorf("store: upsert sca policy: %w", err)
	}
	return rev, nil
}

// SetSCAPolicyEnabled turns a policy on or off for the whole tenant, bumping rev so agents drop
// it from their next assessment rather than keeping a cached copy running.
func (s *Store) SetSCAPolicyEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := s.q(ctx).Exec(ctx, `
		UPDATE sca_policies SET enabled = $1, rev = rev + 1, updated_at = now() WHERE id = $2`,
		enabled, id)
	if err != nil {
		return fmt.Errorf("store: set sca policy enabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: policy not found")
	}
	return nil
}

// DeleteSCAPolicy removes a policy. Its stored results are removed with it: a score for a
// benchmark nobody is running any more is a number on a compliance page with nothing behind it.
func (s *Store) DeleteSCAPolicy(ctx context.Context, id string) error {
	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var policyID string
	if err := tx.QueryRow(ctx,
		`DELETE FROM sca_policies WHERE id = $1 RETURNING policy_id`, id).Scan(&policyID); err != nil {
		return fmt.Errorf("store: delete sca policy: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM agent_benchmarks WHERE policy_id = $1`, policyID); err != nil {
		return fmt.Errorf("store: delete benchmark results: %w", err)
	}
	return tx.Commit(ctx)
}
