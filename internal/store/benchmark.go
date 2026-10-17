package store

// Configuration-benchmark (CIS) assessment results.
//
// Deliberately separate from the agent_sca_findings code next door despite the shared "SCA"
// abbreviation: that one holds a package, a version and a CVE, this one holds a hardening control
// and whether the host satisfies it. They answer different questions for different people.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// BenchmarkResult is one evaluated control, as the agent reports it.
type BenchmarkResult struct {
	PolicyID    string   `json:"policy_id"`
	CheckID     int      `json:"check_id"`
	Title       string   `json:"title"`
	Result      string   `json:"result"`
	Reason      string   `json:"reason"`
	Remediation string   `json:"remediation"`
	CIS         []string `json:"cis"`
}

// BenchmarkSummary is one policy's headline for one agent.
type BenchmarkSummary struct {
	AgentName     string    `json:"agent_name"`
	PolicyID      string    `json:"policy_id"`
	PolicyName    string    `json:"policy_name"`
	Passed        int       `json:"passed"`
	Failed        int       `json:"failed"`
	NotApplicable int       `json:"not_applicable"`
	Score         int       `json:"score"`
	AssessedAt    time.Time `json:"assessed_at"`
}

// ReplaceBenchmarkResults stores one policy's assessment for one agent, replacing the previous
// one.
//
// Replace rather than append, scoped to that one policy. A benchmark answers "is this host
// hardened today"; keeping every past assessment in this table would mean every read had to find
// the latest one first, and the history that actually matters, a control that started failing, is
// in the events table, where each assessment also lands.
//
// Scoping the delete to the policy matters: an agent may carry several policies, and deleting all
// of an agent's rows would make the last policy assessed the only one visible.
func (s *Store) ReplaceBenchmarkResults(ctx context.Context, agentName, policyID, policyName string, results []BenchmarkResult) error {
	if agentName == "" || policyID == "" {
		return fmt.Errorf("store: benchmark results need an agent and a policy")
	}
	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`DELETE FROM agent_benchmarks WHERE agent_name=$1 AND policy_id=$2`, agentName, policyID); err != nil {
		return fmt.Errorf("store: clear benchmark results: %w", err)
	}

	// The agent's tenant, so a result is isolated the same way its events are. An agent with no
	// row falls back to the Default tenant rather than being dropped, the same precedence the
	// event write path uses.
	rows := make([][]any, 0, len(results))
	seen := map[int]bool{}
	for _, r := range results {
		if seen[r.CheckID] {
			continue // a policy with a duplicated check id must not break the copy
		}
		seen[r.CheckID] = true
		cis := r.CIS
		if cis == nil {
			cis = []string{}
		}
		rows = append(rows, []any{agentName, policyID, policyName, r.CheckID, r.Title,
			r.Result, r.Reason, r.Remediation, cis})
	}
	if len(rows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"agent_benchmarks"},
			[]string{"agent_name", "policy_id", "policy_name", "check_id", "title",
				"result", "reason", "remediation", "cis"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("store: copy benchmark results: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE agent_benchmarks b
			   SET tenant_id = a.tenant_id
			  FROM agents a
			 WHERE a.name = b.agent_name AND b.agent_name = $1 AND b.policy_id = $2`,
			agentName, policyID); err != nil {
			return fmt.Errorf("store: stamp benchmark tenant: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// BenchmarkSummaries returns one row per agent and policy, most recently assessed first.
func (s *Store) BenchmarkSummaries(ctx context.Context) ([]BenchmarkSummary, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT agent_name, policy_id, max(policy_name),
		       count(*) FILTER (WHERE result = 'passed'),
		       count(*) FILTER (WHERE result = 'failed'),
		       count(*) FILTER (WHERE result = 'not_applicable'),
		       max(assessed_at)
		  FROM agent_benchmarks
		 GROUP BY agent_name, policy_id
		 ORDER BY max(assessed_at) DESC, agent_name`)
	if err != nil {
		return nil, fmt.Errorf("store: benchmark summaries: %w", err)
	}
	defer rows.Close()
	out := []BenchmarkSummary{}
	for rows.Next() {
		var b BenchmarkSummary
		if err := rows.Scan(&b.AgentName, &b.PolicyID, &b.PolicyName,
			&b.Passed, &b.Failed, &b.NotApplicable, &b.AssessedAt); err != nil {
			return nil, err
		}
		// The score counts only the checks that could be evaluated. Including the skipped ones
		// would let a host improve its score by becoming less assessable, which is the one thing
		// a compliance number must never reward.
		if evaluable := b.Passed + b.Failed; evaluable > 0 {
			b.Score = b.Passed * 100 / evaluable
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// BenchmarkChecks returns the stored controls for one agent and policy. failedOnly narrows it to
// what needs work, which is what an operator opens this for.
func (s *Store) BenchmarkChecks(ctx context.Context, agentName, policyID string, failedOnly bool) ([]BenchmarkResult, error) {
	q := `SELECT policy_id, check_id, title, result, reason, remediation, cis
	        FROM agent_benchmarks
	       WHERE agent_name = $1 AND policy_id = $2`
	if failedOnly {
		q += ` AND result = 'failed'`
	}
	q += ` ORDER BY check_id`
	rows, err := s.q(ctx).Query(ctx, q, agentName, policyID)
	if err != nil {
		return nil, fmt.Errorf("store: benchmark checks: %w", err)
	}
	defer rows.Close()
	out := []BenchmarkResult{}
	for rows.Next() {
		var r BenchmarkResult
		if err := rows.Scan(&r.PolicyID, &r.CheckID, &r.Title, &r.Result, &r.Reason,
			&r.Remediation, &r.CIS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FailedBenchmarkCount is the estate-wide headline, for the dashboard and the ISO evidence
// report: how many controls are failing, across how many hosts.
func (s *Store) FailedBenchmarkCount(ctx context.Context) (controls int, hosts int, err error) {
	err = s.q(ctx).QueryRow(ctx, `
		SELECT count(*), count(DISTINCT agent_name)
		  FROM agent_benchmarks WHERE result = 'failed'`).Scan(&controls, &hosts)
	if err != nil {
		return 0, 0, fmt.Errorf("store: failed benchmark count: %w", err)
	}
	return controls, hosts, nil
}
