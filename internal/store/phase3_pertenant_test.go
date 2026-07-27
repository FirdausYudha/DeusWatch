package store

import (
	"context"
	"testing"
	"time"

	"deuswatch/internal/score"
)

// TestPerTenantScoringNoBlend is the Phase-3 crux: the SAME source IP active in two tenants must
// produce two INDEPENDENT ip_scores rows, and the cross-agent fan-out (count(DISTINCT agent_id)) must
// be counted WITHIN a tenant, never blended across tenants. Before Phase 3 the scorer grouped by
// source_ip alone, merging tenants and inflating one tenant's fan-out with another tenant's agents.
func TestPerTenantScoringNoBlend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := ConnectSuperadmin(ctx, dsn()) // the worker's role — spans all tenants
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	const ip, ds = "203.0.113.88", "iso-score"
	var tenA, tenB string
	cleanup := func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM events WHERE event_dataset=$1`, ds)
		_, _ = st.pool.Exec(ctx, `DELETE FROM ip_scores WHERE host(ip)=$1`, ip)
		for _, tn := range []string{tenA, tenB} {
			if tn != "" {
				_, _ = st.pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tn)
			}
		}
	}
	cleanup()
	defer cleanup()

	mk := func(name string) string {
		var id string
		if err := st.pool.QueryRow(ctx,
			`INSERT INTO tenants (name, slug) VALUES ($1, $1||'-'||substr(gen_random_uuid()::text,1,8)) RETURNING id`,
			name).Scan(&id); err != nil {
			t.Fatalf("tenant %s: %v", name, err)
		}
		return id
	}
	tenA, tenB = mk("ScoreA"), mk("ScoreB")

	seed := func(tenant, agent string) {
		if _, err := st.pool.Exec(ctx, `
			INSERT INTO events (time, event_category, event_severity, source_ip, agent_id, event_dataset, tenant_id)
			VALUES (now(), 'network', 1, $1::inet, $2, $3, $4::uuid)`, ip, agent, ds, tenant); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	// Tenant A: the IP hit TWO distinct agents (fan-out 2). Tenant B: ONE agent (fan-out 1).
	// If the scorer blended tenants, the surviving row(s) would show a fan-out of 3.
	seed(tenA, "a1")
	seed(tenA, "a2")
	seed(tenB, "b1")

	if _, err := st.RefreshIPScores(ctx, time.Hour, score.DefaultWeights()); err != nil {
		t.Fatalf("RefreshIPScores: %v", err)
	}

	agentsByTenant := map[string]int{}
	rows, err := st.pool.Query(ctx, `SELECT tenant_id::text, agents FROM ip_scores WHERE host(ip)=$1`, ip)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var tid string
		var agents int
		if err := rows.Scan(&tid, &agents); err != nil {
			t.Fatal(err)
		}
		agentsByTenant[tid] = agents
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if len(agentsByTenant) != 2 {
		t.Fatalf("expected 2 independent per-tenant score rows for %s, got %d: %v", ip, len(agentsByTenant), agentsByTenant)
	}
	if agentsByTenant[tenA] != 2 {
		t.Fatalf("tenant A fan-out must be 2 (its own agents only), got %d", agentsByTenant[tenA])
	}
	if agentsByTenant[tenB] != 1 {
		t.Fatalf("tenant B fan-out must be 1 (not blended with A's agents), got %d", agentsByTenant[tenB])
	}
}
