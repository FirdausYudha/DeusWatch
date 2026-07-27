package store

import (
	"context"
	"testing"
	"time"

	"deuswatch/internal/tenancy"
)

// TestAgentsAndTicketsIsolation proves Phase-5 enforcement: the sibling-store tables agents and
// tickets (migration 000054) now filter by tenant under a scoped, non-super-admin transaction, just
// like the store-owned tables. A scope sees only its tenant's rows; an unscoped path is fail-closed;
// super-admin spans all tenants.
func TestAgentsAndTicketsIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn()) // regular owner pool — scoped reads drop to deuswatch_app
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()
	if aerr := st.AssertRLSEnforced(ctx); aerr != nil {
		t.Skipf("isolation not enforced (apply migrations through 000054): %v", aerr)
	}

	const agentA, agentB = "p5-agent-a", "p5-agent-b"
	const titleA, titleB = "p5-ticket-a", "p5-ticket-b"
	var tenA, tenB string
	cleanup := func() {
		_ = st.WithTenantScope(ctx, nil, true, func(sctx context.Context) error {
			tx, _ := tenancy.TxFrom(sctx)
			_, _ = tx.Exec(sctx, `DELETE FROM tickets WHERE title = ANY($1)`, []string{titleA, titleB})
			_, _ = tx.Exec(sctx, `DELETE FROM agents WHERE name = ANY($1)`, []string{agentA, agentB})
			return nil
		})
		for _, tn := range []string{tenA, tenB} {
			if tn != "" {
				_, _ = st.pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tn)
			}
		}
	}
	cleanup()
	defer cleanup()

	mkTenant := func(name string) string {
		var id string
		if err := st.pool.QueryRow(ctx,
			`INSERT INTO tenants (name, slug) VALUES ($1, $1||'-'||substr(gen_random_uuid()::text,1,8)) RETURNING id`,
			name).Scan(&id); err != nil {
			t.Fatalf("create tenant %s: %v", name, err)
		}
		return id
	}
	tenA, tenB = mkTenant("P5A"), mkTenant("P5B")

	// Seed one agent + one ticket per tenant under a super-admin scope (so the forced tables accept
	// the writes and stamp the explicit tenant).
	if err := st.WithTenantScope(ctx, nil, true, func(sctx context.Context) error {
		tx, _ := tenancy.TxFrom(sctx)
		for _, r := range []struct{ agent, title, ten string }{{agentA, titleA, tenA}, {agentB, titleB, tenB}} {
			if _, err := tx.Exec(sctx,
				`INSERT INTO agents (name, cert_serial, tenant_id) VALUES ($1, $1||'-serial', $2::uuid)`, r.agent, r.ten); err != nil {
				return err
			}
			if _, err := tx.Exec(sctx,
				`INSERT INTO tickets (title, severity, created_by, tenant_id) VALUES ($1, 2, 'tester', $2::uuid)`, r.title, r.ten); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// visible counts our test agents + tickets visible under the given scope.
	visible := func(tenantIDs []string, superadmin bool) (agents, tickets int) {
		if err := st.WithTenantScope(ctx, tenantIDs, superadmin, func(sctx context.Context) error {
			tx, _ := tenancy.TxFrom(sctx)
			if err := tx.QueryRow(sctx, `SELECT count(*) FROM agents WHERE name = ANY($1)`, []string{agentA, agentB}).Scan(&agents); err != nil {
				return err
			}
			return tx.QueryRow(sctx, `SELECT count(*) FROM tickets WHERE title = ANY($1)`, []string{titleA, titleB}).Scan(&tickets)
		}); err != nil {
			t.Fatalf("scoped read: %v", err)
		}
		return
	}

	if a, tk := visible([]string{tenA}, false); a != 1 || tk != 1 {
		t.Fatalf("scope {A} must see 1 agent + 1 ticket, got agents=%d tickets=%d", a, tk)
	}
	if a, tk := visible(nil, false); a != 0 || tk != 0 {
		t.Fatalf("empty scope must be fail-closed, got agents=%d tickets=%d", a, tk)
	}
	if a, tk := visible(nil, true); a != 2 || tk != 2 {
		t.Fatalf("super-admin must see both tenants, got agents=%d tickets=%d", a, tk)
	}
}
