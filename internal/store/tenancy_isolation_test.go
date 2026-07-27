package store

import (
	"context"
	"testing"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/tenancy"
)

// TestRLSTenantIsolation is the end-to-end proof of Phase-2c enforcement: with migration 000050
// applied, Postgres itself filters every row to the caller's tenant scope. It connects with the
// regular (non-super-admin) pool — the same role the API uses — so FORCE ROW LEVEL SECURITY applies.
// It uses suspicious_ips (a plain forced table) and asserts: a scope sees only its own tenant's rows;
// the union of two scopes sees both; an unscoped path (empty GUC) is fail-closed to zero rows; and a
// super-admin scope spans all tenants.
func TestRLSTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn()) // regular owner pool — subject to FORCE RLS, no bypass
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	// Nothing to prove if the enforcement migration isn't applied on this DB.
	if aerr := st.AssertRLSEnforced(ctx); aerr != nil {
		t.Skipf("RLS not enforced (apply migration 000050): %v", aerr)
	}

	const ipA, ipB = "203.0.113.10", "203.0.113.20" // TEST-NET-3, safe for tests
	var tenA, tenB string
	cleanup := func() {
		// suspicious_ips is RLS-forced, so its rows are only reachable under a super-admin scope.
		_ = st.WithTenantScope(ctx, nil, true, func(sctx context.Context) error {
			tx, _ := tenancy.TxFrom(sctx)
			_, _ = tx.Exec(sctx, `DELETE FROM suspicious_ips WHERE ip = ANY($1::inet[])`, []string{ipA, ipB})
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
	tenA = mkTenant("IsoA")
	tenB = mkTenant("IsoB")

	// Seed one suspicious IP per tenant. The table is forced, so writes run inside a super-admin
	// scope; the explicit tenant_id is what the isolation policy filters on.
	if err := st.WithTenantScope(ctx, nil, true, func(sctx context.Context) error {
		tx, _ := tenancy.TxFrom(sctx)
		for _, row := range []struct{ ip, ten string }{{ipA, tenA}, {ipB, tenB}} {
			if _, err := tx.Exec(sctx,
				`INSERT INTO suspicious_ips (ip, tenant_id) VALUES ($1::inet, $2)`, row.ip, row.ten); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed suspicious_ips: %v", err)
	}

	// visibleIPs returns the set of our test IPs visible under the given scope.
	visibleIPs := func(tenantIDs []string, superadmin bool) map[string]bool {
		out := map[string]bool{}
		if err := st.WithTenantScope(ctx, tenantIDs, superadmin, func(sctx context.Context) error {
			tx, _ := tenancy.TxFrom(sctx)
			rows, err := tx.Query(sctx,
				`SELECT host(ip) FROM suspicious_ips WHERE ip = ANY($1::inet[])`, []string{ipA, ipB})
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var ip string
				if err := rows.Scan(&ip); err != nil {
					return err
				}
				out[ip] = true
			}
			return rows.Err()
		}); err != nil {
			t.Fatalf("scoped read: %v", err)
		}
		return out
	}

	if v := visibleIPs([]string{tenA}, false); !(len(v) == 1 && v[ipA]) {
		t.Fatalf("scope {A} must see only %s, got %v", ipA, v)
	}
	if v := visibleIPs([]string{tenB}, false); !(len(v) == 1 && v[ipB]) {
		t.Fatalf("scope {B} must see only %s, got %v", ipB, v)
	}
	if v := visibleIPs([]string{tenA, tenB}, false); !(len(v) == 2 && v[ipA] && v[ipB]) {
		t.Fatalf("scope {A,B} must see both, got %v", v)
	}
	// A request path that forgot to open a scope must be fail-closed — never a silent leak.
	if v := visibleIPs(nil, false); len(v) != 0 {
		t.Fatalf("empty scope must be fail-closed (0 rows), got %v", v)
	}
	if v := visibleIPs(nil, true); !(v[ipA] && v[ipB]) {
		t.Fatalf("super-admin must see all tenants, got %v", v)
	}
}

// TestEventsViewIsolation proves the events crown-jewel path: the security-barrier view over the
// events_data hypertable (migration 000052) isolates events by tenant even though events itself cannot
// carry RLS (TimescaleDB compression conflict). Same guarantees as the RLS tables: a scope sees only
// its tenant's events, an unscoped path is fail-closed, and super-admin spans all tenants.
func TestEventsViewIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn()) // regular owner pool — scoped reads drop to deuswatch_app
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()
	if aerr := st.AssertRLSEnforced(ctx); aerr != nil {
		t.Skipf("isolation not enforced (apply migrations 000050-000052): %v", aerr)
	}

	const agentA, agentB, ds = "iso-ev-a", "iso-ev-b", "isoevents"
	var tenA, tenB string
	cleanup := func() {
		_ = st.WithTenantScope(ctx, nil, true, func(sctx context.Context) error {
			tx, _ := tenancy.TxFrom(sctx)
			_, _ = tx.Exec(sctx, `DELETE FROM events WHERE event_dataset=$1`, ds)
			return nil
		})
		_, _ = st.pool.Exec(ctx, `DELETE FROM agents WHERE name = ANY($1)`, []string{agentA, agentB})
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
	tenA = mkTenant("EvA")
	tenB = mkTenant("EvB")
	for _, a := range []struct{ name, ten string }{{agentA, tenA}, {agentB, tenB}} {
		if _, err := st.pool.Exec(ctx,
			`INSERT INTO agents (name, cert_serial, tenant_id) VALUES ($1, $1||'-serial', $2)`,
			a.name, a.ten); err != nil {
			t.Fatalf("create agent %s: %v", a.name, err)
		}
	}

	// Seed via the real write path under a super-admin scope; InsertEvent stamps tenant from the agent
	// and writes through the events view (WITH CHECK OPTION passes because super-admin).
	if err := st.WithTenantScope(ctx, nil, true, func(sctx context.Context) error {
		for _, name := range []string{agentA, agentB} {
			e := &ingest.Event{Timestamp: time.Now()}
			e.Event.Category = "test"
			e.Event.Action = "x"
			e.Event.Dataset = ds
			e.Agent = &ingest.Agent{ID: name}
			if err := st.InsertEvent(sctx, e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed events: %v", err)
	}

	visibleAgents := func(tenantIDs []string, superadmin bool) map[string]bool {
		out := map[string]bool{}
		if err := st.WithTenantScope(ctx, tenantIDs, superadmin, func(sctx context.Context) error {
			tx, _ := tenancy.TxFrom(sctx)
			rows, err := tx.Query(sctx, `SELECT DISTINCT agent_id FROM events WHERE event_dataset=$1`, ds)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var a string
				if err := rows.Scan(&a); err != nil {
					return err
				}
				out[a] = true
			}
			return rows.Err()
		}); err != nil {
			t.Fatalf("scoped read: %v", err)
		}
		return out
	}

	if v := visibleAgents([]string{tenA}, false); !(len(v) == 1 && v[agentA]) {
		t.Fatalf("events scope {A} must see only %s, got %v", agentA, v)
	}
	if v := visibleAgents([]string{tenB}, false); !(len(v) == 1 && v[agentB]) {
		t.Fatalf("events scope {B} must see only %s, got %v", agentB, v)
	}
	if v := visibleAgents(nil, false); len(v) != 0 {
		t.Fatalf("events empty scope must be fail-closed (0 rows), got %v", v)
	}
	if v := visibleAgents(nil, true); !(v[agentA] && v[agentB]) {
		t.Fatalf("events super-admin must see all tenants, got %v", v)
	}
}
