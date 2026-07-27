package store

import (
	"context"
	"testing"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/tenancy"
)

// TestInsertEventStampsTenant proves Phase-1 write-path stamping: an event inherits the tenant of
// the agent that produced it, and an event from an unknown agent falls back to the Default tenant
// (never dropped). This is the hot path that makes tenant isolation possible.
func TestInsertEventStampsTenant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := ConnectSuperadmin(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	const agentName = "tenantstamp-agent"
	var tenantID string
	cleanup := func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM events WHERE event_dataset='tenantstamp'`)
		_, _ = st.pool.Exec(ctx, `DELETE FROM agents WHERE name=$1`, agentName)
		if tenantID != "" {
			_, _ = st.pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
		}
	}
	cleanup()
	defer cleanup()

	// A dedicated tenant, distinct from Default, and an agent that belongs to it.
	if err := st.pool.QueryRow(ctx,
		`INSERT INTO tenants (name, slug) VALUES ('Stamp Test', 'stamp-test-'||substr(gen_random_uuid()::text,1,8)) RETURNING id`).
		Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO agents (name, cert_serial, tenant_id) VALUES ($1, 'stamp-serial', $2)`,
		agentName, tenantID); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	insert := func(agentID string) string {
		e := &ingest.Event{Timestamp: time.Now()}
		e.Event.Category = "test"
		e.Event.Action = "x"
		e.Event.Dataset = "tenantstamp"
		if agentID != "" {
			e.Agent = &ingest.Agent{ID: agentID}
		}
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatalf("InsertEvent(%q): %v", agentID, err)
		}
		var got string
		if err := st.pool.QueryRow(ctx,
			`SELECT tenant_id::text FROM events WHERE agent_id IS NOT DISTINCT FROM $1 AND event_dataset='tenantstamp' ORDER BY time DESC LIMIT 1`,
			nilIfEmptyStr(agentID)).Scan(&got); err != nil {
			t.Fatalf("read back event tenant (%q): %v", agentID, err)
		}
		return got
	}

	// Known agent → its tenant.
	if got := insert(agentName); got != tenantID {
		t.Fatalf("event from a known agent must inherit its tenant: got %s want %s", got, tenantID)
	}
	// Unknown agent → Default tenant (fail-safe, not dropped).
	if got := insert("no-such-agent-xyz"); got != tenancy.DefaultTenantID {
		t.Fatalf("event from an unknown agent must fall back to Default: got %s want %s", got, tenancy.DefaultTenantID)
	}
}

func nilIfEmptyStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
