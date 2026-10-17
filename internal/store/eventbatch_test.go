package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

// TestEventColumnsMatchArgs is the guard that makes one shared column list safe: adding a column
// to eventColumns without adding its value to eventArgs (or the reverse) shifts every later
// parameter by one and writes each value into the wrong column, which Postgres accepts whenever
// the types happen to line up. This fails loudly instead.
func TestEventColumnsMatchArgs(t *testing.T) {
	if len(eventColumns) != eventColumnCnt {
		t.Fatalf("eventColumns has %d entries, eventColumnCnt is %d", len(eventColumns), eventColumnCnt)
	}
	n := len(eventArgs(&ingest.Event{}))
	if n != eventColumnCnt {
		t.Fatalf("eventArgs returned %d values, eventColumns has %d", n, eventColumnCnt)
	}
	if eventColumns[colTenantID-1] != "tenant_id" {
		t.Errorf("colTenantID points at %q, not tenant_id", eventColumns[colTenantID-1])
	}
	if eventColumns[colAgentID-1] != "agent_id" {
		t.Errorf("colAgentID points at %q, not agent_id", eventColumns[colAgentID-1])
	}
	for _, c := range []struct {
		pos  int
		name string
	}{{colSourceIP, "source_ip"}, {colThreatIP, "threat_indicator_ip"}, {colDestIP, "destination_ip"}} {
		if eventColumns[c.pos-1] != c.name {
			t.Errorf("inet cast at position %d targets %q, not %q", c.pos, eventColumns[c.pos-1], c.name)
		}
	}
}

// TestInsertEventsSQLOffsets pins the parameter numbering across rows. The tenant COALESCE
// references agent_id by position, so a renumbering bug would silently look up the wrong row's
// agent and stamp the wrong tenant: a cross-tenant leak, not a crash.
func TestInsertEventsSQLOffsets(t *testing.T) {
	for _, rows := range []int{1, 2, 7} {
		sql := insertEventsSQL(rows)
		want := rows * eventColumnCnt
		if got := strings.Count(sql, "$"); got != want+rows {
			// one extra "$" per row: tenant_id appears twice (override + agent_id lookup).
			t.Errorf("rows=%d: %d placeholders, want %d", rows, got, want+rows)
		}
		if n := strings.Count(sql, "::inet"); n != rows*3 {
			t.Errorf("rows=%d: %d inet casts, want %d", rows, n, rows*3)
		}
		for r := 0; r < rows; r++ {
			base := r * eventColumnCnt
			frag := fmt.Sprintf("(SELECT a.tenant_id FROM agents a WHERE a.name = $%d)", base+colAgentID)
			if !strings.Contains(sql, frag) {
				t.Errorf("rows=%d row %d: tenant lookup does not reference $%d", rows, r, base+colAgentID)
			}
		}
		if strings.Contains(sql, "$0") {
			t.Errorf("rows=%d: emitted $0, parameters are 1-based", rows)
		}
	}
}

func TestMaxEventsPerInsertFitsProtocol(t *testing.T) {
	if n := maxEventsPerInsert * eventColumnCnt; n > 65535 {
		t.Fatalf("a full batch binds %d parameters, Postgres allows 65535", n)
	}
}

// TestInsertEventsRoundTrip executes the batch path against a real database: the generated SQL is
// only correct if Postgres accepts it, and it writes through the security_barrier events view.
func TestInsertEventsRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := ConnectSuperadmin(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable, skipping: %v", err)
	}
	defer st.Close()

	const dataset = "batchinsert-test"
	cleanup := func() { _, _ = st.pool.Exec(ctx, `DELETE FROM events WHERE event_dataset=$1`, dataset) }
	cleanup()
	defer cleanup()

	// Deliberately spans two chunks so the chunking loop is exercised, not just the single
	// statement, and mixes populated and empty events so every NULL path is bound too.
	const total = maxEventsPerInsert + 3
	evs := make([]*ingest.Event, 0, total)
	for i := 0; i < total; i++ {
		e := &ingest.Event{Timestamp: time.Now().Add(-time.Duration(i) * time.Second)}
		e.Event.Dataset = dataset
		e.Event.Category = "authentication"
		e.Event.Severity = ingest.SeverityLow
		if i%2 == 0 {
			e.Source = &ingest.Endpoint{IP: fmt.Sprintf("198.51.100.%d", i%256), Port: uint16(1024 + i%1000)}
			e.Rule = &ingest.Rule{ID: fmt.Sprintf("r-%d", i), Name: "batched"}
		}
		evs = append(evs, e)
	}
	if err := st.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	var n int64
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE event_dataset=$1`, dataset).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != total {
		t.Fatalf("stored %d events, inserted %d", n, total)
	}
	// Columns past the first chunk's offsets must still land in the right place.
	var ip, ruleID string
	if err := st.pool.QueryRow(ctx,
		`SELECT host(source_ip), rule_id FROM events WHERE event_dataset=$1 AND rule_id=$2`,
		dataset, fmt.Sprintf("r-%d", maxEventsPerInsert)).Scan(&ip, &ruleID); err != nil {
		t.Fatalf("read back a row from the second chunk: %v", err)
	}
	if want := fmt.Sprintf("198.51.100.%d", maxEventsPerInsert%256); ip != want {
		t.Errorf("source_ip = %q, want %q (parameter offsets drifted)", ip, want)
	}

	if err := st.InsertEvents(ctx, nil); err != nil {
		t.Errorf("InsertEvents(nil): %v", err)
	}
}
