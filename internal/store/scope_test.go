package store

import (
	"context"
	"sort"
	"testing"
	"time"
)

// TestResolveUserScope proves the access resolver (User → Workspace → Tenant): a user's tenant set
// is the union across their workspaces; narrowing by a workspace they belong to works; and a
// workspace the user is NOT a member of can never widen their scope, even if its ID is passed.
func TestResolveUserScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	var userID, otherUser, wsA, wsB, wsC, tenA, tenB, tenC string
	cleanup := func() {
		// FKs cascade from workspaces/tenants; delete users last.
		for _, ws := range []string{wsA, wsB, wsC} {
			if ws != "" {
				_, _ = st.pool.Exec(ctx, `DELETE FROM workspaces WHERE id=$1`, ws)
			}
		}
		for _, tn := range []string{tenA, tenB, tenC} {
			if tn != "" {
				_, _ = st.pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tn)
			}
		}
		for _, u := range []string{userID, otherUser} {
			if u != "" {
				_, _ = st.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u)
			}
		}
	}
	cleanup()
	defer cleanup()

	mk := func(sql string, args ...any) string {
		var id string
		if err := st.pool.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatalf("setup (%s): %v", sql, err)
		}
		return id
	}
	uniq := time.Now().UnixNano()
	userID = mk(`INSERT INTO users (username, password_hash) VALUES ('scopeuser', 'x') RETURNING id`)
	otherUser = mk(`INSERT INTO users (username, password_hash) VALUES ('scopeother', 'x') RETURNING id`)
	tenA = mk(`INSERT INTO tenants (name, slug) VALUES ('A', 'a-` + itoa(uniq) + `') RETURNING id`)
	tenB = mk(`INSERT INTO tenants (name, slug) VALUES ('B', 'b-` + itoa(uniq) + `') RETURNING id`)
	tenC = mk(`INSERT INTO tenants (name, slug) VALUES ('C', 'c-` + itoa(uniq) + `') RETURNING id`)
	wsA = mk(`INSERT INTO workspaces (name, slug) VALUES ('WA', 'wa-` + itoa(uniq) + `') RETURNING id`)
	wsB = mk(`INSERT INTO workspaces (name, slug) VALUES ('WB', 'wb-` + itoa(uniq) + `') RETURNING id`)
	wsC = mk(`INSERT INTO workspaces (name, slug) VALUES ('WC', 'wc-` + itoa(uniq) + `') RETURNING id`)

	// Workspace A → {tenA, tenB}; Workspace B → {tenB, tenC}; Workspace C → {tenC}.
	exec := func(sql string, args ...any) {
		if _, err := st.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup exec: %v", err)
		}
	}
	exec(`INSERT INTO workspace_tenants (workspace_id, tenant_id) VALUES ($1,$2),($1,$3)`, wsA, tenA, tenB)
	exec(`INSERT INTO workspace_tenants (workspace_id, tenant_id) VALUES ($1,$2),($1,$3)`, wsB, tenB, tenC)
	exec(`INSERT INTO workspace_tenants (workspace_id, tenant_id) VALUES ($1,$2)`, wsC, tenC)
	// The user is a member of A and B only (NOT C).
	exec(`INSERT INTO workspace_members (workspace_id, user_id) VALUES ($1,$3),($2,$3)`, wsA, wsB, userID)

	set := func(ids []string) map[string]bool {
		m := map[string]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}

	// Union across A and B → {tenA, tenB, tenC}.
	got, err := st.ResolveUserScope(ctx, userID, "")
	if err != nil {
		t.Fatalf("ResolveUserScope union: %v", err)
	}
	u := set(got)
	if len(u) != 3 || !u[tenA] || !u[tenB] || !u[tenC] {
		t.Fatalf("union scope wrong: %v", sortcopy(got))
	}

	// Narrow to workspace A (a member) → {tenA, tenB} only.
	got, _ = st.ResolveUserScope(ctx, userID, wsA)
	a := set(got)
	if len(a) != 2 || !a[tenA] || !a[tenB] || a[tenC] {
		t.Fatalf("narrowed-to-A scope wrong: %v", sortcopy(got))
	}

	// Ask to narrow to workspace C — the user is NOT a member → must yield NOTHING (a forged
	// workspace id can't widen or grant access).
	got, _ = st.ResolveUserScope(ctx, userID, wsC)
	if len(got) != 0 {
		t.Fatalf("a non-member workspace must grant no tenants, got %v", sortcopy(got))
	}

	// A user in no workspace sees no tenants (fail-closed once RLS is on).
	got, _ = st.ResolveUserScope(ctx, otherUser, "")
	if len(got) != 0 {
		t.Fatalf("a user with no workspace must have empty scope, got %v", sortcopy(got))
	}
}

func itoa(n int64) string {
	// small helper to keep slugs unique without importing strconv into the test's top matter
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%10]}, b...)
		n /= 10
	}
	return string(b)
}

func sortcopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}
