package store

import (
	"context"
	"testing"
	"time"
)

// TestTenancyAdminCRUD exercises the Phase-4 admin surface: create a tenant + workspace, map them,
// add a member, and confirm the member's workspace list + the mapping read back correctly.
func TestTenancyAdminCRUD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := ConnectSuperadmin(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	var userID string
	var ws Workspace
	var ten Tenant
	cleanup := func() {
		if ws.ID != "" {
			_, _ = st.pool.Exec(ctx, `DELETE FROM workspaces WHERE id=$1`, ws.ID)
		}
		if ten.ID != "" {
			_, _ = st.pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, ten.ID)
		}
		if userID != "" {
			_, _ = st.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
		}
	}
	cleanup()
	defer cleanup()

	if err := st.pool.QueryRow(ctx,
		`INSERT INTO users (username, password_hash) VALUES ('wsadmin-test', 'x') RETURNING id::text`).
		Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	uniq := time.Now().UnixNano()
	ten, err = st.CreateTenant(ctx, "Acme "+itoa(uniq))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if ten.ID == "" || ten.Slug == "" {
		t.Fatalf("tenant not fully populated: %+v", ten)
	}
	// Duplicate name → friendly conflict error.
	if _, err := st.CreateTenant(ctx, "Acme "+itoa(uniq)); err == nil {
		t.Fatalf("duplicate tenant should error")
	}

	ws, err = st.CreateWorkspace(ctx, "Team "+itoa(uniq))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}

	if err := st.SetWorkspaceTenants(ctx, ws.ID, []string{ten.ID}); err != nil {
		t.Fatalf("SetWorkspaceTenants: %v", err)
	}
	tids, err := st.ListWorkspaceTenants(ctx, ws.ID)
	if err != nil || len(tids) != 1 || tids[0] != ten.ID {
		t.Fatalf("workspace tenant mapping wrong: %v err=%v", tids, err)
	}

	if err := st.SetWorkspaceMembers(ctx, ws.ID, []string{userID}); err != nil {
		t.Fatalf("SetWorkspaceMembers: %v", err)
	}
	members, err := st.ListWorkspaceMembers(ctx, ws.ID)
	if err != nil || len(members) != 1 || members[0].UserID != userID {
		t.Fatalf("workspace members wrong: %v err=%v", members, err)
	}

	// The member now sees the workspace via the switcher list, and ResolveUserScope reaches the tenant.
	myws, err := st.ListUserWorkspaces(ctx, userID)
	if err != nil || len(myws) != 1 || myws[0].ID != ws.ID {
		t.Fatalf("ListUserWorkspaces wrong: %v err=%v", myws, err)
	}
	scope, err := st.ResolveUserScope(ctx, userID, "")
	if err != nil || len(scope) != 1 || scope[0] != ten.ID {
		t.Fatalf("ResolveUserScope should reach the mapped tenant: %v err=%v", scope, err)
	}
}
