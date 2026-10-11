package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/tenancy"
)

// A new user must land in the Default workspace, because access flows user -> workspace -> tenant
// and ResolveUserScope fails closed. Without a membership the account logs in to an empty product:
// no agents, no events, no blocklist, and no error anywhere saying why.
//
// Admins never hit it, which is why it survived: manage_tenants takes the RLS bypass and does not
// consult membership at all. The accounts that broke were the analyst and viewer ones created for
// other people.
func TestCreateUserJoinsTheDefaultWorkspace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspaces WHERE id=$1::uuid)`,
		tenancy.DefaultWorkspaceID).Scan(&exists); err != nil || !exists {
		t.Skipf("Default workspace not present (migration 000049 not applied?): exists=%v err=%v", exists, err)
	}

	s := NewStore(pool)
	username := fmt.Sprintf("ws-test-%d", time.Now().UnixNano())
	defer pool.Exec(ctx, `DELETE FROM users WHERE username=$1`, username) // membership cascades

	if err := s.CreateUser(ctx, username, "secret123xyz", RoleAnalyst, nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var n int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM workspace_members m
		JOIN users u ON u.id = m.user_id
		WHERE u.username = $1 AND m.workspace_id = $2::uuid`,
		username, tenancy.DefaultWorkspaceID).Scan(&n); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if n != 1 {
		t.Errorf("new user has %d Default-workspace memberships, want 1. Without one they resolve "+
			"to an empty tenant set and see nothing at all.", n)
	}
}

// Creating a user must not half-succeed. The membership and the row go in together, so a failure
// cannot leave an account that exists but can never see anything.
func TestCreateUserIsAtomic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	s := NewStore(pool)
	username := fmt.Sprintf("dup-test-%d", time.Now().UnixNano())
	defer pool.Exec(ctx, `DELETE FROM users WHERE username=$1`, username)

	if err := s.CreateUser(ctx, username, "secret123xyz", RoleViewer, nil); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	// The same username again violates the unique index, so the whole transaction rolls back and
	// no stray membership is left behind.
	if err := s.CreateUser(ctx, username, "secret123xyz", RoleViewer, nil); err == nil {
		t.Fatal("a duplicate username must be refused")
	}

	var users, members int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username=$1`, username).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM workspace_members m JOIN users u ON u.id = m.user_id
		WHERE u.username = $1`, username).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if users != 1 || members != 1 {
		t.Errorf("after a failed duplicate: users=%d members=%d, want 1 and 1", users, members)
	}
}
