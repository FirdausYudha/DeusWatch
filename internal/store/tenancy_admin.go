package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// isUniqueViolation reports whether err is a Postgres unique-constraint violation (SQLSTATE 23505),
// so a duplicate name/slug becomes a friendly 409 instead of a 500.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Tenant is a data-isolation boundary: agents and all their telemetry belong to exactly one tenant.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

// Workspace is a team: a user belongs to one+ workspaces, and each workspace is granted one+ tenants
// (the many-to-many). A user's effective tenant scope is the union across their workspaces.
type Workspace struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

// WorkspaceMember is one user's membership in a workspace (with the username for display).
type WorkspaceMember struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

var slugStrip = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify turns a display name into a URL-safe slug. Empty result falls back to "x" so the unique
// constraint (not an empty string) is what a caller collides on.
func Slugify(name string) string {
	s := slugStrip.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "x"
	}
	return s
}

// ListTenants returns every tenant (platform super-admin view). These are access-control rows, not
// tenant-scoped data, so they carry no RLS.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.q(ctx).Query(ctx, `SELECT id::text, name, slug, created_at FROM tenants ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list tenants: %w", err)
	}
	defer rows.Close()
	out := make([]Tenant, 0, 16)
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateTenant inserts a tenant, deriving a unique slug from the name. Returns a friendly error on a
// duplicate slug so the handler can map it to 409.
func (s *Store) CreateTenant(ctx context.Context, name string) (Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Tenant{}, fmt.Errorf("tenant name is required")
	}
	t := Tenant{Name: name, Slug: Slugify(name)}
	err := s.q(ctx).QueryRow(ctx,
		`INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id::text, created_at`,
		t.Name, t.Slug).Scan(&t.ID, &t.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Tenant{}, fmt.Errorf("a tenant named %q already exists", name)
		}
		return Tenant{}, fmt.Errorf("store: create tenant: %w", err)
	}
	return t, nil
}

// ListWorkspaces returns every workspace (workspace-admin view).
func (s *Store) ListWorkspaces(ctx context.Context) ([]Workspace, error) {
	return s.queryWorkspaces(ctx, `SELECT id::text, name, slug, created_at FROM workspaces ORDER BY name`)
}

// ListUserWorkspaces returns the workspaces a specific user belongs to (drives the workspace switcher).
func (s *Store) ListUserWorkspaces(ctx context.Context, userID string) ([]Workspace, error) {
	return s.queryWorkspaces(ctx, `
		SELECT w.id::text, w.name, w.slug, w.created_at
		FROM workspaces w
		JOIN workspace_members m ON m.workspace_id = w.id
		WHERE m.user_id = $1
		ORDER BY w.name`, userID)
}

func (s *Store) queryWorkspaces(ctx context.Context, sql string, args ...any) ([]Workspace, error) {
	rows, err := s.q(ctx).Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list workspaces: %w", err)
	}
	defer rows.Close()
	out := make([]Workspace, 0, 16)
	for rows.Next() {
		var w Workspace
		if err := rows.Scan(&w.ID, &w.Name, &w.Slug, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// CreateWorkspace inserts a workspace with a slug derived from its name.
func (s *Store) CreateWorkspace(ctx context.Context, name string) (Workspace, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Workspace{}, fmt.Errorf("workspace name is required")
	}
	w := Workspace{Name: name, Slug: Slugify(name)}
	err := s.q(ctx).QueryRow(ctx,
		`INSERT INTO workspaces (name, slug) VALUES ($1, $2) RETURNING id::text, created_at`,
		w.Name, w.Slug).Scan(&w.ID, &w.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Workspace{}, fmt.Errorf("a workspace named %q already exists", name)
		}
		return Workspace{}, fmt.Errorf("store: create workspace: %w", err)
	}
	return w, nil
}

// ListWorkspaceTenants returns the tenant IDs granted to a workspace (the M2M mapping).
func (s *Store) ListWorkspaceTenants(ctx context.Context, workspaceID string) ([]string, error) {
	rows, err := s.q(ctx).Query(ctx,
		`SELECT tenant_id::text FROM workspace_tenants WHERE workspace_id = $1::uuid`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("store: list workspace tenants: %w", err)
	}
	defer rows.Close()
	out := make([]string, 0, 8)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetWorkspaceTenants replaces the workspace→tenant mapping with exactly tenantIDs (transactional).
func (s *Store) SetWorkspaceTenants(ctx context.Context, workspaceID string, tenantIDs []string) error {
	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM workspace_tenants WHERE workspace_id = $1::uuid`, workspaceID); err != nil {
		return fmt.Errorf("store: clear workspace tenants: %w", err)
	}
	for _, tid := range tenantIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO workspace_tenants (workspace_id, tenant_id) VALUES ($1::uuid, $2::uuid)
			 ON CONFLICT DO NOTHING`, workspaceID, tid); err != nil {
			return fmt.Errorf("store: map workspace tenant: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ListWorkspaceMembers returns the members of a workspace with their usernames.
func (s *Store) ListWorkspaceMembers(ctx context.Context, workspaceID string) ([]WorkspaceMember, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT u.id::text, u.username
		FROM workspace_members m
		JOIN users u ON u.id = m.user_id
		WHERE m.workspace_id = $1::uuid
		ORDER BY u.username`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("store: list workspace members: %w", err)
	}
	defer rows.Close()
	out := make([]WorkspaceMember, 0, 16)
	for rows.Next() {
		var m WorkspaceMember
		if err := rows.Scan(&m.UserID, &m.Username); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetWorkspaceMembers replaces a workspace's membership with exactly userIDs (transactional).
func (s *Store) SetWorkspaceMembers(ctx context.Context, workspaceID string, userIDs []string) error {
	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM workspace_members WHERE workspace_id = $1::uuid`, workspaceID); err != nil {
		return fmt.Errorf("store: clear workspace members: %w", err)
	}
	for _, uid := range userIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO workspace_members (workspace_id, user_id) VALUES ($1::uuid, $2::uuid)
			 ON CONFLICT DO NOTHING`, workspaceID, uid); err != nil {
			return fmt.Errorf("store: add workspace member: %w", err)
		}
	}
	return tx.Commit(ctx)
}
