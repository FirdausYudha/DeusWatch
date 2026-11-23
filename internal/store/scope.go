package store

import (
	"context"
	"fmt"
)

// ResolveUserScope returns the set of tenant IDs a user may access: the union of the tenants reached
// by every workspace they belong to (User → Workspace → Tenant). When workspaceID is non-empty the
// set is narrowed to that single workspace, but only if the user is actually a member of it (the
// membership join enforces that), so a forged X-Workspace-ID header cannot widen access.
//
// This reads the access-control tables (workspace_members / workspace_tenants), which are NOT
// tenant-scoped data and carry no RLS, so it runs on the raw pool and must be called BEFORE opening
// a tenant scope. Returns an empty slice when the user belongs to no workspace (fail-closed: they
// then see nothing once RLS is enforced).
func (s *Store) ResolveUserScope(ctx context.Context, userID, workspaceID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT wt.tenant_id::text
		FROM workspace_members wm
		JOIN workspace_tenants wt ON wt.workspace_id = wm.workspace_id
		WHERE wm.user_id = $1
		  AND ($2 = '' OR wm.workspace_id = $2::uuid)`, userID, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("store: resolve user scope: %w", err)
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

// ActiveWorkspaceID resolves which single workspace a request belongs to, for features scoped to one
// workspace (e.g. the shared dashboard layout). It honours the X-Workspace-ID header when the user is
// actually a member of that workspace (a forged header cannot pick a workspace they're not in),
// otherwise falls back to their first workspace by name. Returns "" when the user belongs to none.
func (s *Store) ActiveWorkspaceID(ctx context.Context, userID, headerWorkspaceID string) (string, error) {
	wss, err := s.ListUserWorkspaces(ctx, userID)
	if err != nil {
		return "", err
	}
	if len(wss) == 0 {
		return "", nil
	}
	if headerWorkspaceID != "" {
		for _, w := range wss {
			if w.ID == headerWorkspaceID {
				return headerWorkspaceID, nil
			}
		}
	}
	return wss[0].ID, nil
}
