package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"deuswatch/internal/auth"
	"deuswatch/internal/store"
)

// Multi-tenancy admin API (Phase 4). Tenants are the data-isolation boundary (managed by the platform
// super-admin, manage_tenants); workspaces are teams mapped many-to-many to tenants and carry the user
// memberships (managed by manage_workspaces). Listing tenants and one's own workspaces only needs
// view_dashboard so the workspace switcher and the enrollment tenant picker work for every operator.

// tenantsListHandler (GET /api/tenants) lists all tenants — for the Tenants admin page, the workspace
// tenant-mapping UI, and the enrollment tenant picker.
func tenantsListHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenants, err := st.ListTenants(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
	}
}

// tenantCreateHandler (POST /api/tenants) creates a tenant (manage_tenants).
func tenantCreateHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		t, err := st.CreateTenant(r.Context(), req.Name)
		if err != nil {
			http.Error(w, err.Error(), statusForCreate(err))
			return
		}
		writeJSON(w, http.StatusCreated, t)
	}
}

// tenantDeleteHandler (DELETE /api/tenants/{id}) removes a tenant (manage_tenants). 409 if it still
// has agents, 400 for the protected Default tenant.
func tenantDeleteHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := st.DeleteTenant(r.Context(), r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), statusForDelete(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// myWorkspacesHandler (GET /api/workspaces) lists the workspaces the CURRENT user belongs to — this
// drives the workspace switcher (the X-Workspace-ID the client then sends narrows their tenant scope).
func myWorkspacesHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.UserFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ws, err := st.ListUserWorkspaces(r.Context(), u.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"workspaces": ws})
	}
}

// workspacesAdminListHandler (GET /api/admin/workspaces) lists ALL workspaces (manage_workspaces).
func workspacesAdminListHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ws, err := st.ListWorkspaces(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"workspaces": ws})
	}
}

// workspaceCreateHandler (POST /api/admin/workspaces) creates a workspace (manage_workspaces).
func workspaceCreateHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ws, err := st.CreateWorkspace(r.Context(), req.Name)
		if err != nil {
			http.Error(w, err.Error(), statusForCreate(err))
			return
		}
		writeJSON(w, http.StatusCreated, ws)
	}
}

// workspaceDeleteHandler (DELETE /api/admin/workspaces/{id}) removes a workspace (manage_workspaces).
// 400 for the protected Default workspace.
func workspaceDeleteHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := st.DeleteWorkspace(r.Context(), r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), statusForDelete(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// workspaceTenantsHandler (GET/PUT /api/admin/workspaces/{id}/tenants) reads or replaces the
// workspace→tenant mapping (manage_workspaces).
func workspaceTenantsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		switch r.Method {
		case http.MethodGet:
			ids, err := st.ListWorkspaceTenants(r.Context(), id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"tenant_ids": ids})
		case http.MethodPut:
			var req struct {
				TenantIDs []string `json:"tenant_ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if err := st.SetWorkspaceTenants(r.Context(), id, req.TenantIDs); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// workspaceMembersHandler (GET/PUT /api/admin/workspaces/{id}/members) reads or replaces the
// workspace membership (manage_workspaces).
func workspaceMembersHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		switch r.Method {
		case http.MethodGet:
			members, err := st.ListWorkspaceMembers(r.Context(), id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"members": members})
		case http.MethodPut:
			var req struct {
				UserIDs []string `json:"user_ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if err := st.SetWorkspaceMembers(r.Context(), id, req.UserIDs); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// statusForCreate maps a create error to 409 (duplicate) or 400 (validation) — anything else is 500.
func statusForCreate(err error) int {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "already exists"):
		return http.StatusConflict
	case strings.Contains(msg, "is required"):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// statusForDelete maps a delete error to 409 (still referenced), 400 (protected/invalid), 404 (not
// found) — anything else is 500.
func statusForDelete(err error) int {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "still has"):
		return http.StatusConflict
	case strings.Contains(msg, "cannot be deleted"):
		return http.StatusBadRequest
	case strings.Contains(msg, "not found"):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}
