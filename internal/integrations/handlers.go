package integrations

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// TypesHandler returns the integration type catalog (drives the UI forms).
func (s *Store) TypesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, Catalog)
	}
}

// CollectionHandler handles GET (list) and POST (create) on /api/integrations.
// MUST be wrapped with Middleware + RequirePermission(PermManageIntegrations).
func (s *Store) CollectionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list, err := s.List(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, list)

		case http.MethodPost:
			var req struct {
				Type   string            `json:"type"`
				Name   string            `json:"name"`
				Config map[string]string `json:"config"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			it, err := s.Create(r.Context(), req.Type, req.Name, req.Config)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusCreated, it)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// ItemHandler handles PUT (update) and DELETE on /api/integrations/{id}.
func (s *Store) ItemHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req struct {
				Name    string            `json:"name"`
				Enabled bool              `json:"enabled"`
				Config  map[string]string `json:"config"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			it, err := s.Update(r.Context(), id, req.Name, req.Enabled, req.Config)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, it)

		case http.MethodDelete:
			if err := s.Delete(r.Context(), id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
