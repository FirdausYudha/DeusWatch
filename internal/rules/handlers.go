package rules

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// CollectionHandler: GET (list) / POST (create) on /api/rules.
// MUST be wrapped with Middleware + RequirePermission(PermManageRules).
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
				Name string `json:"name"`
				YAML string `json:"yaml"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			rule, err := s.Create(r.Context(), req.Name, req.YAML)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusCreated, rule)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// ItemHandler: PUT (update) / DELETE on /api/rules/{id}.
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
				Name    string `json:"name"`
				YAML    string `json:"yaml"`
				Enabled bool   `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			rule, err := s.Update(r.Context(), id, req.Name, req.YAML, req.Enabled)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, rule)

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
