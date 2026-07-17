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

// PacksHandler: GET /api/rules/packs — the rule-pack marketplace (installed + catalog).
func (s *Store) PacksHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		packs, err := s.Packs(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, packs)
	}
}

// PackToggleHandler: POST /api/rules/packs/{id}/toggle {enabled} — enable/disable a whole
// installed pack (rule category) at once.
func (s *Store) PackToggleHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		n, err := s.SetEnabledByCategory(r.Context(), id, req.Enabled)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n == 0 {
			// No rules changed: either an external/catalog pack, or an unknown id.
			http.Error(w, "not an installed pack (external rulesets are imported manually — see the pack's link)", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"updated": n, "enabled": req.Enabled})
	}
}

// PackInstallHandler: POST /api/rules/packs/{id}/install — one-click import of a bundled
// curated pack (no network; the rules ship inside DeusWatch).
func (s *Store) PackInstallHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		n, err := s.InstallPack(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"installed": n, "pack": id})
	}
}

// PackUninstallHandler: POST /api/rules/packs/{id}/uninstall — remove a curated pack's rules.
func (s *Store) PackUninstallHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		n, err := s.UninstallPack(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"removed": n, "pack": id})
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
