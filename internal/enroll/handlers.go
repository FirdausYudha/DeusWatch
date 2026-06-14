package enroll

import (
	"encoding/json"
	"errors"
	"net/http"

	"deuswatch/internal/agent"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// TokenHandler (admin): creates a single-use enrollment token.
func (s *Store) TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		raw, expires, err := s.CreateToken(r.Context(), "admin")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": raw, "expires_at": expires})
	}
}

// EnrollHandler (PUBLIC): exchanges a token for a unique client certificate.
// Note: in production this endpoint must sit behind TLS.
func (s *Store) EnrollHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Token string `json:"token"`
			Name  string `json:"name"`
			OS    string `json:"os"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		bundle, err := s.Enroll(r.Context(), req.Token, req.Name, req.OS)
		if errors.Is(err, ErrToken) {
			http.Error(w, "invalid / expired / already-used token", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, bundle)
	}
}

// AgentsHandler: lists registered agents.
func (s *Store) AgentsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agents, err := s.ListAgents(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, agents)
	}
}

// SetConfigHandler (admin): sets the desired sources for an agent (config push).
func (s *Store) SetConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		var req struct {
			Sources []agent.Source `json:"sources"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if len(req.Sources) == 0 {
			http.Error(w, "sources must not be empty", http.StatusBadRequest)
			return
		}
		for _, src := range req.Sources {
			if src.Dataset == "" || src.Type == "" {
				http.Error(w, "each source must have a dataset & type", http.StatusBadRequest)
				return
			}
		}
		version, err := s.SetConfig(r.Context(), id, req.Sources)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated", "version": version})
	}
}

// RevokeHandler (admin): revokes an agent by id (path value).
func (s *Store) RevokeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		if err := s.Revoke(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": id})
	}
}
