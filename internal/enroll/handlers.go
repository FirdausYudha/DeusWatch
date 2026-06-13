package enroll

import (
	"encoding/json"
	"errors"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// TokenHandler (admin): membuat token enrollment sekali-pakai.
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

// EnrollHandler (PUBLIK): menukar token jadi sertifikat client unik.
// Catatan: di produksi endpoint ini harus di belakang TLS.
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
			http.Error(w, "body tidak valid", http.StatusBadRequest)
			return
		}
		bundle, err := s.Enroll(r.Context(), req.Token, req.Name, req.OS)
		if errors.Is(err, ErrToken) {
			http.Error(w, "token tidak valid / kedaluwarsa / sudah dipakai", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, bundle)
	}
}

// AgentsHandler: daftar agent terdaftar.
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

// RevokeHandler (admin): mencabut agent berdasarkan id (path value).
func (s *Store) RevokeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id wajib", http.StatusBadRequest)
			return
		}
		if err := s.Revoke(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": id})
	}
}
