package tickets

import (
	"encoding/json"
	"net/http"

	"deuswatch/internal/auth"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func currentUser(r *http.Request) string {
	if u, ok := auth.UserFrom(r.Context()); ok {
		return u.Username
	}
	return "unknown"
}

// ListHandler: GET /api/tickets?status=&limit= (requires view_tickets).
func (s *Store) ListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := s.List(r.Context(), r.URL.Query().Get("status"), 200)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

// CreateHandler: POST /api/tickets (requires manage_tickets).
func (s *Store) CreateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Severity    int    `json:"severity"`
			Assignee    string `json:"assignee"`
			SourceIP    string `json:"source_ip"`
			RuleID      string `json:"rule_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		t, err := s.Create(r.Context(), currentUser(r), NewTicket{
			Title: req.Title, Description: req.Description, Severity: req.Severity,
			Assignee: req.Assignee, SourceIP: req.SourceIP, RuleID: req.RuleID,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, t)
	}
}

// GetHandler: GET /api/tickets/{id} → {ticket, comments} (requires view_tickets).
func (s *Store) GetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, comments, err := s.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ticket": t, "comments": comments})
	}
}

// UpdateHandler: PUT /api/tickets/{id} (requires manage_tickets).
func (s *Store) UpdateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Title       *string `json:"title"`
			Description *string `json:"description"`
			Severity    *int    `json:"severity"`
			Status      *string `json:"status"`
			Assignee    *string `json:"assignee"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		t, err := s.Update(r.Context(), r.PathValue("id"), UpdateFields{
			Title: req.Title, Description: req.Description, Severity: req.Severity,
			Status: req.Status, Assignee: req.Assignee,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, t)
	}
}

// CommentHandler: POST /api/tickets/{id}/comments (requires manage_tickets).
func (s *Store) CommentHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		c, err := s.AddComment(r.Context(), r.PathValue("id"), currentUser(r), req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, c)
	}
}
