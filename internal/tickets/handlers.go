package tickets

import (
	"encoding/json"
	"net/http"
	"strconv"

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
		t, err := s.Update(r.Context(), r.PathValue("id"), currentUser(r), UpdateFields{
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

// SLAHandler: GET /api/tickets/sla?days= (requires view_tickets).
func (s *Store) SLAHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		days := 30
		if v := r.URL.Query().Get("days"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 365 {
				days = n
			}
		}
		stats, err := s.SLAScorecard(r.Context(), days)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

// AutomationGetHandler: GET /api/tickets/automation (requires manage_settings).
func (s *Store) AutomationGetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.LoadAutomationConfig(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}
}

// AutomationSetHandler: PUT /api/tickets/automation (requires manage_settings).
func (s *Store) AutomationSetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var c AutomationConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := s.SaveAutomationConfig(r.Context(), c); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Answer with the stored row: the save clamps the interval and severity, and echoing the
		// request would show the operator a setting that is not the one in force.
		saved, err := s.LoadAutomationConfig(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, saved)
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
