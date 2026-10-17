package enroll

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"deuswatch/internal/agent"
)

// validateSources rejects a source list the agent cannot act on. Shared by the agent and group
// config handlers so a group cannot be given a policy that would be refused per agent.
func validateSources(sources []agent.Source) error {
	for _, src := range sources {
		if src.Dataset == "" || src.Type == "" {
			return errors.New("each source must have a dataset & type")
		}
	}
	return nil
}

// GroupsHandler (admin): GET lists groups, POST creates one.
func (s *Store) GroupsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			groups, err := s.Groups(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, groups)
			return
		}
		var req struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			Sources     []agent.Source `json:"sources"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if err := validateSources(req.Sources); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id, err := s.CreateGroup(r.Context(), req.Name, req.Description, req.Sources)
		if errors.Is(err, ErrGroupNameTaken) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})
	}
}

// SetGroupConfigHandler (admin): replaces a group's sources, which reaches every member.
func (s *Store) SetGroupConfigHandler() http.HandlerFunc {
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
		if err := validateSources(req.Sources); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		members, err := s.SetGroupConfig(r.Context(), id, req.Sources)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The member count is the answer to "did that do anything", which for a bulk edit is the
		// only feedback an operator gets.
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated", "members": members})
	}
}

// DeleteGroupHandler (admin): removes a group; its members fall back to their own config or to
// the agent defaults.
func (s *Store) DeleteGroupHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		if err := s.DeleteGroup(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
	}
}

// SetAgentGroupHandler (admin): assigns one agent to a group, or to none.
func (s *Store) SetAgentGroupHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		var req struct {
			GroupID string `json:"group_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := s.SetAgentGroup(r.Context(), id, strings.TrimSpace(req.GroupID)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
	}
}

// ClearConfigHandler (admin): drops an agent's own config so its group's applies again.
func (s *Store) ClearConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		if err := s.ClearConfig(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "cleared"})
	}
}
