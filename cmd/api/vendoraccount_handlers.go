package main

// Managing vendor accounts and their access windows (RV-01, S5). Reading the list needs
// view_dashboard; every write gates on manage_settings, because a window is an access control and
// widening it quietly would be the thing an attacker wants.

import (
	"encoding/json"
	"net/http"
	"strings"

	"deuswatch/internal/auth"
	"deuswatch/internal/store"
)

// vendorAccountsHandler serves GET (list) and POST (create or replace).
func vendorAccountsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			rows, err := st.ListVendorAccounts(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"accounts": rows})
		case http.MethodPost:
			if u, _ := auth.UserFrom(r.Context()); u == nil || !u.Can(auth.PermManageSettings) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			var req struct {
				Account  string `json:"account"`
				Days     []int  `json:"days"`
				Start    string `json:"start_time"`
				End      string `json:"end_time"`
				Timezone string `json:"timezone"`
				Note     string `json:"note"`
				Enabled  *bool  `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			req.Account = strings.TrimSpace(req.Account)
			if req.Account == "" {
				http.Error(w, "account is required", http.StatusBadRequest)
				return
			}
			// An empty day set would alert on every single login, which reads as a broken feature
			// rather than a policy. Reject it so the mistake is caught at the keyboard.
			if len(req.Days) == 0 {
				http.Error(w, "at least one allowed day is required (1=Mon..7=Sun)", http.StatusBadRequest)
				return
			}
			for _, d := range req.Days {
				if d < 1 || d > 7 {
					http.Error(w, "days must be 1=Mon..7=Sun", http.StatusBadRequest)
					return
				}
			}
			if req.Start == "" || req.End == "" {
				http.Error(w, "start_time and end_time are required (HH:MM)", http.StatusBadRequest)
				return
			}
			if req.Timezone == "" {
				http.Error(w, "timezone is required (e.g. Asia/Jakarta)", http.StatusBadRequest)
				return
			}
			enabled := true
			if req.Enabled != nil {
				enabled = *req.Enabled
			}
			if err := st.UpsertVendorAccount(r.Context(), req.Account, req.Days,
				req.Start, req.End, req.Timezone, req.Note, enabled); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": "saved", "account": req.Account})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// vendorAccountDeleteHandler serves DELETE /api/vendor-accounts/{id}.
func vendorAccountDeleteHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		if err := st.DeleteVendorAccount(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
	}
}
