package main

// M3 performance scorecard (Kartu Kinerja) endpoints.
//
// Reading the card needs view_dashboard. The three writes each change what the card reports, so
// they gate higher and are written to the audit log: importing the controlled-test log and setting
// a manual figure are manage_settings, and flagging an alert as a false positive is ack_alert
// (the same permission that handles alerts).

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"deuswatch/internal/auth"
	"deuswatch/internal/store"
)

// scorecardHandler serves GET /api/scorecard?days=30.
func scorecardHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		days := 30
		if q := r.URL.Query().Get("days"); q != "" {
			if n, err := strconv.Atoi(q); err == nil {
				days = n
			}
		}
		card, err := st.Scorecard(r.Context(), days)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, card)
	}
}

// scorecardImportHandler serves POST /api/scorecard/import with body {"csv":"..."}: it loads the
// controlled-test log into scenario_runs and reports how many rows imported and which were rejected.
func scorecardImportHandler(st *store.Store, as *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CSV string `json:"csv"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body (expected {\"csv\":\"...\"})", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.CSV) == "" {
			http.Error(w, "csv is empty", http.StatusBadRequest)
			return
		}
		res, err := st.ImportScenarioRuns(r.Context(), req.CSV)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(r, as, "scorecard_import", "scenario_runs",
			strconv.Itoa(res.Imported)+" imported, "+strconv.Itoa(len(res.Rejected))+" rejected")
		writeJSON(w, http.StatusOK, res)
	}
}

// alertReviewHandler serves POST /api/alert-reviews with body {"event_id":"...","false_positive":true}.
func alertReviewHandler(st *store.Store, as *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			EventID        string `json:"event_id"`
			FalsePositive  bool   `json:"false_positive"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		by := actorName(r)
		if err := st.MarkAlertReview(r.Context(), req.EventID, req.FalsePositive, by); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		verdict := "true_positive"
		if req.FalsePositive {
			verdict = "false_positive"
		}
		audit(r, as, "alert_review", req.EventID, verdict)
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
	}
}

// scorecardInputHandler serves POST /api/scorecard/inputs with body {"key":"report_prep_time","value":1}.
func scorecardInputHandler(st *store.Store, as *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Key   string  `json:"key"`
			Value float64 `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Key) == "" {
			http.Error(w, "key is required", http.StatusBadRequest)
			return
		}
		if err := st.AddScorecardInput(r.Context(), req.Key, req.Value, actorName(r)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(r, as, "scorecard_input", req.Key, strconv.FormatFloat(req.Value, 'f', -1, 64))
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
	}
}

// actorName returns the signed-in username, or "unknown" when the context has no user.
func actorName(r *http.Request) string {
	if u, ok := auth.UserFrom(r.Context()); ok && u != nil {
		return u.Username
	}
	return "unknown"
}

// audit writes one scorecard-related action to the audit log, attributed to the signed-in user.
func audit(r *http.Request, as *auth.Store, action, target, detail string) {
	if as == nil {
		return
	}
	role := ""
	actor := "unknown"
	if u, ok := auth.UserFrom(r.Context()); ok && u != nil {
		actor, role = u.Username, string(u.Role)
	}
	as.Audit(r.Context(), actor, role, action, target, detail, auth.ClientIP(r))
}
