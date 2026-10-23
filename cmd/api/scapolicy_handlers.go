package main

// Central management of CIS benchmark policies: upload here, every agent fetches.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"deuswatch/internal/agent"
	"deuswatch/internal/auth"
	"deuswatch/internal/store"
)

// maxPolicyBytes caps an upload. A full CIS benchmark is a few hundred KB of YAML; this leaves
// generous room while keeping a 200MB paste from reaching the parser.
const maxPolicyBytes = 8 << 20

// validatePolicy parses an uploaded benchmark and reports what it is.
//
// Validation happens HERE, at upload, not on the endpoint. A malformed benchmark should be
// rejected by one person at one keyboard who can fix it, rather than fetched by five hundred
// agents that each log a parse error nobody reads. The agent still refuses to run what it cannot
// parse; this is so it never has to.
func validatePolicy(body []byte) (agent.SCAPolicy, error) {
	var p agent.SCAPolicy
	if err := yaml.Unmarshal(body, &p); err != nil {
		return p, fmt.Errorf("not valid YAML: %w", err)
	}
	if strings.TrimSpace(p.Policy.ID) == "" {
		return p, errors.New("the file has no policy.id; this does not look like an SCA policy")
	}
	if len(p.Checks) == 0 {
		return p, errors.New("the policy has no checks")
	}
	// Every check needs rules, or it would be stored as a control that can never be assessed and
	// would sit on the compliance page as a permanent skip with no explanation.
	for _, c := range p.Checks {
		if len(c.Rules) == 0 {
			return p, fmt.Errorf("check %d (%s) has no rules", c.ID, c.Title)
		}
	}
	return p, nil
}

// scaPoliciesHandler (GET /api/sca-policies, POST to upload).
func scaPoliciesHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			rows, err := st.ListSCAPolicies(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"policies": rows})
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPolicyBytes))
		if err != nil {
			http.Error(w, "could not read the upload", http.StatusBadRequest)
			return
		}
		// The operator's detached signature over the policy, if they supplied one. It arrives in
		// a header for a raw-YAML upload and in the envelope for a JSON one, and is stored
		// verbatim: the manager never verifies it and never could, because it does not hold the
		// key. Only the endpoint can, which is the entire point.
		signature := strings.TrimSpace(r.Header.Get("X-Deuswatch-Signature"))

		// Accept either the raw YAML or a JSON envelope carrying it, so the file can be posted
		// directly from a form and also from a script that already speaks JSON.
		yamlBody := body
		if strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
			var env struct {
				YAML      string `json:"yaml"`
				Signature string `json:"signature"`
				Replace   bool   `json:"replace"`
			}
			if err := json.Unmarshal(body, &env); err == nil && env.YAML != "" {
				yamlBody = []byte(env.YAML)
				signature = env.Signature
			}
		}

		p, verr := validatePolicy(yamlBody)
		if verr != nil {
			// The operator's own words back at them: a rejected upload has to say what is wrong
			// with the file, not just that it was rejected.
			http.Error(w, verr.Error(), http.StatusBadRequest)
			return
		}

		uploadedBy := ""
		if u, _ := auth.UserFrom(r.Context()); u != nil {
			uploadedBy = u.Username
		}
		replace := r.URL.Query().Get("replace") == "1"
		rev, err := st.UpsertSCAPolicy(r.Context(), p.Policy.ID, p.Policy.Name,
			string(yamlBody), len(p.Checks), uploadedBy, signature, replace)
		if errors.Is(err, store.ErrSCAPolicyExists) {
			// 409 rather than a silent overwrite. Replacing the benchmark the whole estate is
			// measured against is a decision, so it takes a second click.
			http.Error(w, "a policy with that id is already uploaded; confirm to replace it",
				http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"policy_id": p.Policy.ID,
			"name":      p.Policy.Name,
			"checks":    len(p.Checks),
			"rev":       rev,
			"signed":    signature != "",
		})
	}
}

// scaPolicyEnableHandler (PUT /api/sca-policies/{id}/enabled).
func scaPolicyEnableHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if err := st.SetSCAPolicyEnabled(r.Context(), id, req.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
	}
}

// scaPolicyDeleteHandler (DELETE /api/sca-policies/{id}).
func scaPolicyDeleteHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		if err := st.DeleteSCAPolicy(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
	}
}
