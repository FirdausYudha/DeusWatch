package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"deuswatch/internal/probe"
	"deuswatch/internal/secret"
	"deuswatch/internal/store"
)

// Service/API health check CRUD.
//
// Credentials are encrypted at THIS boundary rather than in the store, so the plaintext token a
// hospital integration needs exists only inside the request that carried it. The store, its
// backups and every later read see ciphertext, and the one place that unseals it is the prober.

// serviceCheckBody is the wire shape. It is not store.ServiceCheck: the client sends headers as a
// plain map and never receives them back, and the live state fields are read-only.
type serviceCheckBody struct {
	Name          string            `json:"name"`
	Group         string            `json:"service_group"`
	Kind          string            `json:"kind"`
	Target        string            `json:"target"`
	Method        string            `json:"method"`
	ExpectStatus  int               `json:"expect_status"`
	ExpectBody    string            `json:"expect_body"`
	Headers       map[string]string `json:"headers"`
	IntervalSecs  int               `json:"interval_secs"`
	TimeoutSecs   int               `json:"timeout_secs"`
	LatencyWarnMS int               `json:"latency_warn_ms"`
	FailThreshold int               `json:"fail_threshold"`
	Enabled       *bool             `json:"enabled"`
}

// toCheck validates the body and converts it, sealing any credentials.
func (b serviceCheckBody) toCheck(cipher *secret.Cipher) (store.ServiceCheck, error) {
	c := store.ServiceCheck{
		Name:          strings.TrimSpace(b.Name),
		Group:         strings.TrimSpace(b.Group),
		Kind:          strings.ToLower(strings.TrimSpace(b.Kind)),
		Target:        strings.TrimSpace(b.Target),
		Method:        strings.ToUpper(strings.TrimSpace(b.Method)),
		ExpectStatus:  b.ExpectStatus,
		ExpectBody:    b.ExpectBody,
		IntervalSecs:  b.IntervalSecs,
		TimeoutSecs:   b.TimeoutSecs,
		LatencyWarnMS: b.LatencyWarnMS,
		FailThreshold: b.FailThreshold,
		Enabled:       b.Enabled == nil || *b.Enabled, // a new check is on unless it says otherwise
	}
	if c.Name == "" {
		return c, errors.New("name is required")
	}
	if c.Kind == "" {
		c.Kind = probe.KindHTTP
	}
	if err := validateTarget(c.Kind, c.Target); err != nil {
		return c, err
	}

	if len(b.Headers) > 0 {
		if cipher == nil {
			// Refuse rather than store the token in the clear: the caller asked for credentials to
			// be kept, and silently keeping them readable is the worse of the two failures.
			return c, errors.New("cannot store credentials: the secrets cipher is unavailable (set SECRETS_KEY)")
		}
		raw, err := json.Marshal(b.Headers)
		if err != nil {
			return c, errors.New("headers could not be encoded")
		}
		enc, err := cipher.Encrypt(string(raw))
		if err != nil {
			return c, errors.New("headers could not be encrypted")
		}
		c.HeadersEnc = enc
	}
	return c, nil
}

// validateTarget rejects a target the prober could not use, while the operator is still looking at
// the form — a check saved broken only announces itself later as a fake outage.
func validateTarget(kind, target string) error {
	if target == "" {
		return errors.New("target is required")
	}
	switch kind {
	case probe.KindHTTP:
		u, err := url.Parse(target)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("target must be a full http:// or https:// URL")
		}
	case probe.KindTCP:
		if !strings.Contains(target, ":") {
			return errors.New("target must be host:port for a TCP check")
		}
	default:
		return errors.New(`kind must be "http" or "tcp"`)
	}
	return nil
}

func serviceChecksListHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := st.ListServiceChecks(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func serviceCheckCreateHandler(st *store.Store, cipher *secret.Cipher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b serviceCheckBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		c, err := b.toCheck(cipher)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := st.CreateServiceCheck(r.Context(), &c); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeServiceCheck(w, st, r, c.ID)
	}
}

func serviceCheckUpdateHandler(st *store.Store, cipher *secret.Cipher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b serviceCheckBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		c, err := b.toCheck(cipher)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.ID = r.PathValue("id")
		// An edit that does not resend the headers keeps the stored ones (the store treats an empty
		// HeadersEnc as "unchanged"), so changing an interval does not silently drop the token.
		if err := st.UpdateServiceCheck(r.Context(), &c); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeServiceCheck(w, st, r, c.ID)
	}
}

// writeServiceCheck answers with the check as STORED rather than as submitted. The two differ:
// the store clamps the intervals, and an edit that omitted the headers kept the stored ones, so
// echoing the request would tell the UI the credentials had just been dropped.
func writeServiceCheck(w http.ResponseWriter, st *store.Store, r *http.Request, id string) {
	c, ok, err := st.GetServiceCheck(r.Context(), id)
	if err != nil || !ok {
		http.Error(w, "saved, but could not be read back", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func serviceCheckDeleteHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := st.DeleteServiceCheck(r.Context(), r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

// serviceCheckClearHeadersHandler removes stored credentials. Without it the only way to un-set a
// token is to delete the check, because an empty headers map means "unchanged" on update.
func serviceCheckClearHeadersHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := st.ClearServiceCheckHeaders(r.Context(), r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
	}
}

func serviceCheckHistoryHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if v := r.URL.Query().Get("hours"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*30 {
				hours = n
			}
		}
		pts, err := st.ServiceCheckHistory(r.Context(), r.PathValue("id"),
			time.Now().Add(-time.Duration(hours)*time.Hour), 2000)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, pts)
	}
}
