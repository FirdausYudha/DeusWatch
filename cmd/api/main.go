// Command api is the DeusWatch API server.
//
// It serves health checks (liveness/readiness) and the Phase 1 data-read endpoints
// (events, alerts, stats) from PostgreSQL+TimescaleDB for the Web UI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"deuswatch/internal/auth"
	"deuswatch/internal/enroll"
	"deuswatch/internal/integrations"
	"deuswatch/internal/migrate"
	"deuswatch/internal/mtls"
	"deuswatch/internal/report"
	"deuswatch/internal/respond"
	"deuswatch/internal/secret"
	"deuswatch/internal/store"
	"deuswatch/internal/tickets"
	"deuswatch/migrations"
)

const version = "0.1.0-foundation"

func main() {
	addr := getenv("HTTP_ADDR", ":8080")

	// The store connection is optional: if the DB is not ready, /api/* endpoints reply
	// 503, but liveness stays up.
	var st *store.Store
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if s, err := store.Connect(ctx, dsn); err != nil {
			log.Printf("api: store unavailable (continuing without DB): %v", err)
		} else {
			st = s
			defer s.Close()
			log.Printf("api: store connected")
			// Automatic migration runner (idempotent) — unless RUN_MIGRATIONS=0.
			if run, _ := strconv.ParseBool(getenv("RUN_MIGRATIONS", "1")); run {
				if n, merr := migrate.Apply(ctx, s.Pool(), migrations.FS); merr != nil {
					log.Printf("api: migration failed: %v", merr)
				} else if n > 0 {
					log.Printf("api: %d migrations applied", n)
				} else {
					log.Printf("api: database schema up to date")
				}
			}
		}
		cancel()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/readyz", readyzHandler)

	if st != nil {
		authStore := auth.NewStore(st.Pool())
		seedAdmin(authStore)

		// Public (no token).
		mux.HandleFunc("/api/login", authStore.LoginHandler())

		// Self-registration (optional, enabled by default): new accounts = viewer role.
		registrationEnabled, _ := strconv.ParseBool(getenv("REGISTRATION_ENABLED", "1"))
		mux.HandleFunc("/api/auth/config", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]bool{"registration_enabled": registrationEnabled})
		})
		if registrationEnabled {
			mux.HandleFunc("/api/register", authStore.RegisterHandler())
			log.Printf("api: self-registration ENABLED (set REGISTRATION_ENABLED=0 to disable)")
		}

		// Protected: requires a valid session + permission.
		protect := func(p auth.Permission, h http.HandlerFunc) http.Handler {
			return authStore.Middleware(auth.RequirePermission(p, h))
		}
		mux.Handle("/api/me", authStore.Middleware(authStore.MeHandler()))
		mux.Handle("/api/logout", authStore.Middleware(authStore.LogoutHandler()))
		mux.Handle("/api/users", protect(auth.PermManageUsers, authStore.UsersHandler()))
		mux.Handle("PUT /api/users/{id}", protect(auth.PermManageUsers, authStore.UpdateUserHandler()))
		mux.Handle("/api/permissions", protect(auth.PermManageUsers, authStore.PermissionsHandler()))

		// 2FA self-service (own account; authenticated is enough).
		mux.Handle("/api/2fa/setup", authStore.Middleware(authStore.Setup2FAHandler()))
		mux.Handle("/api/2fa/enable", authStore.Middleware(authStore.Enable2FAHandler()))
		mux.Handle("/api/2fa/disable", authStore.Middleware(authStore.Disable2FAHandler()))

		// Agent enrollment (needs the CA to issue a per-agent unique certificate).
		if ca, err := mtls.LoadCA(getenv("CERT_DIR", "deploy/certs")); err != nil {
			log.Printf("api: CA not loaded — enrollment disabled: %v", err)
		} else {
			enrollStore := enroll.NewStore(st.Pool(), ca)
			mux.HandleFunc("/api/enroll", enrollStore.EnrollHandler()) // PUBLIC (uses a token)
			mux.Handle("/api/agents/tokens", protect(auth.PermManageAgents, enrollStore.TokenHandler()))
			mux.Handle("/api/agents", protect(auth.PermViewDashboard, enrollStore.AgentsHandler()))
			mux.Handle("POST /api/agents/{id}/revoke", protect(auth.PermManageAgents, enrollStore.RevokeHandler()))
			mux.Handle("PUT /api/agents/{id}/config", protect(auth.PermManageAgents, enrollStore.SetConfigHandler()))
		}
		mux.Handle("/api/events", protect(auth.PermViewDashboard, eventsHandler(st)))
		mux.Handle("/api/alerts", protect(auth.PermViewDashboard, alertsHandler(st)))
		mux.Handle("/api/stats", protect(auth.PermViewDashboard, statsHandler(st)))
		mux.Handle("/api/report", protect(auth.PermViewDashboard, reportHandler(st)))

		// Customizable dashboard: aggregated series + per-user widget layout.
		mux.Handle("GET /api/dashboard", protect(auth.PermViewDashboard, dashboardDataHandler(st)))
		mux.Handle("GET /api/dashboard/layout", protect(auth.PermViewDashboard, getLayoutHandler(st)))
		mux.Handle("PUT /api/dashboard/layout", protect(auth.PermViewDashboard, saveLayoutHandler(st)))

		// Response engine: the block approval workflow (executed via the same responder
		// as the worker — RESPONDER/RESPONSE_LIVE). See internal/respond.
		respStore := respond.NewStore(st.Pool())
		respEngine := respond.NewEngine(respStore, respond.ResponderFromEnv(), respond.DefaultBanPolicy(), false)
		mux.Handle("/api/responses", protect(auth.PermViewDashboard, responsesHandler(respStore)))
		mux.Handle("POST /api/responses/{id}/approve", protect(auth.PermApproveRemediation, approveResponseHandler(respEngine)))
		mux.Handle("POST /api/responses/{id}/dismiss", protect(auth.PermApproveRemediation, dismissResponseHandler(respEngine)))

		// Integrations registry (firewalls, bouncers, CTI providers). Secret config
		// fields are encrypted at rest with the secrets cipher.
		if cipher, dev, cerr := secret.FromEnv(); cerr != nil {
			log.Printf("api: secrets cipher unavailable — integrations disabled: %v", cerr)
		} else {
			if dev {
				log.Printf("api: SECRETS_KEY not set — using a DEV key (set SECRETS_KEY for production!)")
			}
			intStore := integrations.NewStore(st.Pool(), cipher)
			mux.Handle("/api/integrations/types", protect(auth.PermManageIntegrations, intStore.TypesHandler()))
			mux.Handle("/api/integrations", protect(auth.PermManageIntegrations, intStore.CollectionHandler()))
			mux.Handle("/api/integrations/{id}", protect(auth.PermManageIntegrations, intStore.ItemHandler()))
		}

		// Tier-2 DFIR ticketing (case management).
		ticketStore := tickets.NewStore(st.Pool())
		mux.Handle("GET /api/tickets", protect(auth.PermViewTickets, ticketStore.ListHandler()))
		mux.Handle("POST /api/tickets", protect(auth.PermManageTickets, ticketStore.CreateHandler()))
		mux.Handle("GET /api/tickets/{id}", protect(auth.PermViewTickets, ticketStore.GetHandler()))
		mux.Handle("PUT /api/tickets/{id}", protect(auth.PermManageTickets, ticketStore.UpdateHandler()))
		mux.Handle("POST /api/tickets/{id}/comments", protect(auth.PermManageTickets, ticketStore.CommentHandler()))
	} else {
		// Without a DB: endpoints reply 503.
		mux.HandleFunc("/api/events", eventsHandler(nil))
		mux.HandleFunc("/api/alerts", alertsHandler(nil))
		mux.HandleFunc("/api/stats", statsHandler(nil))
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("DeusWatch API %s listening on %s", version, addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// seedAdmin creates the initial admin user if there are no users yet.
func seedAdmin(authStore *auth.Store) {
	user := getenv("ADMIN_USERNAME", "admin")
	pass := os.Getenv("ADMIN_PASSWORD")
	if pass == "" {
		pass = "thewatcher"
		log.Printf("api: ADMIN_PASSWORD empty — using the dev default (CHANGE it for production!)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	created, err := authStore.EnsureAdmin(ctx, user, pass)
	if err != nil {
		log.Printf("api: seed admin failed: %v", err)
		return
	}
	if created {
		log.Printf("api: initial admin user %q created", user)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "DeusWatch API",
		"version": version,
		"status":  "ok",
	})
}

// healthzHandler = liveness.
func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

// readyzHandler = readiness (Postgres & NATS reachable). Foundation stage: TCP dial.
func readyzHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	targets := map[string]string{
		"postgres": getenv("POSTGRES_ADDR", "db:5432"),
		"nats":     getenv("NATS_ADDR", "nats:4222"),
	}
	deps := make(map[string]string, len(targets))
	allReady := true
	for name, target := range targets {
		if err := dialTCP(ctx, target); err != nil {
			deps[name] = "unreachable: " + err.Error()
			allReady = false
			continue
		}
		deps[name] = "reachable"
	}
	status, overall := http.StatusOK, "ready"
	if !allReady {
		status, overall = http.StatusServiceUnavailable, "not_ready"
	}
	writeJSON(w, status, map[string]any{"status": overall, "dependencies": deps})
}

func eventsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		rows, err := st.RecentEvents(r.Context(), queryLimit(r, 50, 500))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

func alertsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		rows, err := st.RecentAlerts(r.Context(), queryLimit(r, 50, 500))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

func statsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		s, err := st.Stats(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, s)
	}
}

func reportHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours, err := strconv.Atoi(r.URL.Query().Get("hours"))
		if err != nil || hours <= 0 {
			hours = 24
		}
		rep, err := st.BuildReport(r.Context(), hours)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if r.URL.Query().Get("format") == "md" {
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			_, _ = w.Write([]byte(report.RenderMarkdown(rep)))
			return
		}
		writeJSON(w, http.StatusOK, rep)
	}
}

func dashboardDataHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours, err := strconv.Atoi(r.URL.Query().Get("hours"))
		if err != nil || hours <= 0 {
			hours = 24
		}
		d, err := st.Dashboard(r.Context(), hours)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, d)
	}
}

func getLayoutHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		if u == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		raw, err := st.GetDashboardLayout(r.Context(), u.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if raw == nil {
			_, _ = w.Write([]byte("null"))
			return
		}
		_, _ = w.Write(raw)
	}
}

func saveLayoutHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		if u == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		if !json.Valid(body) {
			http.Error(w, "invalid JSON layout", http.StatusBadRequest)
			return
		}
		if err := st.SaveDashboardLayout(r.Context(), u.ID, body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
	}
}

func responsesHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := s.List(r.Context(), r.URL.Query().Get("status"), queryLimit(r, 100, 500))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func approveResponseHandler(e *respond.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := e.Approve(r.Context(), id, currentUsername(r)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "id": id})
	}
}

func dismissResponseHandler(e *respond.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := e.Dismiss(r.Context(), id, currentUsername(r)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "dismissed", "id": id})
	}
}

func currentUsername(r *http.Request) string {
	if u, ok := auth.UserFrom(r.Context()); ok {
		return u.Username
	}
	return ""
}

func queryLimit(r *http.Request, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func dialTCP(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}
