// Command api is the DeusWatch API server.
//
// It serves health checks (liveness/readiness) and the Phase 1 data-read endpoints
// (events, alerts, stats) from PostgreSQL+TimescaleDB for the Web UI.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"deuswatch/internal/agentinstall"
	"deuswatch/internal/auth"
	"deuswatch/internal/enroll"
	"deuswatch/internal/integrations"
	"deuswatch/internal/llm"
	"deuswatch/internal/migrate"
	"deuswatch/internal/mtls"
	"deuswatch/internal/report"
	"deuswatch/internal/respond"
	"deuswatch/internal/rules"
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
		if s := connectStoreWithRetry(dsn); s == nil {
			log.Printf("api: store unavailable after retries (continuing without DB)")
		} else {
			st = s
			defer s.Close()
			log.Printf("api: store connected")
			// Automatic migration runner (idempotent) — unless RUN_MIGRATIONS=0.
			if run, _ := strconv.ParseBool(getenv("RUN_MIGRATIONS", "1")); run {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if n, merr := migrate.Apply(ctx, s.Pool(), migrations.FS); merr != nil {
					log.Printf("api: migration failed: %v", merr)
				} else if n > 0 {
					log.Printf("api: %d migrations applied", n)
				} else {
					log.Printf("api: database schema up to date")
				}
				cancel()
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/readyz", readyzHandler)

	// Public one-line agent installer: scripts + cross-compiled binaries (no auth;
	// the enrollment token is the credential). Binaries come from AGENT_BIN_DIR.
	ai := agentinstall.New(getenv("AGENT_BIN_DIR", "/agents"))
	mux.HandleFunc("GET /api/agent/install.sh", ai.InstallSh)
	mux.HandleFunc("GET /api/agent/install.ps1", ai.InstallPs1)
	mux.HandleFunc("GET /api/agent/binary/{os}/{arch}", ai.Binary)

	if st != nil {
		authStore := auth.NewStore(st.Pool())
		seedAdmin(authStore)

		// Detection rules: seed the bundled rules into the DB on first start, then serve CRUD.
		ruleStore := rules.NewStore(st.Pool())
		sctx, scancel := context.WithTimeout(context.Background(), 20*time.Second)
		if n, serr := ruleStore.SeedFromDir(sctx, getenv("RULES_DIR", "/rules/sigma")); serr != nil {
			log.Printf("api: rule seed: %v", serr)
		} else if n > 0 {
			log.Printf("api: seeded %d builtin detection rules", n)
		}
		scancel()

		// Public (no token).
		mux.HandleFunc("/api/login", authStore.LoginHandler())

		// Self-registration (optional, DISABLED by default): admins create users in the UI.
		// Set REGISTRATION_ENABLED=1 to allow new viewer-role accounts from the login page.
		registrationEnabled, _ := strconv.ParseBool(getenv("REGISTRATION_ENABLED", "0"))
		mux.HandleFunc("/api/auth/config", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]bool{"registration_enabled": registrationEnabled})
		})
		if registrationEnabled {
			mux.HandleFunc("/api/register", authStore.RegisterHandler())
			log.Printf("api: self-registration ENABLED (set REGISTRATION_ENABLED=0 to disable)")
		} else {
			log.Printf("api: self-registration disabled (set REGISTRATION_ENABLED=1 to enable)")
		}

		// Protected: requires a valid session + permission.
		protect := func(p auth.Permission, h http.HandlerFunc) http.Handler {
			return authStore.Middleware(auth.RequirePermission(p, h))
		}
		mux.Handle("/api/me", authStore.Middleware(authStore.MeHandler()))
		mux.Handle("/api/me/password", authStore.Middleware(authStore.ChangePasswordHandler()))
		mux.Handle("/api/logout", authStore.Middleware(authStore.LogoutHandler()))
		mux.Handle("/api/users", protect(auth.PermManageUsers, authStore.UsersHandler()))
		mux.Handle("PUT /api/users/{id}", protect(auth.PermManageUsers, authStore.UpdateUserHandler()))
		mux.Handle("DELETE /api/users/{id}", protect(auth.PermManageUsers, authStore.DeleteUserHandler()))
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
		mux.Handle("GET /api/events/search", protect(auth.PermViewDashboard, searchEventsHandler(st)))
		mux.Handle("POST /api/export/events", protect(auth.PermViewDashboard, exportEventsHandler(st)))
		mux.Handle("POST /api/export/report", protect(auth.PermViewDashboard, exportReportHandler(st)))
		mux.Handle("/api/alerts", protect(auth.PermViewDashboard, alertsHandler(st)))
		mux.Handle("/api/stats", protect(auth.PermViewDashboard, statsHandler(st)))
		mux.Handle("/api/report", protect(auth.PermViewDashboard, reportHandler(st)))
		mux.Handle("GET /api/report/summary", protect(auth.PermViewDashboard, reportSummaryGetHandler(st)))
		mux.Handle("POST /api/report/summary", protect(auth.PermViewDashboard, reportSummaryGenerateHandler(st)))
		mux.Handle("GET /api/report/ai-config", protect(auth.PermViewDashboard, reportAIConfigGetHandler(st)))
		mux.Handle("PUT /api/report/ai-config", protect(auth.PermManageSettings, reportAIConfigSetHandler(st)))

		// Config profile: export/import all settings to clone one server's setup onto another.
		mux.Handle("GET /api/config/export", protect(auth.PermManageSettings, configExportHandler(st)))
		mux.Handle("POST /api/config/import", protect(auth.PermManageSettings, configImportHandler(st)))

		// Customizable dashboard: aggregated series + per-user widget layout.
		mux.Handle("GET /api/dashboard", protect(auth.PermViewDashboard, dashboardDataHandler(st)))
		mux.Handle("GET /api/dashboard/layout", protect(auth.PermViewDashboard, getLayoutHandler(st)))
		mux.Handle("PUT /api/dashboard/layout", protect(auth.PermViewDashboard, saveLayoutHandler(st)))

		// Response engine: the block approval workflow (executed via the same responder
		// as the worker — RESPONDER/RESPONSE_LIVE). See internal/respond.
		respStore := respond.NewStore(st.Pool())
		respEngine := respond.NewEngine(respStore, respond.ResponderFromEnv(), respond.DefaultBanPolicy(), false)
		mux.Handle("/api/responses", protect(auth.PermViewDashboard, responsesHandler(respStore)))
		mux.Handle("GET /api/responses/offenders", protect(auth.PermViewDashboard, offendersHandler(respStore)))
		mux.Handle("POST /api/responses/dismiss-ip", protect(auth.PermApproveRemediation, dismissIPHandler(respStore)))
		mux.Handle("POST /api/responses/{id}/approve", protect(auth.PermApproveRemediation, approveResponseHandler(respEngine)))
		mux.Handle("POST /api/responses/{id}/dismiss", protect(auth.PermApproveRemediation, dismissResponseHandler(respEngine)))

		// Progressive-ban policy (escalation ladder). View for anyone with the dashboard;
		// edit requires manage_settings. The worker live-reloads it.
		mux.Handle("GET /api/ban-policy", protect(auth.PermViewDashboard, banPolicyGetHandler(respStore)))
		mux.Handle("PUT /api/ban-policy", protect(auth.PermManageSettings, banPolicySetHandler(respStore)))

		// IP whitelist: trusted IPs/CIDRs the response engine never bans.
		mux.Handle("GET /api/whitelist", protect(auth.PermViewDashboard, whitelistListHandler(respStore)))
		mux.Handle("POST /api/whitelist", protect(auth.PermManageSettings, whitelistAddHandler(respStore)))
		mux.Handle("DELETE /api/whitelist/{id}", protect(auth.PermManageSettings, whitelistDeleteHandler(respStore)))

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

		// Detection rules CRUD (Wazuh-style management).
		mux.Handle("/api/rules", protect(auth.PermManageRules, ruleStore.CollectionHandler()))
		mux.Handle("/api/rules/{id}", protect(auth.PermManageRules, ruleStore.ItemHandler()))

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

// connectStoreWithRetry dials the store, retrying with backoff so the API survives
// starting before Postgres is ready — e.g. after a host/Docker Desktop reboot, where
// compose `depends_on` ordering is NOT honored and the API can win the race against
// the DB. Without this, a one-shot connect failure leaves every DB-backed route
// (including /api/login) unregistered → 404 until a manual restart. Returns nil only
// if the DB never becomes reachable within the window.
func connectStoreWithRetry(dsn string) *store.Store {
	const maxWait = 90 * time.Second
	deadline := time.Now().Add(maxWait)
	delay := time.Second
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, err := store.Connect(ctx, dsn)
		cancel()
		if err == nil {
			return s
		}
		if time.Now().After(deadline) {
			log.Printf("api: store connect gave up after %s: %v", maxWait, err)
			return nil
		}
		log.Printf("api: store not ready (attempt %d): %v — retrying in %s", attempt, err, delay)
		time.Sleep(delay)
		if delay < 8*time.Second {
			delay *= 2
		}
	}
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

// searchEventsHandler powers the dashboard's filterable Events/Alerts table.
// Query params: q, ip, rule, technique, category, severity (min 0..4), alerts (bool),
// from/to (RFC3339), limit. All optional.
// parseEventFilter builds an EventFilter from the request query params (shared by the
// search and webhook-export endpoints).
func parseEventFilter(r *http.Request) store.EventFilter {
	q := r.URL.Query()
	f := store.EventFilter{
		Text:        q.Get("q"),
		SourceIP:    q.Get("ip"),
		RuleID:      q.Get("rule"),
		TechniqueID: q.Get("technique"),
		Category:    q.Get("category"),
		MinSeverity: -1,
		Limit:       queryLimit(r, 50, 500),
	}
	if sev, err := strconv.Atoi(q.Get("severity")); err == nil && sev >= 0 {
		f.MinSeverity = sev
	}
	if b, _ := strconv.ParseBool(q.Get("alerts")); b {
		f.AlertsOnly = true
	}
	if t, ok := parseTime(q.Get("from")); ok {
		f.From = t
	}
	if t, ok := parseTime(q.Get("to")); ok {
		f.To = t
	}
	return f
}

func searchEventsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		rows, err := st.SearchEvents(r.Context(), parseEventFilter(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// apiResolveWebhook returns the configured export-webhook URL (webhook_export integration
// or the WEBHOOK_EXPORT_URL env), or "" if none.
func apiResolveWebhook(ctx context.Context, st *store.Store) string {
	if cipher, _, err := secret.FromEnv(); err == nil {
		intStore := integrations.NewStore(st.Pool(), cipher)
		if rows, rerr := intStore.Resolve(ctx, "webhook_export"); rerr == nil && len(rows) > 0 {
			if u := rows[0].Config["url"]; u != "" {
				return u
			}
		}
	}
	return os.Getenv("WEBHOOK_EXPORT_URL")
}

// postJSON sends payload as a JSON POST to url.
func postJSON(ctx context.Context, url string, payload any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// exportEventsHandler POSTs the filtered events to the configured export webhook as JSON.
func exportEventsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := apiResolveWebhook(r.Context(), st)
		if url == "" {
			http.Error(w, "no export webhook configured — add a 'Webhook export' integration", http.StatusBadRequest)
			return
		}
		rows, err := st.SearchEvents(r.Context(), parseEventFilter(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		payload := map[string]any{"source": "deuswatch", "type": "events", "generated_at": time.Now(), "count": len(rows), "events": rows}
		if err := postJSON(r.Context(), url, payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sent": len(rows)})
	}
}

// exportReportHandler POSTs the report to the configured export webhook as JSON.
func exportReportHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := apiResolveWebhook(r.Context(), st)
		if url == "" {
			http.Error(w, "no export webhook configured — add a 'Webhook export' integration", http.StatusBadRequest)
			return
		}
		hours, err := strconv.Atoi(r.URL.Query().Get("hours"))
		if err != nil || hours <= 0 {
			hours = 24
		}
		rep, err := st.BuildReport(r.Context(), hours)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		payload := map[string]any{"source": "deuswatch", "type": "report", "generated_at": time.Now(), "report": rep}
		if err := postJSON(r.Context(), url, payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sent": 1})
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

// apiResolveAnalyzer builds an LLM analyzer for on-demand report summaries, preferring an
// enabled "llm" integration over env (mirrors the worker's resolveAnalyzer).
func apiResolveAnalyzer(ctx context.Context, st *store.Store) (llm.Analyzer, bool) {
	if cipher, _, err := secret.FromEnv(); err == nil {
		intStore := integrations.NewStore(st.Pool(), cipher)
		if rows, rerr := intStore.Resolve(ctx, "llm"); rerr == nil && len(rows) > 0 {
			c := rows[0].Config
			if a, aerr := llm.NewAnalyzer(c["provider"], c["base_url"], c["api_key"], c["model"]); aerr == nil {
				return a, true
			}
		}
	}
	return llm.AnalyzerFromEnv()
}

// reportSummaryGetHandler returns the latest stored AI report summary (no LLM call).
func reportSummaryGetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rs, ok, err := st.LatestReportSummary(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			writeJSON(w, http.StatusOK, map[string]any{"summary": "", "generated_at": nil})
			return
		}
		writeJSON(w, http.StatusOK, rs)
	}
}

// reportSummaryGenerateHandler generates a fresh AI summary on demand (one LLM call).
func reportSummaryGenerateHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours, err := strconv.Atoi(r.URL.Query().Get("hours"))
		if err != nil || hours <= 0 {
			hours = 24
		}
		analyzer, ok := apiResolveAnalyzer(r.Context(), st)
		if !ok {
			http.Error(w, "no LLM configured — add an LLM integration (Ollama/Claude) or set LLM_BASE_URL / ANTHROPIC_API_KEY", http.StatusBadRequest)
			return
		}
		rep, err := st.BuildReport(r.Context(), hours)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		summary, err := analyzer.Summarize(ctx, report.SummaryPrompt(rep))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if err := st.SaveReportSummary(r.Context(), hours, summary, analyzer.Name()); err != nil {
			log.Printf("api: save report summary: %v", err)
		}
		writeJSON(w, http.StatusOK, store.ReportSummary{Summary: summary, Model: analyzer.Name(), PeriodHours: hours, GeneratedAt: time.Now()})
	}
}

func reportAIConfigGetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := st.LoadReportAIConfig(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}
}

func reportAIConfigSetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var c store.ReportAIConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if c.IntervalHours < 0 || c.PeriodHours < 0 {
			http.Error(w, "hours must be >= 0", http.StatusBadRequest)
			return
		}
		if err := st.SaveReportAIConfig(r.Context(), c); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}
}

// configExportHandler returns a portable JSON profile of this server's configuration —
// detection rules, ban policy, IP whitelist, the AI-report schedule, and integrations
// (secret values masked out) — so it can be imported on another DeusWatch server.
func configExportHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rs := respond.NewStore(st.Pool())
		rl := rules.NewStore(st.Pool())
		bundle := map[string]any{"version": 1, "exported_at": time.Now()}

		if p, err := rs.LoadPolicy(ctx); err == nil {
			bundle["ban_policy"] = banPolicyJSON(p)
		}
		if wl, err := rs.ListWhitelist(ctx); err == nil {
			items := make([]map[string]string, 0, len(wl))
			for _, e := range wl {
				items = append(items, map[string]string{"cidr": e.CIDR, "note": e.Note})
			}
			bundle["ip_whitelist"] = items
		}
		if c, err := st.LoadReportAIConfig(ctx); err == nil {
			bundle["report_ai_config"] = c
		}
		if rr, err := rl.List(ctx); err == nil {
			items := make([]map[string]any, 0, len(rr))
			for _, ru := range rr {
				items = append(items, map[string]any{"name": ru.Name, "kind": ru.Kind, "yaml": ru.YAML, "enabled": ru.Enabled, "builtin": ru.Builtin})
			}
			bundle["rules"] = items
		}
		if cipher, _, err := secret.FromEnv(); err == nil {
			if list, err := integrations.NewStore(st.Pool(), cipher).List(ctx); err == nil {
				items := make([]map[string]any, 0, len(list))
				for _, it := range list {
					items = append(items, map[string]any{"type": it.Type, "name": it.Name, "enabled": it.Enabled, "config": it.Config, "secrets_set": it.SecretsSet})
				}
				bundle["integrations"] = items
			}
		}
		w.Header().Set("Content-Disposition", `attachment; filename="deuswatch-config.json"`)
		writeJSON(w, http.StatusOK, bundle)
	}
}

// configImportHandler applies a config profile (from configExportHandler) onto this server.
// Secret values are NOT part of the profile — re-enter them after import. Rules and
// integrations are upserted by name; ban policy / whitelist / schedule are replaced/merged.
func configImportHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			BanPolicy *struct {
				Durations   []int `json:"durations"`
				Permanent   bool  `json:"permanent"`
				WindowSecs  int   `json:"window_secs"`
				AutoApprove bool  `json:"auto_approve"`
			} `json:"ban_policy"`
			Whitelist []struct{ CIDR, Note string } `json:"ip_whitelist"`
			ReportAI  *store.ReportAIConfig         `json:"report_ai_config"`
			Rules     []struct {
				Name, Kind, YAML string
				Enabled          bool
			} `json:"rules"`
			Integrations []struct {
				Type, Name string
				Enabled    bool
				Config     map[string]string
			} `json:"integrations"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&b); err != nil {
			http.Error(w, "invalid config profile", http.StatusBadRequest)
			return
		}
		ctx := r.Context()
		pool := st.Pool()
		rs := respond.NewStore(pool)
		applied := map[string]int{}

		if b.BanPolicy != nil {
			durs := make([]time.Duration, 0, len(b.BanPolicy.Durations))
			for _, s := range b.BanPolicy.Durations {
				if s > 0 {
					durs = append(durs, time.Duration(s)*time.Second)
				}
			}
			if len(durs) > 0 {
				_ = rs.SavePolicy(ctx, respond.BanPolicy{Durations: durs, Permanent: b.BanPolicy.Permanent,
					Window: time.Duration(b.BanPolicy.WindowSecs) * time.Second, AutoApprove: b.BanPolicy.AutoApprove})
				applied["ban_policy"] = 1
			}
		}
		for _, e := range b.Whitelist {
			if _, err := rs.AddWhitelist(ctx, e.CIDR, e.Note); err == nil {
				applied["ip_whitelist"]++
			}
		}
		if b.ReportAI != nil {
			_ = st.SaveReportAIConfig(ctx, *b.ReportAI)
			applied["report_ai_config"] = 1
		}
		for _, ru := range b.Rules {
			if ru.Name == "" || ru.YAML == "" {
				continue
			}
			var id string
			if err := pool.QueryRow(ctx, `SELECT id FROM rules WHERE name=$1`, ru.Name).Scan(&id); err == nil {
				_, _ = pool.Exec(ctx, `UPDATE rules SET yaml=$1, enabled=$2, updated_at=now() WHERE id=$3`, ru.YAML, ru.Enabled, id)
			} else {
				kind := ru.Kind
				if kind == "" {
					kind = "single"
				}
				_, _ = pool.Exec(ctx, `INSERT INTO rules (name,kind,yaml,enabled,builtin) VALUES ($1,$2,$3,$4,false)`, ru.Name, kind, ru.YAML, ru.Enabled)
			}
			applied["rules"]++
		}
		for _, it := range b.Integrations {
			if it.Type == "" || it.Name == "" {
				continue
			}
			cfg, _ := json.Marshal(it.Config)
			var id string
			if err := pool.QueryRow(ctx, `SELECT id FROM integrations WHERE type=$1 AND name=$2`, it.Type, it.Name).Scan(&id); err == nil {
				_, _ = pool.Exec(ctx, `UPDATE integrations SET enabled=$1, config=$2, updated_at=now() WHERE id=$3`, it.Enabled, cfg, id)
			} else {
				_, _ = pool.Exec(ctx, `INSERT INTO integrations (type,name,enabled,config) VALUES ($1,$2,$3,$4)`, it.Type, it.Name, it.Enabled, cfg)
			}
			applied["integrations"]++
		}
		writeJSON(w, http.StatusOK, map[string]any{"applied": applied, "note": "re-enter integration secrets (API keys/passwords) after import"})
	}
}

func dashboardDataHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		since, until := dashboardWindow(r)
		d, err := st.Dashboard(r.Context(), since, until)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, d)
	}
}

// dashboardWindow resolves the time window from the request: an explicit
// from/to (RFC3339) range takes precedence, otherwise a relative ?hours= window
// (default 24h). The span is clamped to at most 90 days.
func dashboardWindow(r *http.Request) (since, until time.Time) {
	q := r.URL.Query()
	from, fOK := parseTime(q.Get("from"))
	to, tOK := parseTime(q.Get("to"))
	if fOK || tOK {
		if !tOK {
			to = time.Now()
		}
		if !fOK {
			from = to.Add(-24 * time.Hour)
		}
		if from.After(to) {
			from, to = to, from
		}
		if to.Sub(from) > 90*24*time.Hour {
			from = to.Add(-90 * 24 * time.Hour)
		}
		return from, to
	}
	hours, err := strconv.Atoi(q.Get("hours"))
	if err != nil || hours <= 0 || hours > 24*90 {
		hours = 24
	}
	now := time.Now()
	return now.Add(-time.Duration(hours) * time.Hour), now
}

// parseTime accepts an RFC3339 timestamp (with or without a numeric offset).
func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
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

func banPolicyJSON(p respond.BanPolicy) map[string]any {
	secs := make([]int, len(p.Durations))
	for i, d := range p.Durations {
		secs[i] = int(d.Seconds())
	}
	return map[string]any{
		"durations":    secs,
		"permanent":    p.Permanent,
		"window_secs":  int(p.Window.Seconds()),
		"auto_approve": p.AutoApprove,
	}
}

func banPolicyGetHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.LoadPolicy(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, banPolicyJSON(p))
	}
}

func banPolicySetHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Durations   []int `json:"durations"`
			Permanent   bool  `json:"permanent"`
			WindowSecs  int   `json:"window_secs"`
			AutoApprove bool  `json:"auto_approve"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if len(req.Durations) == 0 {
			http.Error(w, "at least one ban duration is required", http.StatusBadRequest)
			return
		}
		durs := make([]time.Duration, 0, len(req.Durations))
		for _, secs := range req.Durations {
			if secs <= 0 {
				http.Error(w, "ban durations must be positive (seconds)", http.StatusBadRequest)
				return
			}
			durs = append(durs, time.Duration(secs)*time.Second)
		}
		if req.WindowSecs < 0 {
			http.Error(w, "window must be >= 0", http.StatusBadRequest)
			return
		}
		p := respond.BanPolicy{Durations: durs, Permanent: req.Permanent, Window: time.Duration(req.WindowSecs) * time.Second, AutoApprove: req.AutoApprove}
		if err := s.SavePolicy(r.Context(), p); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, banPolicyJSON(p))
	}
}

func whitelistListHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := s.ListWhitelist(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func whitelistAddHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CIDR string `json:"cidr"`
			Note string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if _, err := respond.NormalizeCIDR(req.CIDR); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		e, err := s.AddWhitelist(r.Context(), req.CIDR, req.Note)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, e)
	}
}

func whitelistDeleteHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.DeleteWhitelist(r.Context(), r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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

// offendersHandler returns the per-IP rollup for the IP-centric response view.
func offendersHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Offenders(r.Context(), queryLimit(r, 200, 1000))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

// dismissIPHandler bulk-dismisses every pending recommendation for one IP.
func dismissIPHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if net.ParseIP(req.IP) == nil {
			http.Error(w, "invalid IP", http.StatusBadRequest)
			return
		}
		n, err := s.DismissPendingForIP(r.Context(), req.IP, currentUsername(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "dismissed", "dismissed": n})
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
