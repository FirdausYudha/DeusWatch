// Command api is the DeusWatch API server.
//
// It serves health checks (liveness/readiness) and the Phase 1 data-read endpoints
// (events, alerts, stats) from PostgreSQL+TimescaleDB for the Web UI.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"deuswatch/internal/agentinstall"
	"deuswatch/internal/auth"
	"deuswatch/internal/bus"
	"deuswatch/internal/decoders"
	"deuswatch/internal/enroll"
	"deuswatch/internal/ingest"
	"deuswatch/internal/ingesthook"
	"deuswatch/internal/integrations"
	"deuswatch/internal/llm"
	"deuswatch/internal/migrate"
	"deuswatch/internal/mtls"
	"deuswatch/internal/playbooks"
	"deuswatch/internal/report"
	"deuswatch/internal/respond"
	"deuswatch/internal/rules"
	"deuswatch/internal/secret"
	"deuswatch/internal/store"
	"deuswatch/internal/tickets"
	"deuswatch/migrations"
)

const version = "0.1.0-foundation"

// buildVersion is the short git commit baked in at build time (-ldflags -X). "dev" when
// built without it. Used by the update-check endpoint to compare against GitHub.
var buildVersion = "dev"

const githubRepo = "FirdausYudha/DeusWatch"

func main() {
	addr := getenv("HTTP_ADDR", ":8080")

	// Reverse proxies whose X-Forwarded-For we trust (the bundled web/nginx
	// container in compose). Without this the login rate limiter and audit log
	// would see every UI request as the proxy's IP.
	if tp := os.Getenv("TRUSTED_PROXIES"); tp != "" {
		if err := auth.SetTrustedProxies(tp); err != nil {
			log.Printf("api: %v", err)
		}
	}
	// Password policy floor for NEW passwords (existing hashes are untouched).
	if v := os.Getenv("PASSWORD_MIN_LEN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			auth.SetMinPasswordLen(n)
		}
	}

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
	ai := agentinstall.New(getenv("AGENT_BIN_DIR", "/agents"), getenv("PUBLIC_API_PORT", "8080"), getenv("PUBLIC_GATEWAY_PORT", "8443"))
	mux.HandleFunc("GET /api/agent/install.sh", ai.InstallSh)
	mux.HandleFunc("GET /api/agent/install.ps1", ai.InstallPs1)
	mux.HandleFunc("GET /api/agent/install-info", ai.InstallInfo)
	mux.HandleFunc("GET /api/agent/binary/{os}/{arch}", ai.Binary)

	if st != nil {
		authStore := auth.NewStore(st.Pool())
		seedAdmin(authStore)

		// Detection rules: seed the bundled rules into the DB on first start, then serve CRUD.
		ruleStore := rules.NewStore(st.Pool())
		sctx, scancel := context.WithTimeout(context.Background(), 20*time.Second)
		rulesDir := getenv("RULES_DIR", "/rules/sigma")
		if n, serr := ruleStore.SeedFromDir(sctx, rulesDir); serr != nil {
			log.Printf("api: rule seed: %v", serr)
		} else if n > 0 {
			log.Printf("api: seeded %d builtin detection rules", n)
		}
		// On upgrades, add any newly-bundled builtin rules the DB doesn't have yet.
		if n, serr := ruleStore.SyncBuiltinsFromDir(sctx, rulesDir); serr != nil {
			log.Printf("api: rule sync: %v", serr)
		} else if n > 0 {
			log.Printf("api: added %d new builtin detection rules", n)
		}
		scancel()

		// Custom decoders (data-driven log-source support): seed/sync the bundled examples,
		// then manage from the UI; the gateway loads the enabled set and live-reloads.
		decoderStore := decoders.NewStore(st.Pool())
		dctx, dcancel := context.WithTimeout(context.Background(), 20*time.Second)
		if n, derr := decoderStore.SyncBuiltinsFromDir(dctx, getenv("DECODERS_DIR", "/decoders")); derr != nil {
			log.Printf("api: decoder sync: %v", derr)
		} else if n > 0 {
			log.Printf("api: added %d builtin decoder(s)", n)
		}
		dcancel()

		// Activate the enabled decoder set in THIS process too (+ live-reload), so raw lines
		// ingested via the webhook are normalized with the operator's custom decoders - the
		// gateway has its own copy for agent traffic; the API needs one for the webhook.
		if set, derr := decoderStore.EnabledSet(context.Background()); derr == nil {
			ingest.SetDecoders(set)
		}
		go reloadAPIDecoders(context.Background(), decoderStore)

		// Remediation playbooks (design doc section 9): seed/sync the bundled catalog
		// (rules/playbooks/), then manage from the UI; the worker live-reloads the
		// enabled set and stamps the matching playbook onto every fired alert.
		playbookStore := playbooks.NewStore(st.Pool())
		pbctx, pbcancel := context.WithTimeout(context.Background(), 20*time.Second)
		if n, perr := playbookStore.SyncBuiltinsFromDir(pbctx, getenv("PLAYBOOKS_DIR", "/rules/playbooks")); perr != nil {
			log.Printf("api: playbook sync: %v", perr)
		} else if n > 0 {
			log.Printf("api: added %d builtin playbook(s)", n)
		}
		pbcancel()

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

		// Threat-scoring weights (composite score + suspicious-IP watchlist), UI-tunable.
		mux.Handle("GET /api/score-config", protect(auth.PermViewDashboard, scoreConfigGetHandler(st)))
		mux.Handle("PUT /api/score-config", protect(auth.PermManageSettings, scoreConfigSetHandler(st)))

		// ML bridge: a token-authed API for an external anomaly-detection batch (e.g. an Isolation
		// Forest) to pull per-IP features and write anomaly_score back. Token-based (like the
		// ingest webhook) so a cron/Python job can call it without a UI session. Off (404) unless
		// ML_API_TOKEN is set.
		mux.HandleFunc("GET /api/ml/ip-features", mlFeaturesHandler(st))
		mux.HandleFunc("POST /api/ml/anomaly", mlAnomalyHandler(st))

		// Subscription API (the sellable rich-log product): external subscribers PULL enriched
		// events / threat indicators with a per-subscriber API key (no UI session). Admins manage
		// the keys under manage_integrations. See internal/store/subscriptions.go + docs.
		mux.HandleFunc("GET /api/subscribe/events", subscribeEventsHandler(st))
		mux.HandleFunc("GET /api/subscribe/indicators", subscribeIndicatorsHandler(st))
		mux.Handle("GET /api/subscriptions", protect(auth.PermManageIntegrations, subscriptionsListHandler(st)))
		mux.Handle("POST /api/subscriptions", protect(auth.PermManageIntegrations, subscriptionCreateHandler(st)))
		mux.Handle("POST /api/subscriptions/{id}/toggle", protect(auth.PermManageIntegrations, subscriptionToggleHandler(st)))
		mux.Handle("DELETE /api/subscriptions/{id}", protect(auth.PermManageIntegrations, subscriptionDeleteHandler(st)))

		// Versioned FIM snapshots (ADR 0002): browse the dated version timeline of watched files.
		mux.Handle("GET /api/fim/snapshots/paths", protect(auth.PermViewDashboard, fimSnapshotPathsHandler(st)))
		mux.Handle("GET /api/fim/snapshots", protect(auth.PermViewDashboard, fimSnapshotsHandler(st)))
		mux.Handle("GET /api/fim/actions", protect(auth.PermViewDashboard, fimActionsHandler(st)))
		mux.Handle("POST /api/fim/snapshot-now", protect(auth.PermManageAgents, fimSnapshotNowHandler(st)))
		mux.Handle("POST /api/fim/quarantine", protect(auth.PermApproveRemediation, fimQuarantineHandler(st)))
		mux.Handle("POST /api/fim/restore-version", protect(auth.PermApproveRemediation, fimRestoreVersionHandler(st)))
		mux.Handle("POST /api/fim/bulk-restore", protect(auth.PermApproveRemediation, fimBulkRestoreHandler(st)))

		// Ransomware kill-switch: viewing proposals is a dashboard right, but authorizing a
		// process termination requires approve-remediation - the same bar as other destructive
		// response actions.
		mux.Handle("GET /api/kill-requests", protect(auth.PermViewDashboard, killListHandler(st)))
		mux.Handle("POST /api/kill-requests/approve", protect(auth.PermApproveRemediation, killDecisionHandler(st, true)))
		mux.Handle("POST /api/kill-requests/dismiss", protect(auth.PermApproveRemediation, killDecisionHandler(st, false)))

		// Log storage health (size, retention/compression, replication) for the dashboard.
		mux.Handle("GET /api/storage/status", protect(auth.PermViewDashboard, storageStatusHandler(st)))
		mux.Handle("PUT /api/storage/retention", protect(auth.PermManageSettings, storageRetentionHandler(st)))

		// Software update check (read-only; never executes an update).
		mux.Handle("GET /api/update-check", protect(auth.PermViewDashboard, updateCheckHandler()))

		// CTI enrichment: dedup cache TTL (UI-managed).

		// Notifications: alert severity threshold + scheduled report delivery to channels.
		mux.Handle("GET /api/notify-config", protect(auth.PermViewDashboard, notifyConfigGetHandler(st)))
		mux.Handle("PUT /api/notify-config", protect(auth.PermManageSettings, notifyConfigSetHandler(st)))

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
		// Blocklist feed (pull model): a token-gated, unauthenticated URL that serves the active
		// banned IPs as a plaintext/JSON list, so any external firewall that fetches a dynamic
		// block list (Palo Alto EDL, OPNsense URL-table alias, pfSense pfBlockerNG, MikroTik
		// fetch) can mirror our bans. The token is UI-managed (Response page); an existing
		// BLOCKLIST_FEED_TOKEN env is seeded into the DB once so it keeps working.
		if sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second); true {
			if err := respStore.SeedFeedTokenFromEnv(sctx, os.Getenv("BLOCKLIST_FEED_TOKEN")); err != nil {
				log.Printf("api: seed feed token: %v", err)
			}
			cancel()
		}
		// Raw-log ingest webhook (e.g. a Wazuh manager pushing alerts). Token-authed like the
		// blocklist feed; publishes normalized events to NATS so they flow through the normal
		// pipeline. The token is UI-managed (Integrations page) and read per request, so
		// enable/regenerate/disable take effect immediately; an existing INGEST_WEBHOOK_TOKEN
		// env is seeded into the DB once so it keeps working. Route needs a reachable NATS.
		if sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second); true {
			if err := st.SeedWebhookTokenFromEnv(sctx, os.Getenv("INGEST_WEBHOOK_TOKEN")); err != nil {
				log.Printf("api: seed webhook token: %v", err)
			}
			cancel()
		}
		if natsURL := os.Getenv("NATS_URL"); natsURL != "" {
			if b, berr := bus.Connect(context.Background(), natsURL); berr != nil {
				log.Printf("api: ingest webhook disabled — NATS unavailable: %v", berr)
			} else {
				hook := ingesthook.New(b, st.WebhookToken)
				mux.Handle("POST /api/ingest/webhook", hook)
				// Config endpoints for the Integrations-page panel (admin-managed inbound secret).
				mux.Handle("GET /api/ingest-config", protect(auth.PermManageIntegrations, ingestConfigHandler(st)))
				mux.Handle("POST /api/ingest-config/regenerate", protect(auth.PermManageIntegrations, ingestRegenerateHandler(st)))
				mux.Handle("POST /api/ingest-config/disable", protect(auth.PermManageIntegrations, ingestDisableHandler(st)))
				if hook.Enabled() {
					log.Printf("api: raw-log ingest webhook active (POST /api/ingest/webhook?token=...)")
				} else {
					log.Printf("api: ingest webhook route registered but OFF (enable it on the Integrations page)")
				}
			}
		}

		mux.HandleFunc("GET /api/blocklist", blocklistFeedHandler(respStore, respStore.FeedToken))
		mux.Handle("GET /api/blocklist-config", protect(auth.PermManageSettings, blocklistConfigHandler(respStore)))
		mux.Handle("POST /api/blocklist-config/regenerate", protect(auth.PermManageSettings, blocklistRegenerateHandler(respStore)))
		mux.Handle("GET /api/response/enforcement", protect(auth.PermViewDashboard, enforcementHandler(st, respStore.FeedToken)))
		mux.Handle("GET /api/response/decision-table", protect(auth.PermViewDashboard, decisionTableHandler()))
		mux.Handle("/api/responses", protect(auth.PermViewDashboard, responsesHandler(respStore)))
		mux.Handle("GET /api/responses/offenders", protect(auth.PermViewDashboard, offendersHandler(respStore)))
		mux.Handle("POST /api/responses/dismiss-ip", protect(auth.PermApproveRemediation, dismissIPHandler(respStore)))
		mux.Handle("POST /api/responses/{id}/approve", protect(auth.PermApproveRemediation, approveResponseHandler(respEngine)))
		mux.Handle("POST /api/responses/{id}/dismiss", protect(auth.PermApproveRemediation, dismissResponseHandler(respEngine)))
		mux.Handle("POST /api/responses/{id}/unban", protect(auth.PermApproveRemediation, unbanResponseHandler(respEngine)))

		// Progressive-ban policy (escalation ladder). View for anyone with the dashboard;
		// edit requires manage_settings. The worker live-reloads it.
		mux.Handle("GET /api/ban-policy", protect(auth.PermViewDashboard, banPolicyGetHandler(respStore)))
		mux.Handle("PUT /api/ban-policy", protect(auth.PermManageSettings, banPolicySetHandler(respStore)))

		// IP whitelist: trusted IPs/CIDRs the response engine never bans.
		mux.Handle("GET /api/whitelist", protect(auth.PermViewDashboard, whitelistListHandler(respStore)))
		mux.Handle("POST /api/whitelist", protect(auth.PermManageSettings, whitelistAddHandler(respStore)))
		mux.Handle("DELETE /api/whitelist/{id}", protect(auth.PermManageSettings, whitelistDeleteHandler(respStore)))

		// Network containment (host isolation): analyst list + approve/dismiss/release. The
		// edge-block half of a release executes via the same responder as the worker.
		containEngine := respond.NewContainmentEngine(respStore, respond.ResponderFromEnv(), false)
		mux.Handle("GET /api/containments", protect(auth.PermViewDashboard, containmentsHandler(respStore)))
		mux.Handle("POST /api/containments/{id}/approve", protect(auth.PermApproveRemediation, approveContainmentHandler(containEngine)))
		mux.Handle("POST /api/containments/{id}/dismiss", protect(auth.PermApproveRemediation, dismissContainmentHandler(containEngine)))
		mux.Handle("POST /api/containments/{id}/release", protect(auth.PermApproveRemediation, releaseContainmentHandler(containEngine)))

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
		mux.Handle("GET /api/rules/packs", protect(auth.PermManageRules, ruleStore.PacksHandler()))
		mux.Handle("POST /api/rules/packs/{id}/toggle", protect(auth.PermManageRules, ruleStore.PackToggleHandler()))
		mux.Handle("POST /api/rules/packs/{id}/install", protect(auth.PermManageRules, ruleStore.PackInstallHandler()))
		mux.Handle("POST /api/rules/packs/{id}/uninstall", protect(auth.PermManageRules, ruleStore.PackUninstallHandler()))
		mux.Handle("/api/rules/{id}", protect(auth.PermManageRules, ruleStore.ItemHandler()))
		mux.Handle("/api/decoders", protect(auth.PermManageRules, decoderStore.CollectionHandler()))
		mux.Handle("GET /api/decoders/samples", protect(auth.PermManageRules, decoderStore.SamplesHandler()))
		mux.Handle("POST /api/decoders/test", protect(auth.PermManageRules, decoderStore.TestHandler()))
		mux.Handle("/api/decoders/{id}", protect(auth.PermManageRules, decoderStore.ItemHandler()))
		mux.Handle("/api/playbooks", protect(auth.PermManageRules, playbookStore.CollectionHandler()))
		mux.Handle("/api/playbooks/{id}", protect(auth.PermManageRules, playbookStore.ItemHandler()))
		mux.Handle("POST /api/fim/restore", protect(auth.PermExecuteBlock, fimRestoreHandler(st)))

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

	log.Printf("DeusWatch API %s listening on %s", appVersion(), addr)
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

// reloadAPIDecoders keeps this process's decoder set in sync with UI edits (every 30s),
// so webhook-ingested raw lines are normalized with the operator's latest custom decoders.
func reloadAPIDecoders(ctx context.Context, ds *decoders.Store) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rc, cancel := context.WithTimeout(ctx, 10*time.Second)
			if set, err := ds.EnabledSet(rc); err == nil {
				ingest.SetDecoders(set)
			}
			cancel()
		}
	}
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
		"version": appVersion(),
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
		Agent:       q.Get("agent"),
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
		st.AttachScores(r.Context(), rows)
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

// fimRestoreHandler (POST /api/fim/restore {agent, path}) requests that an agent restore a
// file to its known-good snapshot (undo a defacement). Needs the execute_block permission.
func fimRestoreHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Agent string `json:"agent"`
			Path  string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Agent == "" || req.Path == "" {
			http.Error(w, "agent and path are required", http.StatusBadRequest)
			return
		}
		by := ""
		if u, ok := auth.UserFrom(r.Context()); ok {
			by = u.Username
		}
		if err := st.RequestRestore(r.Context(), req.Agent, req.Path, by); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "restore requested", "path": req.Path})
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
		st.AttachScores(r.Context(), rows)
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
		var (
			rep report.Report
			err error
		)
		// An explicit from–to range (used by the PDF/Markdown export) wins over ?hours=, which
		// is the rolling "last N hours" the page shows by default.
		if from, to, ok := parseReportRange(r); ok {
			rep, err = st.BuildReportRange(r.Context(), from, to)
		} else {
			hours, herr := strconv.Atoi(r.URL.Query().Get("hours"))
			if herr != nil || hours <= 0 {
				hours = 24
			}
			rep, err = st.BuildReport(r.Context(), hours)
		}
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

// parseReportRange reads an explicit ?from=&to= window. Both are accepted as an RFC3339
// timestamp or a plain YYYY-MM-DD date; a bare date means the whole day, so `to=2026-07-17`
// includes that day rather than stopping at midnight. ok=false means no range was requested.
func parseReportRange(r *http.Request) (from, to time.Time, ok bool) {
	parse := func(v string, endOfDay bool) (time.Time, bool) {
		v = strings.TrimSpace(v)
		if v == "" {
			return time.Time{}, false
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t, true
		}
		if d, err := time.ParseInLocation("2006-01-02", v, time.Local); err == nil {
			if endOfDay {
				return d.AddDate(0, 0, 1), true // exclusive end = start of the next day
			}
			return d, true
		}
		return time.Time{}, false
	}
	f, fok := parse(r.URL.Query().Get("from"), false)
	if !fok {
		return time.Time{}, time.Time{}, false
	}
	t, tok := parse(r.URL.Query().Get("to"), true)
	if !tok {
		t = time.Now() // from given without to: run up to now
	}
	if t.Before(f) {
		f, t = t, f // tolerate a swapped range rather than returning an empty report
	}
	return f, t, true
}

// apiResolveAnalyzer builds an LLM analyzer for on-demand report summaries, preferring an
// enabled "llm" integration over env (mirrors the worker's resolveAnalyzer).
func apiResolveAnalyzer(ctx context.Context, st *store.Store) (llm.Analyzer, bool) {
	if cipher, _, err := secret.FromEnv(); err == nil {
		intStore := integrations.NewStore(st.Pool(), cipher)
		if rows, rerr := intStore.Resolve(ctx, "llm"); rerr == nil {
			// On-demand summary is a report task: prefer a model set to report/both.
			for _, row := range rows {
				c := row.Config
				if !integrations.LLMPurposeMatches(c["purpose"], "report") {
					continue
				}
				if a, aerr := llm.NewAnalyzer(c["provider"], c["base_url"], c["api_key"], c["model"]); aerr == nil {
					return a, true
				}
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
		analyzer, ok := apiResolveAnalyzer(r.Context(), st)
		if !ok {
			http.Error(w, "no LLM configured — add an LLM integration (Ollama/Claude) or set LLM_BASE_URL / ANTHROPIC_API_KEY", http.StatusBadRequest)
			return
		}
		// Summarize the SAME window the page shows: an explicit from–to range wins over ?hours=,
		// so a summary generated with the date range picker actually covers those dates.
		var (
			rep   report.Report
			err   error
			hours int
		)
		if from, to, hasRange := parseReportRange(r); hasRange {
			rep, err = st.BuildReportRange(r.Context(), from, to)
			hours = int(to.Sub(from).Hours() + 0.5)
		} else {
			hours, _ = strconv.Atoi(r.URL.Query().Get("hours"))
			if hours <= 0 {
				hours = 24
			}
			rep, err = st.BuildReport(r.Context(), hours)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		cfg, _ := st.LoadReportAIConfig(r.Context()) // custom prompt template ("" = default)
		summary, err := analyzer.Summarize(ctx, cfg.SummaryPrompt, report.SummaryPrompt(rep))
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

// mlAuthorized checks the ML_API_TOKEN (query ?token= or Authorization: Bearer) in constant time.
// Returns false — and writes the response — when the token is unset (feature off) or wrong.
func mlAuthorized(w http.ResponseWriter, r *http.Request) bool {
	want := strings.TrimSpace(os.Getenv("ML_API_TOKEN"))
	if want == "" {
		http.Error(w, "ML API disabled (set ML_API_TOKEN)", http.StatusNotFound)
		return false
	}
	got := r.URL.Query().Get("token")
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// mlFeaturesHandler (GET /api/ml/ip-features?token=&window=24h&limit=1000) serves the per-IP
// feature vectors for the external ML batch (Isolation Forest low-and-slow detection).
func mlFeaturesHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !mlAuthorized(w, r) {
			return
		}
		window := 24 * time.Hour
		if v := r.URL.Query().Get("window"); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				window = d
			}
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		feats, err := st.IPFeatures(r.Context(), window, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, feats)
	}
}

// mlAnomalyHandler (POST /api/ml/anomaly?token=) accepts the anomaly_score writeback. Body: a
// JSON array [{"ip":"1.2.3.4","anomaly":85}, …] (or a single object). The composite scorer folds
// the score in on its next run, subject to the UI-tunable anomaly weight.
func mlAnomalyHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !mlAuthorized(w, r) {
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
		if err != nil {
			http.Error(w, "request too large", http.StatusBadRequest)
			return
		}
		trimmed := bytesTrimLeadingSpace(body)
		var entries []store.IPAnomaly
		if len(trimmed) > 0 && trimmed[0] == '{' {
			var one store.IPAnomaly
			if err := json.Unmarshal(body, &one); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			entries = []store.IPAnomaly{one}
		} else if err := json.Unmarshal(body, &entries); err != nil {
			http.Error(w, "invalid body (expected a JSON array of {ip, anomaly})", http.StatusBadRequest)
			return
		}
		n, err := st.SetIPAnomalies(r.Context(), entries)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"updated": n})
	}
}

func bytesTrimLeadingSpace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	return b[i:]
}

func scoreConfigGetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := st.LoadScoreConfig(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Include the built-in defaults so the UI can offer "reset to defaults".
		writeJSON(w, http.StatusOK, map[string]any{"config": c, "defaults": store.DefaultScoreConfig()})
	}
}

func scoreConfigSetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var c store.ScoreConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := st.SaveScoreConfig(r.Context(), c); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Return the sanitized/stored value so the UI reflects any clamping.
		saved, _ := st.LoadScoreConfig(r.Context())
		writeJSON(w, http.StatusOK, saved)
	}
}

func reportAIConfigGetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := st.LoadReportAIConfig(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Return the built-in default too so the UI can show it / offer "reset to default".
		// server_time tells the UI which clock at_hour refers to (the server's, not the
		// browser's) — without it "run at 08:00" is ambiguous on a UTC container.
		now := time.Now()
		zone, _ := now.Zone()
		writeJSON(w, http.StatusOK, map[string]any{
			"interval_hours": c.IntervalHours,
			"period_hours":   c.PeriodHours,
			"summary_prompt": c.SummaryPrompt,
			"at_hour":        c.AtHour,
			"default_prompt": llm.DefaultReportSystemPrompt,
			"server_time":    now.Format("15:04"),
			"server_tz":      zone,
		})
	}
}

func reportAIConfigSetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Default AtHour to -1 BEFORE decoding: an omitted at_hour must mean "no fixed hour",
		// not midnight (the zero value would silently pin the summary to 00:00).
		c := store.ReportAIConfig{AtHour: -1}
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
// storageBudgetBytes reads the configured log-storage soft cap (STORAGE_BUDGET_GB).
func storageBudgetBytes() int64 {
	if v := os.Getenv("STORAGE_BUDGET_GB"); v != "" {
		if gb, err := strconv.ParseFloat(v, 64); err == nil && gb > 0 {
			return int64(gb * 1024 * 1024 * 1024)
		}
	}
	return 0
}

func storageStatusHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, st.StorageStatus(r.Context(), storageBudgetBytes()))
	}
}

func storageRetentionHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RetentionDays   int `json:"retention_days"`
			CompressionDays int `json:"compression_days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.RetentionDays < 1 || body.RetentionDays > 3650 {
			http.Error(w, "retention_days must be 1..3650", http.StatusBadRequest)
			return
		}
		if body.CompressionDays < 0 || body.CompressionDays >= body.RetentionDays {
			http.Error(w, "compression_days must be >= 0 and less than retention_days", http.StatusBadRequest)
			return
		}
		if err := st.SetLifecycle(r.Context(), body.RetentionDays, body.CompressionDays); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, st.StorageStatus(r.Context(), storageBudgetBytes()))
	}
}

// updateCheckHandler compares the running build against the latest commit on GitHub's main
// branch (read-only). It never executes an update — that stays a host operation
// (./scripts/update.sh) so the web container needs no Docker/host access.
// parseSemver extracts the major/minor/patch from a tag like "v1.2.3" (any pre-release or
// "-N-gsha" build suffix after the patch is ignored). ok=false when it doesn't parse.
func parseSemver(s string) ([3]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// semverLess reports whether version a is strictly older than b. Non-parseable => false.
func semverLess(a, b string) bool {
	pa, oka := parseSemver(a)
	pb, okb := parseSemver(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

// appVersion returns the human-friendly version: the baked semver from git tags
// (e.g. "v1.1.1", or "v1.1.1-3-gabc" between releases), falling back to the const.
func appVersion() string {
	if buildVersion != "" && buildVersion != "dev" {
		return buildVersion
	}
	return version
}

func updateCheckHandler() http.HandlerFunc {
	type result struct {
		Current         string `json:"current"`
		Latest          string `json:"latest"`
		LatestDate      string `json:"latest_date"`
		UpdateAvailable bool   `json:"update_available"`
		RepoURL         string `json:"repo_url"`
		UpdateCommand   string `json:"update_command"`
	}
	hc := &http.Client{Timeout: 8 * time.Second}
	return func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet,
			"https://api.github.com/repos/"+githubRepo+"/releases/latest", nil)
		req.Header.Set("Accept", "application/vnd.github+json")
		cur := appVersion()
		resp, err := hc.Do(req)
		if err != nil {
			http.Error(w, "could not reach GitHub: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			// No published releases yet - report the running version, nothing to compare.
			writeJSON(w, http.StatusOK, result{Current: cur, UpdateAvailable: false,
				RepoURL: "https://github.com/" + githubRepo, UpdateCommand: "./scripts/update.sh"})
			return
		}
		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("GitHub returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
			return
		}
		var gh struct {
			TagName     string `json:"tag_name"`
			PublishedAt string `json:"published_at"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&gh); err != nil {
			http.Error(w, "bad response from GitHub", http.StatusBadGateway)
			return
		}
		latest := gh.TagName
		// Available only when the latest release is a strictly newer semver than our version
		// (a dev build ahead of the latest release is "up to date", not behind).
		available := latest != "" && cur != "dev" && semverLess(cur, latest)
		writeJSON(w, http.StatusOK, result{
			Current: cur, Latest: latest, LatestDate: gh.PublishedAt,
			UpdateAvailable: available,
			RepoURL:         "https://github.com/" + githubRepo + "/releases",
			UpdateCommand:   "./scripts/update.sh",
		})
	}
}

func notifyConfigGetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := st.LoadNotifyConfig(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}
}

func notifyConfigSetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var c store.NotifyConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if c.MinSeverity < 0 || c.MinSeverity > 4 || c.ReportIntervalHours < 0 || c.ReportPeriodHours < 0 {
			http.Error(w, "min_severity must be 0..4 and hours >= 0", http.StatusBadRequest)
			return
		}
		if err := st.SaveNotifyConfig(r.Context(), c); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}
}

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
		if c, err := st.LoadNotifyConfig(ctx); err == nil {
			bundle["notify_config"] = c
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
			Notify    *store.NotifyConfig           `json:"notify_config"`
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
		if b.Notify != nil {
			_ = st.SaveNotifyConfig(ctx, *b.Notify)
			applied["notify_config"] = 1
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

// blockLister is the subset of the response store the blocklist feed needs (stubbable in tests).
type blockLister interface {
	ActiveBlocks(ctx context.Context) ([]string, error)
}

// blocklistFeedConfig is the store the UI config handlers need.
type blocklistFeedConfig interface {
	FeedToken(ctx context.Context) (string, error)
	SetFeedToken(ctx context.Context, token string) error
}

// blocklistConfigHandler (GET /api/blocklist-config) returns the current feed token + whether the
// feed is enabled, for the Response page's feed panel (admin only).
func blocklistConfigHandler(s blocklistFeedConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, err := s.FeedToken(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": tok, "enabled": tok != ""})
	}
}

// blocklistRegenerateHandler (POST /api/blocklist-config/regenerate) mints a new random feed
// token (rotating it, which invalidates the old URL) and returns it.
func blocklistRegenerateHandler(s blocklistFeedConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 24)
		if _, err := rand.Read(buf); err != nil {
			http.Error(w, "token generation failed", http.StatusInternalServerError)
			return
		}
		tok := hex.EncodeToString(buf)
		if err := s.SetFeedToken(r.Context(), tok); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": tok, "enabled": true})
	}
}

// enforcementHandler (GET /api/response/enforcement) reports whether a ban can ACTUALLY reach a
// firewall. Without it the Response page would badge an IP "blocked" even when nothing is wired
// up to enforce it — DeusWatch would be claiming an action it never performed. The UI uses this
// to relabel such rows as "Dangerous IP" instead.
//
// A ban reaches a firewall when either:
//   - a push responder is live: RESPONSE_LIVE=1 AND a MikroTik/CrowdSec/nftables connector is
//     enabled (Integrations) or selected via the RESPONDER env; or
//   - the pull blocklist feed is enabled: an external firewall fetches the list itself.
func enforcementHandler(st *store.Store, feedToken func(context.Context) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		live, _ := strconv.ParseBool(os.Getenv("RESPONSE_LIVE"))
		backends := []string{}
		for _, t := range []string{"mikrotik", "crowdsec", "nftables_agent"} {
			if ok, err := integrations.HasEnabled(r.Context(), st.Pool(), t); err == nil && ok {
				backends = append(backends, t)
			}
		}
		switch strings.ToLower(strings.TrimSpace(os.Getenv("RESPONDER"))) {
		case "nftables", "crowdsec", "mikrotik":
			backends = append(backends, os.Getenv("RESPONDER")+" (env)")
		}
		feed := false
		if tok, err := feedToken(r.Context()); err == nil && tok != "" {
			feed = true
		}
		pushLive := live && len(backends) > 0
		writeJSON(w, http.StatusOK, map[string]any{
			"enforcing":      pushLive || feed, // a ban actually reaches something
			"push_live":      pushLive,
			"response_live":  live,
			"backends":       backends,
			"blocklist_feed": feed,
		})
	}
}

// fimSnapshotPathsHandler (GET /api/fim/snapshots/paths?agent=) lists the watched files that have
// dated snapshots for an agent (ADR 0002).
func fimSnapshotPathsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agent := strings.TrimSpace(r.URL.Query().Get("agent"))
		if agent == "" {
			http.Error(w, "agent required", http.StatusBadRequest)
			return
		}
		paths, err := st.ListSnapshotPaths(r.Context(), agent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"paths": paths})
	}
}

// fimSnapshotsHandler (GET /api/fim/snapshots?agent=&path=&limit=) returns the dated version
// timeline of one watched file, newest first (ADR 0002).
func fimSnapshotsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		agent, path := strings.TrimSpace(q.Get("agent")), strings.TrimSpace(q.Get("path"))
		if agent == "" || path == "" {
			http.Error(w, "agent and path required", http.StatusBadRequest)
			return
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		snaps, err := st.ListSnapshots(r.Context(), agent, path, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"snapshots": snaps})
	}
}

// fimActionsHandler (GET /api/fim/actions?agent=&path=) returns recent on-demand file actions
// (snapshot_now / quarantine) and their outcomes for one watched file (ADR 0002 Phase 3).
func fimActionsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		agent, path := strings.TrimSpace(q.Get("agent")), strings.TrimSpace(q.Get("path"))
		if agent == "" || path == "" {
			http.Error(w, "agent and path required", http.StatusBadRequest)
			return
		}
		acts, err := st.ListFileActions(r.Context(), agent, path, 25)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"actions": acts})
	}
}

// ── Ransomware kill-switch (feature 3) ────────────────────────────────────────
//
// Killing a process is the most destructive action DeusWatch can take, so detections land as
// inert RECOMMENDATIONS and a human with approve-remediation must promote them. Approval is the
// manager-side gate only; the agent independently re-verifies process identity and protection
// before it kills anything, and its refusal is final (internal/agent/killproc.go).

// killListHandler (GET /api/kill-requests?pending=1&limit=) lists proposed/executed kills.
func killListHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pending := r.URL.Query().Get("pending") == "1"
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		reqs, err := st.ListKillRequests(r.Context(), pending, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"requests": reqs})
	}
}

// killDecisionHandler (POST /api/kill-requests/{action}) approves or dismisses a recommendation.
// Both are one-shot: they only affect a row still awaiting a decision, so a double-click or a
// stale tab cannot re-fire a kill or overturn a recorded outcome.
func killDecisionHandler(st *store.Store, approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID int64 `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		var err error
		if approve {
			err = st.ApproveKill(r.Context(), req.ID, currentUsername(r))
		} else {
			err = st.DismissKill(r.Context(), req.ID, currentUsername(r))
		}
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "no pending kill recommendation with that id (already decided?)", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// fimActionReq is the body for the on-demand file-action endpoints.
type fimActionReq struct {
	Agent string `json:"agent"`
	Path  string `json:"path"`
}

func (req fimActionReq) valid() bool {
	return strings.TrimSpace(req.Agent) != "" && strings.TrimSpace(req.Path) != ""
}

// fimSnapshotNowHandler (POST /api/fim/snapshot-now) queues an immediate version capture.
func fimSnapshotNowHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req fimActionReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.valid() {
			http.Error(w, "agent and path required", http.StatusBadRequest)
			return
		}
		if err := st.RequestFileAction(r.Context(), req.Agent, req.Path, "snapshot_now", currentUsername(r)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// fimQuarantineHandler (POST /api/fim/quarantine) queues moving the current file into quarantine
// for blue-team analysis.
func fimQuarantineHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req fimActionReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.valid() {
			http.Error(w, "agent and path required", http.StatusBadRequest)
			return
		}
		if err := st.RequestFileAction(r.Context(), req.Agent, req.Path, "quarantine", currentUsername(r)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// fimRestoreVersionHandler (POST /api/fim/restore-version {agent, path, sha256}) queues restoring
// a watched file to a specific captured version (ADR 0002 restore-by-date).
func fimRestoreVersionHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Agent  string `json:"agent"`
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
			strings.TrimSpace(req.Agent) == "" || strings.TrimSpace(req.Path) == "" || len(strings.TrimSpace(req.SHA256)) != 64 {
			http.Error(w, "agent, path and a 64-char sha256 required", http.StatusBadRequest)
			return
		}
		if err := st.RequestRestoreVersion(r.Context(), req.Agent, req.Path, strings.TrimSpace(req.SHA256), currentUsername(r)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// fimBulkRestoreHandler (POST /api/fim/bulk-restore {agent, path, as_of}) queues a point-in-time
// revert of every watched file (optionally under `path`) to its version as of `as_of` — the
// ransomware "roll everything back to before the attack" action (ADR 0002).
func fimBulkRestoreHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Agent string `json:"agent"`
			Path  string `json:"path"`  // optional directory subtree ("" = all watched files)
			AsOf  string `json:"as_of"` // RFC3339
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Agent) == "" {
			http.Error(w, "agent and as_of required", http.StatusBadRequest)
			return
		}
		asOf, err := time.Parse(time.RFC3339, strings.TrimSpace(req.AsOf))
		if err != nil {
			http.Error(w, "as_of must be RFC3339", http.StatusBadRequest)
			return
		}
		n, err := st.BulkRestoreVersions(r.Context(), req.Agent, req.Path, asOf, currentUsername(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"queued": n})
	}
}

// decisionTableHandler (GET /api/response/decision-table) returns the explicit entity_type →
// response policy mapping (external_ip → block, host → network_containment, user/hash →
// alert-only). It is the same table the worker routes alerts by, so the UI and an LLM analyst
// can read exactly what DeusWatch does with each kind of entity — and see which actions are
// automatically enforced today versus surfaced for review.
func decisionTableHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"decisions": respond.DefaultDecisionTable()})
	}
}

// ── Subscription API (sellable rich-log product) ─────────────────────────────
// External subscribers PULL enriched events / indicators with a per-subscriber API key. The
// subscriber endpoints authenticate by key (no UI session); the /api/subscriptions endpoints are
// admin-only (manage_integrations) key management. See internal/store/subscriptions.go.

// subscriptionKeyFromRequest pulls the presented API key from Authorization: Bearer, the
// X-API-Key header, or the ?key= query param (in that order).
func subscriptionKeyFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	if h := strings.TrimSpace(r.Header.Get("X-API-Key")); h != "" {
		return h
	}
	return strings.TrimSpace(r.URL.Query().Get("key"))
}

// authSubscriber resolves the subscriber from its API key and checks the required scope, writing
// the 401/403 response and returning nil on failure. A successful call bumps the usage counters.
func authSubscriber(w http.ResponseWriter, r *http.Request, st *store.Store, scope string) *store.Subscription {
	sub, err := st.AuthenticateSubscription(r.Context(), subscriptionKeyFromRequest(r))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil
	}
	if !sub.HasScope(scope) {
		http.Error(w, "forbidden: subscription lacks scope "+scope, http.StatusForbidden)
		return nil
	}
	return sub
}

// subscribeSettleLag is how long an event must age before it is served to subscribers, so CTI and
// score enrichment have settled first (SUBSCRIPTION_SETTLE_LAG, default 30s).
func subscribeSettleLag() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("SUBSCRIPTION_SETTLE_LAG")); err == nil && d >= 0 {
		return d
	}
	return 30 * time.Second
}

// subscribeEventsHandler (GET /api/subscribe/events?cursor=&limit=&from=&min_severity=) serves a
// forward-only, cursor-paginated page of enriched events for a subscriber.
func subscribeEventsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub := authSubscriber(w, r, st, "events")
		if sub == nil {
			return
		}
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		// The subscription's own min_severity is the floor; a caller may raise it, never lower it.
		minSev := sub.MinSeverity
		if v, err := strconv.Atoi(q.Get("min_severity")); err == nil && v > minSev {
			minSev = v
		}
		var from time.Time
		if v := q.Get("from"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				from = t
			}
		}
		page, err := st.SubscriptionEvents(r.Context(), q.Get("cursor"), minSev, subscribeSettleLag(), from, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, page)
	}
}

// subscribeIndicatorsHandler (GET /api/subscribe/indicators?min_score=&limit=) serves curated
// scored source IPs, highest score first.
func subscribeIndicatorsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub := authSubscriber(w, r, st, "indicators")
		if sub == nil {
			return
		}
		q := r.URL.Query()
		minScore, _ := strconv.Atoi(q.Get("min_score"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		inds, err := st.SubscriptionIndicators(r.Context(), minScore, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"indicators": inds})
	}
}

// subscriptionsListHandler (GET /api/subscriptions) lists subscribers (no secrets).
func subscriptionsListHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subs, err := st.ListSubscriptions(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"subscriptions": subs})
	}
}

// subscriptionCreateHandler (POST /api/subscriptions) creates a subscriber and returns the ONE-
// TIME plaintext API key (never retrievable again).
func subscriptionCreateHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name        string   `json:"name"`
			Scopes      []string `json:"scopes"`
			MinSeverity int      `json:"min_severity"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		sub, key, err := st.CreateSubscription(r.Context(), req.Name, req.Scopes, req.MinSeverity)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"subscription": sub, "api_key": key})
	}
}

// subscriptionToggleHandler (POST /api/subscriptions/{id}/toggle) enables/disables a subscriber.
func subscriptionToggleHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := st.SetSubscriptionEnabled(r.Context(), r.PathValue("id"), req.Enabled); err != nil {
			http.Error(w, err.Error(), notFoundOr500(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// subscriptionDeleteHandler (DELETE /api/subscriptions/{id}) removes a subscriber permanently.
func subscriptionDeleteHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := st.DeleteSubscription(r.Context(), r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), notFoundOr500(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func notFoundOr500(err error) int {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

// ingestWebhookConfig is the store subset the webhook config handlers need.
type ingestWebhookConfig interface {
	WebhookToken(ctx context.Context) (string, error)
	SetWebhookToken(ctx context.Context, token string) error
}

// ingestConfigHandler (GET /api/ingest-config) returns the current inbound-webhook token and
// whether it is enabled, for the Integrations-page panel (manage_integrations only).
func ingestConfigHandler(s ingestWebhookConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, err := s.WebhookToken(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": tok, "enabled": tok != ""})
	}
}

// ingestRegenerateHandler (POST /api/ingest-config/regenerate) mints a new random webhook token
// (rotating it, which invalidates the old one) and returns it.
func ingestRegenerateHandler(s ingestWebhookConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 24)
		if _, err := rand.Read(buf); err != nil {
			http.Error(w, "token generation failed", http.StatusInternalServerError)
			return
		}
		tok := hex.EncodeToString(buf)
		if err := s.SetWebhookToken(r.Context(), tok); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": tok, "enabled": true})
	}
}

// ingestDisableHandler (POST /api/ingest-config/disable) clears the token, turning the webhook
// off (subsequent POSTs 404). Reversible by regenerating.
func ingestDisableHandler(s ingestWebhookConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.SetWebhookToken(r.Context(), ""); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": "", "enabled": false})
	}
}

// blocklistFeedHandler serves the currently-banned IPs as a firewall-consumable dynamic block
// list. It is token-gated (the UI-managed feed token) and unauthenticated so a firewall appliance
// can poll it on a schedule. The default body is one IP per line (what Palo Alto EDL / OPNsense
// URL tables / pfSense pfBlockerNG / MikroTik fetch expect); ?format=json returns JSON. The token
// is read per request so a regenerate takes effect immediately; an empty token disables the feed
// (404), so it is never exposed by accident.
func blocklistFeedHandler(bl blockLister, tokenFn func(context.Context) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := tokenFn(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if token == "" {
			http.NotFound(w, r) // feed not enabled
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ips, err := bl.ActiveBlocks(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sort.Strings(ips)
		if r.URL.Query().Get("format") == "json" {
			writeJSON(w, http.StatusOK, map[string]any{
				"generated": time.Now().UTC().Format(time.RFC3339),
				"count":     len(ips),
				"ips":       ips,
			})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		var b strings.Builder
		fmt.Fprintf(&b, "# DeusWatch blocklist - %d active blocks - %s\n", len(ips), time.Now().UTC().Format(time.RFC3339))
		for _, ip := range ips {
			b.WriteString(ip)
			b.WriteByte('\n')
		}
		_, _ = io.WriteString(w, b.String())
	}
}

func responsesHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := s.List(r.Context(), r.URL.Query().Get("status"), r.URL.Query().Get("q"), queryLimit(r, 100, 500))
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

func unbanResponseHandler(e *respond.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := e.Unban(r.Context(), id, currentUsername(r)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "id": id})
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

// ── Network containment (host isolation) ──────────────────

func containmentsHandler(s *respond.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := s.ListContainments(r.Context(), r.URL.Query().Get("status"), queryLimit(r, 100, 500))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func approveContainmentHandler(e *respond.ContainmentEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := e.Approve(r.Context(), id, currentUsername(r)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "contained", "id": id})
	}
}

func dismissContainmentHandler(e *respond.ContainmentEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := e.Dismiss(r.Context(), id, currentUsername(r)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "dismissed", "id": id})
	}
}

func releaseContainmentHandler(e *respond.ContainmentEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := e.Release(r.Context(), id, currentUsername(r)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "released", "id": id})
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
