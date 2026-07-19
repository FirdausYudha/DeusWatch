// Command worker runs the DeusWatch worker. Phase 1: detection mode (SSH brute force).
// Other modes (enrich/respond/llm) are integrated and selected via env.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"deuswatch/internal/archive"
	"deuswatch/internal/bus"
	"deuswatch/internal/clickhouse"
	"deuswatch/internal/detect"
	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/enrich"
	"deuswatch/internal/espull"
	"deuswatch/internal/hashrep"
	"deuswatch/internal/ingest"
	"deuswatch/internal/integrations"
	"deuswatch/internal/llm"
	"deuswatch/internal/notify"
	"deuswatch/internal/playbooks"
	"deuswatch/internal/report"
	"deuswatch/internal/respond"
	"deuswatch/internal/rules"
	"deuswatch/internal/secret"
	"deuswatch/internal/store"
	"deuswatch/internal/syslogin"
	"deuswatch/internal/worker"
)

// aggInterval: how often the aggregation runner (Sigma SQL path) scans events.
const aggInterval = 30 * time.Second

// llmInterval: how often the LLM worker analyzes alerts without a verdict.
const llmInterval = 20 * time.Second

func main() {
	natsURL := getenv("NATS_URL", "nats://localhost:4222")
	dsn := getenv("STORE_DSN", "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable")

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	st, err := store.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("worker: store: %v", err)
	}
	defer st.Close()

	b, err := bus.Connect(ctx, natsURL)
	if err != nil {
		log.Fatalf("worker: bus: %v", err)
	}
	defer b.Close()

	// Integrations registry: CTI keys & responder config the admin manages in the UI
	// take precedence over env vars. nil if the secrets cipher can't be built.
	var intStore *integrations.Store
	if cipher, dev, cerr := secret.FromEnv(); cerr != nil {
		log.Printf("worker: secrets cipher unavailable — using env-only integration config: %v", cerr)
	} else {
		if dev {
			log.Printf("worker: SECRETS_KEY not set — using a DEV key (set SECRETS_KEY for production!)")
		}
		intStore = integrations.NewStore(st.Pool(), cipher)
	}

	bruteForce := detect.NewBruteForceDetector(detect.DefaultBruteForceConfig())

	// Detection rules come from the DB (managed in the UI). Fall back to the bundled files
	// if the DB has none yet. The runner re-reads the DB periodically (live reload).
	ruleStore := rules.NewStore(st.Pool())
	sigmaDir := getenv("RULES_DIR", "rules/sigma")
	single, agg, rerr := ruleStore.Enabled(ctx)
	if rerr != nil {
		log.Printf("worker: load rules from DB: %v", rerr)
	}
	if len(single) == 0 && len(agg) == 0 {
		if rs, derr := sigma.LoadDir(sigmaDir); derr == nil {
			single = rs
		}
		if ar, derr := sigma.LoadAggDir(sigmaDir); derr == nil {
			agg = ar
		}
		log.Printf("worker: DB rules empty — loaded from disk %q", sigmaDir)
	}
	sigmaDet := detect.NewSigmaDetector(single)
	aggRunner := detect.NewAggregateRunner(st, agg, 0)
	log.Printf("worker: %d single-event + %d aggregation rules loaded", sigmaDet.RuleCount(), aggRunner.RuleCount())

	// CTI enrichment: TTL cache in Postgres + a real provider when AbuseIPDB/OTX keys are
	// configured — from the Integrations registry first, then env (GEOIP via env), else mock.
	abuseKey, otxKey := resolveCTIKeys(ctx, intStore)
	geoOn, _ := strconv.ParseBool(os.Getenv("GEOIP_ENABLED"))
	provider, real := enrich.BuildProvider(abuseKey, otxKey, geoOn, splitCSV(os.Getenv("BLOCKLIST_URLS")))
	if real {
		log.Printf("worker: real CTI provider active (abuseipdb=%v otx=%v geoip=%v)", abuseKey != "", otxKey != "", geoOn)
	} else {
		log.Printf("worker: mock CTI provider (add an AbuseIPDB/OTX integration or set the env keys for real)")
	}
	ctiTTL := resolveCTITTL(ctx, intStore) // dedup window; configured on the CTI integration
	enricher := enrich.NewEnricher(provider, enrich.NewCache(st.Pool()), ctiTTL, enrich.EscalationFromEnv())

	// FIM file-hash reputation (optional): CIRCL hashlookup (free) + VirusTotal, from the
	// Integrations registry first, then env. Enables known-good/known-bad classification of
	// hashed files (a known-bad file raises the event to High severity).
	vtKey, mbKey, circlOn := resolveHashRep(ctx, intStore)
	if hp, hok := hashrep.BuildProvider(vtKey, mbKey, circlOn); hok {
		enricher.SetHashReputation(hp, hashrep.NewCache(st.Pool()), ctiTTL)
		log.Printf("worker: FIM hash reputation active (virustotal=%v, malwarebazaar=%v, circl=%v)", vtKey != "", mbKey != "", circlOn)
	}

	// Response engine (Phase 2): block recommendations + approval + progressive ban.
	// The responder comes from the Integrations registry (MikroTik) first, else RESPONDER env
	// (dry-run unless RESPONSE_LIVE=1). RESPONSE_AUTO_APPROVE=1 executes without manual approval.
	respStore := respond.NewStore(st.Pool())
	responder := resolveResponder(ctx, intStore)
	var engine *respond.Engine
	if responder != nil {
		autoApprove, _ := strconv.ParseBool(os.Getenv("RESPONSE_AUTO_APPROVE"))
		policy, perr := respStore.LoadPolicy(ctx)
		if perr != nil {
			log.Printf("worker: load ban policy: %v", perr)
		}
		engine = respond.NewEngine(respStore, responder, policy, autoApprove)
		if nets, werr := respStore.WhitelistNets(ctx); werr != nil {
			log.Printf("worker: load IP whitelist: %v", werr)
		} else {
			engine.SetWhitelist(nets)
			log.Printf("worker: IP whitelist loaded (%d entries)", len(nets))
		}
		log.Printf("worker: response engine active (responder=%s, auto_approve=%v)", responder.Name(), autoApprove)
	} else {
		log.Printf("worker: response engine disabled (RESPONDER=none)")
	}

	// Network containment engine (host isolation): isolates a compromised agent host from the
	// LAN except the manager. Works even when the IP-ban responder is nil (host self-isolation
	// is the primary control; the responder, when present, adds the best-effort edge block).
	// Auto-contain is gated by CONTAINMENT_AUTO=1 AND each rule's criticality_threshold.
	containAuto, _ := strconv.ParseBool(os.Getenv("CONTAINMENT_AUTO"))
	containEngine := respond.NewContainmentEngine(respStore, responder, containAuto)
	containEngine.SetAllowIPs(splitCSV(os.Getenv("DEUSWATCH_CONTAINMENT_ALLOW_IPS")))
	if nets := parseCIDRs(splitCSV(os.Getenv("DEUSWATCH_MANAGER_IPS"))); len(nets) > 0 {
		containEngine.SetManagerNets(nets)
	}
	log.Printf("worker: containment engine active (auto=%v, edge=%v)", containAuto, responder != nil)
	go runContainmentSweep(ctx, containEngine)

	// Blocklist sync: reconcile active blocks onto all sync-capable enforcers (MikroTik)
	// every RESPONSE_SYNC_INTERVAL - propagates bans/unbans to every router + self-heals.
	go runBlocklistSync(ctx, respStore, responder)

	// Composite threat scoring per source IP (Multi-Source Event Correlation) + optional
	// scenario ban when an IP's score crosses SCENARIO_BAN_SCORE.
	go runIPScorer(ctx, st, engine)

	// Suspicious-IP watchlist: long-window behavioral detection of low-and-slow reconnaissance
	// (independent of CTI/WAF), for the dashboard + the AI report.
	go runSuspiciousScorer(ctx, st)

	// Slow-scanner watchlist: the multi-DAY view — sources that keep coming back at a volume too
	// low for any burst rule (2 probes today, none tomorrow, 5 the day after).
	go runSlowScanScorer(ctx, st)

	// OpenSearch/Elasticsearch pull: tail each configured cluster index (e.g. the Wazuh
	// indexer) into the pipeline. No-op when no such integration is enabled.
	go runESPull(ctx, intStore, b, st)

	// Native syslog listener (UDP+TCP): ingest logs from agentless devices (routers, firewalls,
	// appliances). Off unless SYSLOG_LISTEN is set (e.g. ":5514").
	if addr := strings.TrimSpace(os.Getenv("SYSLOG_LISTEN")); addr != "" {
		srv := syslogin.New(addr, b, os.Getenv("SYSLOG_DATASET"))
		go func() {
			if err := srv.Run(ctx); err != nil {
				log.Printf("worker: syslog listener disabled: %v", err)
			}
		}()
	}

	// Notifications (Phase 2): Telegram/email/webhook + dedup/throttle.
	dispatcher, notifyOn := notify.DispatcherFromEnv()
	if notifyOn {
		log.Printf("worker: notifications active (sinks=%v)", dispatcher.SinkNames())
	} else {
		log.Printf("worker: notifications disabled (set TELEGRAM_*/WEBHOOK_URL/SMTP_* to enable)")
	}

	onAlert := makeAlertHook(engine, containEngine, dispatcher)

	// Remediation playbooks (design doc section 9): each alert is stamped with the
	// remediation steps for its label before it is stored. Live-reloaded on UI edits.
	pbStore := playbooks.NewStore(st.Pool())
	pbLive := playbooks.NewLive()
	if err := pbLive.Reload(ctx, pbStore); err != nil {
		log.Printf("worker: load playbooks: %v", err)
	}
	log.Printf("worker: %d remediation playbooks loaded", pbLive.Len())

	// Live-reload rules + ban policy + playbooks from the DB so UI edits take effect
	// without a restart.
	go reloadConfig(ctx, ruleStore, sigmaDet, aggRunner, engine, respStore, pbStore, pbLive)

	// Trusted-session gate: a plain file-change alert (e.g. index.php edited) is treated as an
	// official change - and suppressed - when the host had a recent successful login from a
	// whitelisted admin/deploy IP. Alerts that authorize containment (e.g. a webshell in an
	// uploads dir) are NEVER gated, so genuine backdoors still fire. Window: env
	// FILE_CHANGE_TRUSTED_WINDOW (default 15m). Inert when the IP whitelist is empty.
	fileGate := makeTrustedSessionGate(st, engine, trustedWindowFromEnv())

	stop, err := b.Consume(ctx, bus.StreamLogs, "detect", bus.SubjectLogsNormalized,
		worker.Handler(ctx, st, enricher, onAlert, fileGate, pbLive.Annotate, bruteForce, sigmaDet))
	if err != nil {
		log.Fatalf("worker: consume: %v", err)
	}
	defer stop()

	// Raw daily archive: a second consumer appends every event's original line to
	// <ARCHIVE_DIR>/<source>/<dataset>/<date>.log.zst. Off unless ARCHIVE_DIR is set.
	if dir := strings.TrimSpace(os.Getenv("ARCHIVE_DIR")); dir != "" {
		retDays, _ := strconv.Atoi(os.Getenv("ARCHIVE_RETENTION_DAYS"))
		if arc, aerr := archive.New(dir, durEnv("ARCHIVE_FLUSH", 10*time.Second), retDays); aerr != nil {
			log.Printf("worker: raw archive disabled: %v", aerr)
		} else {
			go arc.Run(ctx)
			aStop, cerr := b.Consume(ctx, bus.StreamLogs, "archive", bus.SubjectLogsNormalized, archiveHandler(arc))
			if cerr != nil {
				log.Printf("worker: raw archive consumer: %v", cerr)
			} else {
				defer aStop()
				log.Printf("worker: raw archive active (%s, retention=%dd)", dir, retDays)
			}
		}
	}

	// ClickHouse analytics sink: a consumer streams every event into a ClickHouse table for
	// large-scale columnar analytics (TimescaleDB stays the operational store). Off unless
	// CLICKHOUSE_URL is set.
	if chCfg, chOn := clickhouse.ConfigFromEnv(os.Getenv); chOn {
		sink := clickhouse.New(chCfg)
		if serr := sink.EnsureSchema(ctx); serr != nil {
			log.Printf("worker: clickhouse sink disabled (schema init failed): %v", serr)
		} else {
			go sink.Run(ctx)
			chStop, cerr := b.Consume(ctx, bus.StreamLogs, "clickhouse", bus.SubjectLogsNormalized, clickhouseHandler(sink))
			if cerr != nil {
				log.Printf("worker: clickhouse consumer: %v", cerr)
			} else {
				defer chStop()
				log.Printf("worker: clickhouse analytics sink active (%s db=%s table=%s)", chCfg.URL, chCfg.Database, chCfg.Table)
			}
		}
	}

	if aggRunner.RuleCount() > 0 {
		go runAggregation(ctx, aggRunner, st, onAlert, pbLive.Annotate)
	}

	// LLM worker (Phase 3): the analyzer powers report summaries (cost-controlled) and,
	// only when explicitly enabled, continuous per-alert triage. Per-alert triage is OFF
	// by default (LLM_PER_ALERT=1 to enable) so a paid API isn't called on every alert —
	// AI is primarily a periodic/on-demand report (see the Report page + scheduler).
	// The "Use for" dropdown on the LLM integration decides which model powers which task, so
	// triage and report analyzers are resolved independently (they may be the same model when
	// purpose=both, or two different models).
	// The triage & report analyzers live in swappable holders so a UI change to the LLM
	// integration (add/edit/disable, or flip its "Use for") takes effect within ~1 min WITHOUT
	// restarting the worker — runLLMReload re-resolves them on a timer, like the CTI reload.
	triageH, reportH := &analyzerHolder{}, &analyzerHolder{}
	if a, ok := resolveAnalyzer(ctx, intStore, "triage"); ok {
		triageH.set(a)
	}
	if a, ok := resolveAnalyzer(ctx, intStore, "report"); ok {
		reportH.set(a)
	}
	go runLLMReload(ctx, intStore, triageH, reportH)

	// Per-alert AI triage is OFF by default (cost control): it calls the LLM for every alert,
	// so it only runs when LLM_PER_ALERT=1. The report summaries (Report page + scheduled
	// delivery) work regardless of this flag.
	if perAlert, _ := strconv.ParseBool(os.Getenv("LLM_PER_ALERT")); perAlert {
		log.Printf("worker: LLM per-alert triage ENABLED (LLM_PER_ALERT=1); analyzer live-reloads from Integrations")
		go runLLM(ctx, st, triageH)
	} else {
		log.Printf("worker: LLM per-alert triage OFF by default (set LLM_PER_ALERT=1 to enable). AI report summaries still work on the Report page.")
	}
	// Scheduled AI report summaries — always running; a nil holder (no report LLM configured) is
	// a no-op until one is added.
	go runReportScheduler(ctx, st, reportH)

	// Notification config: live-reload the alert severity threshold + scheduled report
	// delivery to channels (Telegram/email). Runs even without an analyzer (plain report).
	go runNotifyScheduler(ctx, st, dispatcher, reportH)

	// Storage monitor: warn (Telegram/email) when the log DB approaches its budget.
	go runStorageMonitor(ctx, st, dispatcher)

	// Self-monitoring (design doc section 13): agent liveness checker (disconnect ->
	// HIGH selfhealth alert), the disk-watermark janitor (section 8), and the worker's
	// own /healthz + /readyz endpoints.
	go runAgentHealth(ctx, st, onAlert, pbLive.Annotate)
	go runDiskJanitor(ctx, st, onAlert, pbLive.Annotate)
	go serveHealth(ctx, st, b)

	// Live-reload the CTI provider AND its cache window (dedup TTL) so adding/editing an
	// AbuseIPDB/OTX integration in the UI takes effect without restarting the worker.
	go runCTIProviderReload(ctx, intStore, enricher, geoOn, splitCSV(os.Getenv("BLOCKLIST_URLS")), abuseKey, otxKey)

	log.Printf("DeusWatch worker (detect) ready — consuming %q", bus.SubjectLogsNormalized)
	<-ctx.Done()
	log.Println("worker: shutdown")
}

// makeAlertHook combines the response engine, containment engine + notification dispatcher
// into a single worker.AlertHook. containment is always evaluated (it self-gates on the rule's
// mitigation_action), so the hook is never nil.
func makeAlertHook(engine *respond.Engine, contain *respond.ContainmentEngine, dispatcher *notify.Dispatcher) worker.AlertHook {
	return func(ctx context.Context, alert *ingest.Event) {
		// Route by the entity_type decision-table (internal/respond/decision.go): each entity the
		// alert concerns is dispatched to the engine that owns its action. This is behaviour-
		// preserving — the engines self-gate on exactly what respond.Entities classifies — but it
		// makes the routing explicit and keeps it aligned with the policy the API/UI expose.
		//   external_ip → ban engine   host → containment engine   user/hash → alert-only (below)
		for _, ent := range respond.Entities(alert) {
			switch ent {
			case respond.EntityExternalIP:
				if engine != nil {
					if _, err := engine.Recommend(ctx, alert); err != nil {
						log.Printf("worker: response recommendation failed: %v", err)
					}
				}
			case respond.EntityHost:
				// Isolate the compromised host when a rule authorized it. Cheap for the common
				// case — Evaluate returns immediately unless the alert carries a containment directive.
				if contain != nil {
					if _, err := contain.Evaluate(ctx, alert); err != nil {
						log.Printf("worker: containment evaluation failed: %v", err)
					}
				}
			}
			// EntityUser / EntityHash are alert-only today — the notification dispatch below
			// carries their context; no automated enforcement action is taken.
		}
		if dispatcher.Enabled() {
			if err := dispatcher.Dispatch(ctx, notify.FromEvent(alert)); err != nil {
				log.Printf("worker: notification failed: %v", err)
			}
		}
	}
}

// trustedWindowFromEnv reads the correlation window for the trusted-session gate
// (FILE_CHANGE_TRUSTED_WINDOW, e.g. "15m", "1h"); default 15 minutes.
func trustedWindowFromEnv() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("FILE_CHANGE_TRUSTED_WINDOW")); err == nil && d > 0 {
		return d
	}
	return 15 * time.Minute
}

// makeTrustedSessionGate builds the AlertSuppressor. It suppresses a file-change alert when the
// reporting agent had a successful login from a whitelisted IP within `window` - an official
// change (deploy/content edit), not an attack. It never suppresses:
//   - non-file alerts (network attacks keep their own IP-whitelist handling), or
//   - alerts that authorize network containment (e.g. a webshell in an uploads dir), which are
//     unambiguous and must always fire.
//
// Returns nil (no gating) when there is no ban engine to hold the live whitelist.
func makeTrustedSessionGate(st *store.Store, engine *respond.Engine, window time.Duration) worker.AlertSuppressor {
	if engine == nil {
		return nil
	}
	return func(ctx context.Context, alert *ingest.Event) bool {
		if alert.File == nil || alert.File.Path == "" { // only plain file-change alerts
			return false
		}
		if alert.DeusWatch.Containment != nil { // webshell/containment rules are never gated
			return false
		}
		if alert.Agent == nil || alert.Agent.ID == "" {
			return false // no host identity to correlate a session against
		}
		ips, err := st.RecentAuthSuccessIPs(ctx, alert.Agent.ID, time.Now().Add(-window))
		if err != nil {
			return false // fail open: on a query error, keep the alert
		}
		for _, ip := range ips {
			if engine.Whitelisted(ip) {
				return true // official change: a trusted admin/deploy session is present
			}
		}
		return false
	}
}

// runContainmentSweep auto-releases contained hosts whose timeout has elapsed.
func runContainmentSweep(ctx context.Context, engine *respond.ContainmentEngine) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sc, cancel := context.WithTimeout(ctx, 20*time.Second)
			if n, err := engine.SweepExpired(sc); err != nil {
				log.Printf("worker: containment sweep: %v", err)
			} else if n > 0 {
				log.Printf("worker: auto-released %d expired containment(s)", n)
			}
			cancel()
		}
	}
}

// parseCIDRs parses IPs/CIDRs into networks, skipping invalid entries (bare IPs become /32|/128).
func parseCIDRs(items []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, s := range items {
		norm, err := respond.NormalizeCIDR(s)
		if err != nil {
			continue
		}
		if _, n, err := net.ParseCIDR(norm); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// runAggregation runs the aggregation runner every aggInterval, storing fired alerts.
// Stops when ctx is cancelled.
func runAggregation(ctx context.Context, runner *detect.AggregateRunner, sink interface {
	InsertEvent(context.Context, *ingest.Event) error
}, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {
	t := time.NewTicker(aggInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rc, cancel := context.WithTimeout(ctx, 10*time.Second)
			alerts, err := runner.RunOnce(rc, time.Now())
			if err != nil {
				log.Printf("worker: aggregation: %v", err)
			}
			for _, a := range alerts {
				if annotate != nil {
					annotate(a)
				}
				if err := sink.InsertEvent(rc, a); err != nil {
					log.Printf("worker: store aggregation alert: %v", err)
					continue
				}
				log.Printf("worker: ALERT(agg) %s rule=%s group=%s",
					a.DeusWatch.Label, a.Rule.ID, aggGroup(a))
				if onAlert != nil {
					onAlert(rc, a)
				}
			}
			cancel()
		}
	}
}

// runCTIProviderReload re-resolves the AbuseIPDB/OTX keys AND the cache window (dedup TTL)
// from the Integrations registry every minute, rebuilding the CTI provider when the keys
// change and applying the TTL when it changes, so adding/editing a CTI integration in the UI
// takes effect without a worker restart. GeoIP/blocklist stay from env (restart).
func runCTIProviderReload(ctx context.Context, intStore *integrations.Store, enricher *enrich.Enricher, geoOn bool, blURLs []string, abuseKey, otxKey string) {
	sig := abuseKey + "|" + otxKey
	ttlSig := resolveCTITTL(ctx, intStore)
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ttl := resolveCTITTL(ctx, intStore); ttl != ttlSig {
				ttlSig = ttl
				enricher.SetTTL(ttl)
				log.Printf("worker: CTI cache window reloaded from UI change (%s)", ttl)
			}
			ak, ox := resolveCTIKeys(ctx, intStore)
			if ak+"|"+ox == sig {
				continue
			}
			sig = ak + "|" + ox
			provider, real := enrich.BuildProvider(ak, ox, geoOn, blURLs)
			enricher.SetProvider(provider)
			log.Printf("worker: CTI provider reloaded from UI change (real=%v abuseipdb=%v otx=%v)", real, ak != "", ox != "")
		}
	}
}

// resolveCTITTL reads the CTI cache dedup window (hours) from the enabled CTI integrations,
// with AbuseIPDB taking precedence over OTX, falling back to 24h. The window now lives on the
// CTI integration config ("cache_ttl_hours"), not a separate Settings section.
func resolveCTITTL(ctx context.Context, intStore *integrations.Store) time.Duration {
	const def = 24 * time.Hour
	if intStore == nil {
		return def
	}
	pick := func(typ string) (time.Duration, bool) {
		rows, err := intStore.Resolve(ctx, typ)
		if err != nil || len(rows) == 0 {
			return 0, false
		}
		v := strings.TrimSpace(rows[0].Config["cache_ttl_hours"])
		if n, aerr := strconv.Atoi(v); aerr == nil && n >= 1 && n <= 8760 {
			return time.Duration(n) * time.Hour, true
		}
		return 0, false
	}
	if d, ok := pick("abuseipdb"); ok {
		return d
	}
	if d, ok := pick("otx"); ok {
		return d
	}
	return def
}

// runStorageMonitor checks log-DB size against STORAGE_BUDGET_GB hourly and sends one alert
// per day when usage crosses STORAGE_ALERT_PERCENT (default 85). Disabled if no budget set.
func runStorageMonitor(ctx context.Context, st *store.Store, dispatcher *notify.Dispatcher) {
	budgetGB, _ := strconv.ParseFloat(os.Getenv("STORAGE_BUDGET_GB"), 64)
	if budgetGB <= 0 {
		log.Printf("worker: storage monitor disabled (set STORAGE_BUDGET_GB to enable near-full alerts)")
		return
	}
	threshold := 85
	if v, err := strconv.Atoi(os.Getenv("STORAGE_ALERT_PERCENT")); err == nil && v > 0 && v <= 100 {
		threshold = v
	}
	budget := int64(budgetGB * 1024 * 1024 * 1024)
	log.Printf("worker: storage monitor active (budget=%.0fGB, alert at %d%%)", budgetGB, threshold)

	var lastAlert time.Time
	check := func() {
		s := st.StorageStatus(ctx, budget)
		if !s.Reachable || s.UsedPercent < threshold {
			return
		}
		if !dispatcher.Enabled() || time.Since(lastAlert) < 24*time.Hour {
			return
		}
		msg := fmt.Sprintf("Log storage at %d%% of the %.0f GB budget (%s used, %d events). "+
			"Old data is auto-dropped by the retention policy; raise STORAGE_BUDGET_GB or lower retention if this persists.",
			s.UsedPercent, budgetGB, s.DBSizePretty, s.EventsCount)
		if err := dispatcher.SendText(ctx, "DeusWatch storage alert", msg); err == nil {
			lastAlert = time.Now()
			log.Printf("worker: storage alert sent (%d%%)", s.UsedPercent)
		}
	}

	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	check() // once on startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

// runNotifyScheduler live-reloads the alert severity threshold into the dispatcher and
// delivers a scheduled report to the channels (Telegram/email) per notify_config —
// independent of the AI-summary schedule. Checks every minute; only sends when due.
func runNotifyScheduler(ctx context.Context, st *store.Store, dispatcher *notify.Dispatcher, reportH *analyzerHolder) {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			analyzer := reportH.get() // may be nil — the plain report is still delivered
			cfg, err := st.LoadNotifyConfig(ctx)
			if err != nil {
				continue
			}
			if dispatcher != nil {
				dispatcher.SetMinSeverity(ingest.Severity(cfg.MinSeverity)) // live threshold
			}
			if cfg.ReportIntervalHours <= 0 || dispatcher == nil || !dispatcher.Enabled() {
				continue // delivery disabled or no channel
			}
			if cfg.ReportLastSentAt != nil && time.Since(*cfg.ReportLastSentAt) < time.Duration(cfg.ReportIntervalHours)*time.Hour {
				continue // not due yet
			}
			rc, cancel := context.WithTimeout(ctx, 2*time.Minute)
			rep, berr := st.BuildReport(rc, cfg.ReportPeriodHours)
			if berr != nil {
				cancel()
				continue
			}
			body := report.RenderMarkdown(rep)
			if analyzer != nil {
				acfg, _ := st.LoadReportAIConfig(rc) // custom prompt template ("" = default)
				if s, serr := analyzer.Summarize(rc, acfg.SummaryPrompt, report.SummaryPrompt(rep)); serr == nil && s != "" {
					body = "AI summary:\n" + s + "\n\n" + body
				}
			}
			err = dispatcher.SendText(rc, fmt.Sprintf("DeusWatch report - last %dh", cfg.ReportPeriodHours), body)
			cancel()
			if err != nil {
				log.Printf("worker: scheduled report delivery failed: %v", err)
				continue
			}
			_ = st.MarkReportDelivered(ctx)
			log.Printf("worker: delivered scheduled report to channels (period=%dh, next in ~%dh)", cfg.ReportPeriodHours, cfg.ReportIntervalHours)
		}
	}
}

// reportDue decides whether the scheduled AI summary should run now.
//
// atHour < 0 keeps the classic drifting interval: fire once intervalHours have passed since the
// last summary. atHour 0..23 pins it to that hour of the day (server local time) — the run
// happens on the first tick inside that hour, and only if the previous summary is old enough
// that we're not repeating within the same window. Pure so the timing rules are testable.
func reportDue(now, lastAt time.Time, hasLast bool, intervalHours, atHour int) bool {
	if intervalHours <= 0 {
		return false // disabled
	}
	interval := time.Duration(intervalHours) * time.Hour
	if atHour < 0 || atHour > 23 {
		return !hasLast || now.Sub(lastAt) >= interval
	}
	if now.Hour() != atHour {
		return false // not the appointed hour
	}
	if !hasLast {
		return true
	}
	// Inside the right hour: don't fire twice in the same hour, and respect a multi-day
	// interval. The slack keeps a daily schedule from being skipped when the previous run
	// landed a few minutes late (e.g. 08:05 yesterday vs 08:00 today).
	minGap := interval - time.Hour
	if minGap < time.Hour {
		minGap = time.Hour
	}
	return now.Sub(lastAt) >= minGap
}

// runReportScheduler generates an AI report summary on the configured cadence
// (report_ai_config.interval_hours; 0 = disabled). It checks every 10 min and only
// generates when enough time has passed since the last stored summary, so it is cheap
// and survives restarts. The schedule is re-read each tick (live config).
func runReportScheduler(ctx context.Context, st *store.Store, holder *analyzerHolder) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			analyzer := holder.get()
			if analyzer == nil {
				continue // no report LLM configured (yet)
			}
			cfg, err := st.LoadReportAIConfig(ctx)
			if err != nil || cfg.IntervalHours <= 0 {
				continue // disabled
			}
			last, hasLast, _ := st.LatestReportSummary(ctx)
			var lastAt time.Time
			if hasLast {
				lastAt = last.GeneratedAt
			}
			if !reportDue(time.Now(), lastAt, hasLast, cfg.IntervalHours, cfg.AtHour) {
				continue
			}
			rc, cancel := context.WithTimeout(ctx, 2*time.Minute)
			rep, err := st.BuildReport(rc, cfg.PeriodHours)
			if err != nil {
				cancel()
				continue
			}
			summary, err := analyzer.Summarize(rc, cfg.SummaryPrompt, report.SummaryPrompt(rep))
			cancel()
			if err != nil {
				log.Printf("worker: scheduled report summary failed: %v", err)
				continue
			}
			if err := st.SaveReportSummary(ctx, cfg.PeriodHours, summary, analyzer.Name()); err != nil {
				log.Printf("worker: save scheduled summary: %v", err)
				continue
			}
			log.Printf("worker: scheduled AI report summary generated (period=%dh, next in ~%dh)", cfg.PeriodHours, cfg.IntervalHours)
		}
	}
}

// analyzerHolder holds the currently-resolved LLM analyzer for one task (triage or report),
// swappable at runtime so the worker's LLM consumers pick up UI integration changes live.
type analyzerHolder struct {
	mu sync.RWMutex
	a  llm.Analyzer
}

func (h *analyzerHolder) get() llm.Analyzer  { h.mu.RLock(); defer h.mu.RUnlock(); return h.a }
func (h *analyzerHolder) set(a llm.Analyzer) { h.mu.Lock(); h.a = a; h.mu.Unlock() }
func (h *analyzerHolder) name() string {
	if a := h.get(); a != nil {
		return a.Name()
	}
	return ""
}

// runLLMReload re-resolves the triage & report analyzers from the Integrations registry every
// minute and swaps them into their holders, so adding/editing/disabling the LLM integration in
// the UI takes effect without a worker restart (mirrors runCTIProviderReload).
func runLLMReload(ctx context.Context, intStore *integrations.Store, triageH, reportH *analyzerHolder) {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, r := range []struct {
				purpose string
				h       *analyzerHolder
			}{{"triage", triageH}, {"report", reportH}} {
				a, ok := resolveAnalyzer(ctx, intStore, r.purpose)
				var next llm.Analyzer
				if ok {
					next = a
				}
				was := r.h.name()
				now := ""
				if next != nil {
					now = next.Name()
				}
				if was != now {
					r.h.set(next)
					log.Printf("worker: LLM %s analyzer reloaded from UI change (%q -> %q)", r.purpose, was, now)
				}
			}
		}
	}
}

// runLLM polls alerts without an LLM verdict, then analyzes & stores the verdict. The analyzer
// is read from the holder each tick, so it live-reloads (and a nil holder is a no-op).
func runLLM(ctx context.Context, st *store.Store, holder *analyzerHolder) {
	t := time.NewTicker(llmInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			analyzer := holder.get()
			if analyzer == nil {
				continue // no triage LLM configured (yet)
			}
			rc, cancel := context.WithTimeout(ctx, 30*time.Second)
			alerts, err := st.AlertsForLLM(rc, 10)
			if err != nil {
				log.Printf("worker: fetch LLM alerts: %v", err)
				cancel()
				continue
			}
			for _, a := range alerts {
				res, err := analyzer.Analyze(rc, llm.AlertInput{
					Rule: a.RuleName, Severity: ingest.Severity(a.Severity), SourceIP: a.SourceIP,
					Technique: a.Technique, Tactic: a.Tactic, Label: a.Label, Original: a.Original,
					Country: a.Country, AbuseConfidence: a.AbuseConfidence, OTXPulseCount: a.OTXPulseCount,
				})
				if err != nil {
					log.Printf("worker: LLM analysis %s failed: %v", a.ID, err)
					continue
				}
				if err := st.SetLLMVerdict(rc, a.ID, string(res.Verdict), res.Summary); err != nil {
					log.Printf("worker: store LLM verdict %s: %v", a.ID, err)
					continue
				}
				log.Printf("worker: LLM %s -> %s", a.ID, res.Verdict)
			}
			cancel()
		}
	}
}

func aggGroup(a *ingest.Event) string {
	if a.Source != nil && a.Source.IP != "" {
		return a.Source.IP
	}
	if a.Host != nil && a.Host.Name != "" {
		return a.Host.Name
	}
	if a.User != nil && a.User.Name != "" {
		return a.User.Name
	}
	return "-"
}

// reloadConfig re-reads the enabled rules, ban policy and IP whitelist from the DB every
// 30s and swaps them into the live detectors/engine, so UI edits take effect without restarting.
func reloadConfig(ctx context.Context, store *rules.Store, det *detect.SigmaDetector, runner *detect.AggregateRunner, engine *respond.Engine, respStore *respond.Store, pbStore *playbooks.Store, pbLive *playbooks.Live) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if single, agg, err := store.Enabled(ctx); err != nil {
				log.Printf("worker: reload rules: %v", err)
			} else {
				det.SetRules(single)
				runner.SetRules(agg)
			}
			if err := pbLive.Reload(ctx, pbStore); err != nil {
				log.Printf("worker: reload playbooks: %v", err)
			}
			if engine != nil {
				if p, err := respStore.LoadPolicy(ctx); err != nil {
					log.Printf("worker: reload ban policy: %v", err)
				} else {
					engine.SetPolicy(p)
				}
				if nets, err := respStore.WhitelistNets(ctx); err != nil {
					log.Printf("worker: reload IP whitelist: %v", err)
				} else {
					engine.SetWhitelist(nets)
				}
			}
		}
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// resolveCTIKeys returns the AbuseIPDB & OTX keys, preferring enabled Integrations
// registry entries over the env vars.
func resolveCTIKeys(ctx context.Context, intStore *integrations.Store) (abuseKey, otxKey string) {
	abuseKey = os.Getenv("ABUSEIPDB_API_KEY")
	otxKey = os.Getenv("OTX_API_KEY")
	if intStore == nil {
		return
	}
	if rows, err := intStore.Resolve(ctx, "abuseipdb"); err == nil && len(rows) > 0 {
		if k := rows[0].Config["api_key"]; k != "" {
			abuseKey = k
		}
	}
	if rows, err := intStore.Resolve(ctx, "otx"); err == nil && len(rows) > 0 {
		if k := rows[0].Config["api_key"]; k != "" {
			otxKey = k
		}
	}
	return
}

// resolveAnalyzer builds the LLM analyzer for a given task ("triage" or "report") from the
// first enabled "llm" integration whose "Use for" purpose matches (triage | report | both),
// otherwise falls back to the env path. This lets a deployment point a small local model at
// per-alert triage while a stronger model writes report summaries (or use one for both).
func resolveAnalyzer(ctx context.Context, intStore *integrations.Store, purpose string) (llm.Analyzer, bool) {
	if intStore != nil {
		if rows, err := intStore.Resolve(ctx, "llm"); err == nil {
			for _, row := range rows {
				c := row.Config
				if !integrations.LLMPurposeMatches(c["purpose"], purpose) {
					continue
				}
				a, aerr := llm.NewAnalyzer(c["provider"], c["base_url"], c["api_key"], c["model"])
				if aerr == nil {
					log.Printf("worker: LLM %s analyzer from Integrations %q (%s)", purpose, row.Name, a.Name())
					return a, true
				}
				log.Printf("worker: LLM integration %q invalid: %v", row.Name, aerr)
			}
		}
	}
	return llm.AnalyzerFromEnv()
}

// resolveHashRep returns the VirusTotal key & whether CIRCL hashlookup is on for FIM
// file-hash reputation, preferring enabled Integrations entries over env vars
// (VIRUSTOTAL_API_KEY, CIRCL_HASHLOOKUP_ENABLED).
func resolveHashRep(ctx context.Context, intStore *integrations.Store) (vtKey, mbKey string, circlOn bool) {
	vtKey = os.Getenv("VIRUSTOTAL_API_KEY")
	mbKey = os.Getenv("MALWAREBAZAAR_API_KEY")
	circlOn, _ = strconv.ParseBool(os.Getenv("CIRCL_HASHLOOKUP_ENABLED"))
	if intStore == nil {
		return
	}
	if rows, err := intStore.Resolve(ctx, "virustotal"); err == nil && len(rows) > 0 {
		if k := rows[0].Config["api_key"]; k != "" {
			vtKey = k
		}
	}
	if rows, err := intStore.Resolve(ctx, "malwarebazaar"); err == nil && len(rows) > 0 {
		if k := rows[0].Config["api_key"]; k != "" {
			mbKey = k
		}
	}
	if rows, err := intStore.Resolve(ctx, "circl_hashlookup"); err == nil && len(rows) > 0 {
		circlOn = true
	}
	return
}

// resolveResponder builds the block responder from ALL enabled MikroTik integrations if
// present (fan-out to every router), otherwise falls back to the RESPONDER env selection.
func resolveResponder(ctx context.Context, intStore *integrations.Store) respond.Responder {
	if intStore != nil {
		if rows, err := intStore.Resolve(ctx, "mikrotik"); err == nil && len(rows) > 0 {
			cfgs := make([]respond.MikrotikConfig, 0, len(rows))
			names := make([]string, 0, len(rows))
			for _, row := range rows {
				c := row.Config
				insecure, _ := strconv.ParseBool(c["insecure_tls"])
				cfgs = append(cfgs, respond.MikrotikConfig{
					Address: c["address"], User: c["username"], Pass: c["password"],
					List: c["address_list"], Insecure: insecure,
				})
				names = append(names, row.Name)
			}
			log.Printf("worker: responder from %d Integrations MikroTik router(s): %s", len(cfgs), strings.Join(names, ", "))
			// Startup REST health-check per router: surfaces reachability/TLS/auth/list
			// problems in the log immediately, instead of a silent "bans never arrive".
			for i, c := range cfgs {
				list := c.List
				if list == "" {
					list = "deuswatch_ban"
				}
				probe := respond.NewMikrotikResponder(c.Address, c.User, c.Pass, c.List, c.Insecure)
				if err := probe.Verify(ctx); err != nil {
					log.Printf("worker: MikroTik %q REST check FAILED: %v", names[i], err)
				} else {
					log.Printf("worker: MikroTik %q REST check OK (list=%s reachable)", names[i], list)
				}
			}
			// A configured MikroTik that will never receive bans (dry-run) is the single most
			// confusing failure mode - call it out explicitly with the fix.
			if live, _ := strconv.ParseBool(os.Getenv("RESPONSE_LIVE")); !live {
				log.Printf("worker: NOTE - MikroTik is configured but RESPONSE_LIVE!=1: bans will NOT be pushed (dry-run). Set RESPONSE_LIVE=1 in deploy/.env and restart to go live.")
			}
			return respond.MikrotikMultiFromConfigs(cfgs)
		}
	}
	return respond.ResponderFromEnv()
}

// runBlocklistSync periodically reconciles DeusWatch's active blocks onto every enforcer
// that supports full-state sync (MikroTik). This is the CrowdSec-bouncer-like behaviour:
// a ban/unban in DeusWatch reaches all connected routers within one interval, and a router
// that rebooted (losing its address-list) is re-populated. No-op when the responder is
// dry-run or doesn't support sync (nftables/crowdsec use on-demand Block/Unblock instead).
func runBlocklistSync(ctx context.Context, respStore *respond.Store, responder respond.Responder) {
	syncer, ok := responder.(respond.Syncer)
	if !ok {
		return // dry-run or a non-syncing responder
	}
	interval := durEnv("RESPONSE_SYNC_INTERVAL", 10*time.Second)
	log.Printf("worker: blocklist sync active (reconcile every %s to %s)", interval, responder.Name())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sc, cancel := context.WithTimeout(ctx, 30*time.Second)
			desired, err := respStore.ActiveBlocks(sc)
			if err != nil {
				log.Printf("worker: blocklist sync: load active blocks: %v", err)
			} else if err := syncer.Sync(sc, desired); err != nil {
				log.Printf("worker: blocklist sync: %v", err)
			}
			cancel()
		}
	}
}

// archiveHandler appends each normalized event's RAW original (or the whole event JSON when
// there is no original — structured FIM/Windows events) to the per-source daily zstd archive.
// The source key is the agent/sender; the dataset groups by log type.
func archiveHandler(arc *archive.Archiver) bus.Handler {
	return func(_ string, data []byte) error {
		var ev ingest.Event
		if err := json.Unmarshal(data, &ev); err != nil {
			return nil // skip an unparseable message; never Nak (would redeliver forever)
		}
		source := "unknown"
		if ev.Agent != nil && ev.Agent.ID != "" {
			source = ev.Agent.ID
		} else if ev.Host != nil && ev.Host.Name != "" {
			source = ev.Host.Name
		}
		dataset := ev.Event.Dataset
		line := ev.Event.Original
		if line == "" {
			line = string(data) // no raw text (structured event) — archive the normalized JSON
		}
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		arc.Add(source, dataset, line, ts)
		return nil
	}
}

// clickhouseHandler flattens each normalized event into a row and buffers it for the batched
// ClickHouse insert. Parse failures are skipped (never Nak — that would redeliver forever).
func clickhouseHandler(sink *clickhouse.Sink) bus.Handler {
	return func(_ string, data []byte) error {
		var ev ingest.Event
		if err := json.Unmarshal(data, &ev); err != nil {
			return nil
		}
		sink.Add(context.Background(), &ev)
		return nil
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// runESPull tails every enabled OpenSearch/Elasticsearch pull integration into the pipeline,
// one goroutine per cluster. Each poller resumes from its persisted cursor and publishes
// normalized events to logs.normalized, exactly like an agent-shipped or webhook line.
func runESPull(ctx context.Context, intStore *integrations.Store, pub *bus.Bus, st *store.Store) {
	if intStore == nil {
		return
	}
	rows, err := intStore.Resolve(ctx, "opensearch")
	if err != nil {
		log.Printf("worker: es-pull: resolve integrations: %v", err)
		return
	}
	for _, row := range rows {
		c := row.Config
		if c["address"] == "" || c["index"] == "" {
			log.Printf("worker: es-pull %q skipped: address and index are required", row.Name)
			continue
		}
		insecure, _ := strconv.ParseBool(c["insecure_tls"])
		interval, _ := time.ParseDuration(strings.TrimSpace(c["poll_interval"]))
		cfg := espull.Config{
			Address: c["address"], Index: c["index"],
			Username: c["username"], Password: c["password"], APIKey: c["api_key"],
			TimestampField: c["timestamp_field"], Query: c["query"], Mode: c["mode"],
			Insecure: insecure, Interval: interval,
			AgentTag: "opensearch/" + row.Name,
		}
		go runOnePull(ctx, cfg, row.ID, row.Name, pub, st)
	}
}

// runOnePull drives one cluster poller on its interval, persisting the cursor after each batch.
func runOnePull(ctx context.Context, cfg espull.Config, id, name string, pub *bus.Bus, st *store.Store) {
	var cursor []json.RawMessage
	if raw, err := st.GetCursor(ctx, id); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &cursor)
	}
	poller := espull.New(cfg, cursor)
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	log.Printf("worker: es-pull %q active (%s%s every %s)", name, cfg.Address, indexLabel(cfg.Index), interval)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sc, cancel := context.WithTimeout(ctx, 30*time.Second)
			events, n, err := poller.Poll(sc)
			if err != nil {
				log.Printf("worker: es-pull %q: %v", name, err)
				cancel()
				continue
			}
			published := 0
			for _, ev := range events {
				data, merr := json.Marshal(ev)
				if merr != nil {
					continue
				}
				if perr := pub.Publish(sc, bus.SubjectLogsNormalized, data); perr != nil {
					log.Printf("worker: es-pull %q: publish: %v", name, perr)
					break
				}
				published++
			}
			// Persist the cursor only after a successful batch so a mid-batch failure re-pulls.
			if n > 0 {
				if cur := poller.Cursor(); len(cur) > 0 {
					if b, merr := json.Marshal(cur); merr == nil {
						if cerr := st.SetCursor(sc, id, string(b)); cerr != nil {
							log.Printf("worker: es-pull %q: save cursor: %v", name, cerr)
						}
					}
				}
				log.Printf("worker: es-pull %q: %d hits, %d published", name, n, published)
			}
			cancel()
		}
	}
}

func indexLabel(index string) string {
	if index == "" {
		return ""
	}
	return "/" + index
}
