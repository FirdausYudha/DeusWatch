// Command worker runs the DeusWatch worker. Phase 1: detection mode (SSH brute force).
// Other modes (enrich/respond/llm) are integrated and selected via env.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"deuswatch/internal/bus"
	"deuswatch/internal/detect"
	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/enrich"
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
	vtKey, circlOn := resolveHashRep(ctx, intStore)
	if hp, hok := hashrep.BuildProvider(vtKey, circlOn); hok {
		enricher.SetHashReputation(hp, hashrep.NewCache(st.Pool()), ctiTTL)
		log.Printf("worker: FIM hash reputation active (virustotal=%v, circl=%v)", vtKey != "", circlOn)
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
	triageAnalyzer, haveTriage := resolveAnalyzer(ctx, intStore, "triage")
	reportAnalyzer, haveReport := resolveAnalyzer(ctx, intStore, "report")
	if haveTriage {
		perAlert, _ := strconv.ParseBool(os.Getenv("LLM_PER_ALERT"))
		if perAlert {
			log.Printf("worker: LLM per-alert triage active (%s)", triageAnalyzer.Name())
			go runLLM(ctx, st, triageAnalyzer)
		} else {
			log.Printf("worker: LLM triage analyzer ready (%s); per-alert triage off (set LLM_PER_ALERT=1 to enable)", triageAnalyzer.Name())
		}
	} else {
		log.Printf("worker: LLM triage disabled (add an LLM integration set to triage/both, or set ANTHROPIC_API_KEY / LLM_BASE_URL / LLM_ENABLED=1)")
	}
	if haveReport {
		log.Printf("worker: LLM report analyzer ready (%s)", reportAnalyzer.Name())
		go runReportScheduler(ctx, st, reportAnalyzer) // configurable AI report summaries
	} else {
		reportAnalyzer = nil
		log.Printf("worker: LLM report summaries disabled (add an LLM integration set to report/both)")
	}

	// Notification config: live-reload the alert severity threshold + scheduled report
	// delivery to channels (Telegram/email). Runs even without an analyzer (plain report).
	go runNotifyScheduler(ctx, st, dispatcher, reportAnalyzer)

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
		if engine != nil {
			if _, err := engine.Recommend(ctx, alert); err != nil {
				log.Printf("worker: response recommendation failed: %v", err)
			}
		}
		// Host containment: isolate the compromised host when a rule authorized it. Cheap for
		// the common case — returns immediately unless the alert carries a containment directive.
		if contain != nil {
			if _, err := contain.Evaluate(ctx, alert); err != nil {
				log.Printf("worker: containment evaluation failed: %v", err)
			}
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
func runNotifyScheduler(ctx context.Context, st *store.Store, dispatcher *notify.Dispatcher, analyzer llm.Analyzer) {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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

// runReportScheduler generates an AI report summary on the configured cadence
// (report_ai_config.interval_hours; 0 = disabled). It checks every 10 min and only
// generates when enough time has passed since the last stored summary, so it is cheap
// and survives restarts. The schedule is re-read each tick (live config).
func runReportScheduler(ctx context.Context, st *store.Store, analyzer llm.Analyzer) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cfg, err := st.LoadReportAIConfig(ctx)
			if err != nil || cfg.IntervalHours <= 0 {
				continue // disabled
			}
			if last, ok, _ := st.LatestReportSummary(ctx); ok &&
				time.Since(last.GeneratedAt) < time.Duration(cfg.IntervalHours)*time.Hour {
				continue // not due yet
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

// runLLM polls alerts without an LLM verdict, then analyzes & stores the verdict.
func runLLM(ctx context.Context, st *store.Store, analyzer llm.Analyzer) {
	t := time.NewTicker(llmInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
func resolveHashRep(ctx context.Context, intStore *integrations.Store) (vtKey string, circlOn bool) {
	vtKey = os.Getenv("VIRUSTOTAL_API_KEY")
	circlOn, _ = strconv.ParseBool(os.Getenv("CIRCL_HASHLOOKUP_ENABLED"))
	if intStore == nil {
		return
	}
	if rows, err := intStore.Resolve(ctx, "virustotal"); err == nil && len(rows) > 0 {
		if k := rows[0].Config["api_key"]; k != "" {
			vtKey = k
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
				cfgs = append(cfgs, respond.MikrotikConfig{
					Address: c["address"], User: c["username"], Pass: c["password"], List: c["address_list"],
				})
				names = append(names, row.Name)
			}
			log.Printf("worker: responder from %d Integrations MikroTik router(s): %s", len(cfgs), strings.Join(names, ", "))
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

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
