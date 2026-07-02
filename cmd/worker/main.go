// Command worker runs the DeusWatch worker. Phase 1: detection mode (SSH brute force).
// Other modes (enrich/respond/llm) are integrated and selected via env.
package main

import (
	"context"
	"fmt"
	"log"
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
	ctiTTL := 24 * time.Hour // dedup window; UI-managed via cti_config (Settings)
	if c, err := st.LoadCTIConfig(ctx); err == nil {
		ctiTTL = c.TTL()
	}
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
	var engine *respond.Engine
	if responder := resolveResponder(ctx, intStore); responder != nil {
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

	// Live-reload rules + ban policy from the DB so UI edits take effect without a restart.
	go reloadConfig(ctx, ruleStore, sigmaDet, aggRunner, engine, respStore)

	// Notifications (Phase 2): Telegram/email/webhook + dedup/throttle.
	dispatcher, notifyOn := notify.DispatcherFromEnv()
	if notifyOn {
		log.Printf("worker: notifications active (sinks=%v)", dispatcher.SinkNames())
	} else {
		log.Printf("worker: notifications disabled (set TELEGRAM_*/WEBHOOK_URL/SMTP_* to enable)")
	}

	onAlert := makeAlertHook(engine, dispatcher)

	stop, err := b.Consume(ctx, bus.StreamLogs, "detect", bus.SubjectLogsNormalized,
		worker.Handler(ctx, st, enricher, onAlert, bruteForce, sigmaDet))
	if err != nil {
		log.Fatalf("worker: consume: %v", err)
	}
	defer stop()

	if aggRunner.RuleCount() > 0 {
		go runAggregation(ctx, aggRunner, st, onAlert)
	}

	// LLM worker (Phase 3): the analyzer powers report summaries (cost-controlled) and,
	// only when explicitly enabled, continuous per-alert triage. Per-alert triage is OFF
	// by default (LLM_PER_ALERT=1 to enable) so a paid API isn't called on every alert —
	// AI is primarily a periodic/on-demand report (see the Report page + scheduler).
	analyzer, haveAnalyzer := resolveAnalyzer(ctx, intStore)
	if haveAnalyzer {
		perAlert, _ := strconv.ParseBool(os.Getenv("LLM_PER_ALERT"))
		if perAlert {
			log.Printf("worker: LLM per-alert triage active (%s)", analyzer.Name())
			go runLLM(ctx, st, analyzer)
		} else {
			log.Printf("worker: LLM analyzer ready for reports (%s); per-alert triage off (set LLM_PER_ALERT=1 to enable)", analyzer.Name())
		}
		go runReportScheduler(ctx, st, analyzer) // configurable AI report summaries
	} else {
		log.Printf("worker: LLM analyzer disabled (add an LLM integration, or set ANTHROPIC_API_KEY / LLM_BASE_URL / LLM_ENABLED=1)")
		analyzer = nil
	}

	// Notification config: live-reload the alert severity threshold + scheduled report
	// delivery to channels (Telegram/email). Runs even without an analyzer (plain report).
	go runNotifyScheduler(ctx, st, dispatcher, analyzer)

	// Storage monitor: warn (Telegram/email) when the log DB approaches its budget.
	go runStorageMonitor(ctx, st, dispatcher)

	// Live-reload the CTI cache TTL (dedup window) from the UI-managed config.
	go runCTIConfigReload(ctx, st, enricher)

	// Live-reload the CTI provider so adding an AbuseIPDB/OTX integration in the UI takes
	// effect without restarting the worker.
	go runCTIProviderReload(ctx, intStore, enricher, geoOn, splitCSV(os.Getenv("BLOCKLIST_URLS")), abuseKey, otxKey)

	log.Printf("DeusWatch worker (detect) ready — consuming %q", bus.SubjectLogsNormalized)
	<-ctx.Done()
	log.Println("worker: shutdown")
}

// makeAlertHook combines the response engine + notification dispatcher into a single
// worker.AlertHook (nil if both are disabled).
func makeAlertHook(engine *respond.Engine, dispatcher *notify.Dispatcher) worker.AlertHook {
	if engine == nil && !dispatcher.Enabled() {
		return nil
	}
	return func(ctx context.Context, alert *ingest.Event) {
		if engine != nil {
			if _, err := engine.Recommend(ctx, alert); err != nil {
				log.Printf("worker: response recommendation failed: %v", err)
			}
		}
		if dispatcher.Enabled() {
			if err := dispatcher.Dispatch(ctx, notify.FromEvent(alert)); err != nil {
				log.Printf("worker: notification failed: %v", err)
			}
		}
	}
}

// runAggregation runs the aggregation runner every aggInterval, storing fired alerts.
// Stops when ctx is cancelled.
func runAggregation(ctx context.Context, runner *detect.AggregateRunner, sink interface {
	InsertEvent(context.Context, *ingest.Event) error
}, onAlert worker.AlertHook) {
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

// runCTIProviderReload re-resolves the AbuseIPDB/OTX keys from the Integrations registry
// every minute and rebuilds the CTI provider when they change, so a key added in the UI
// activates real lookups without a worker restart. GeoIP/blocklist stay from env (restart).
func runCTIProviderReload(ctx context.Context, intStore *integrations.Store, enricher *enrich.Enricher, geoOn bool, blURLs []string, abuseKey, otxKey string) {
	sig := abuseKey + "|" + otxKey
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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

// runCTIConfigReload applies UI changes to the CTI cache TTL (dedup window) without a
// restart, checking every minute.
func runCTIConfigReload(ctx context.Context, st *store.Store, enricher *enrich.Enricher) {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if c, err := st.LoadCTIConfig(ctx); err == nil {
				enricher.SetTTL(c.TTL())
			}
		}
	}
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
func reloadConfig(ctx context.Context, store *rules.Store, det *detect.SigmaDetector, runner *detect.AggregateRunner, engine *respond.Engine, respStore *respond.Store) {
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

// resolveAnalyzer builds the LLM analyzer from an enabled "llm" integration if present
// (UI-configured: provider/base_url/model/api_key), otherwise falls back to the env path.
func resolveAnalyzer(ctx context.Context, intStore *integrations.Store) (llm.Analyzer, bool) {
	if intStore != nil {
		if rows, err := intStore.Resolve(ctx, "llm"); err == nil && len(rows) > 0 {
			c := rows[0].Config
			if a, aerr := llm.NewAnalyzer(c["provider"], c["base_url"], c["api_key"], c["model"]); aerr == nil {
				log.Printf("worker: LLM analyzer from Integrations %q", rows[0].Name)
				return a, true
			} else {
				log.Printf("worker: LLM integration invalid, falling back to env: %v", aerr)
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

// resolveResponder builds the block responder from an enabled MikroTik integration if
// present, otherwise falls back to the RESPONDER env selection.
func resolveResponder(ctx context.Context, intStore *integrations.Store) respond.Responder {
	if intStore != nil {
		if rows, err := intStore.Resolve(ctx, "mikrotik"); err == nil && len(rows) > 0 {
			c := rows[0].Config
			log.Printf("worker: responder from Integrations MikroTik %q", rows[0].Name)
			return respond.MikrotikResponderFromConfig(c["address"], c["username"], c["password"], c["address_list"])
		}
	}
	return respond.ResponderFromEnv()
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
