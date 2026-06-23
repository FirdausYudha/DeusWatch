// Command worker runs the DeusWatch worker. Phase 1: detection mode (SSH brute force).
// Other modes (enrich/respond/llm) are integrated and selected via env.
package main

import (
	"context"
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
	"deuswatch/internal/ingest"
	"deuswatch/internal/integrations"
	"deuswatch/internal/llm"
	"deuswatch/internal/notify"
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

	// Live-reload rules from the DB so UI edits take effect without a restart.
	go reloadRules(ctx, ruleStore, sigmaDet, aggRunner)

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
	enricher := enrich.NewEnricher(provider, enrich.NewCache(st.Pool()), enrich.DefaultTTL, enrich.EscalationFromEnv())

	// Response engine (Phase 2): block recommendations + approval + progressive ban.
	// The responder comes from the Integrations registry (MikroTik) first, else RESPONDER env
	// (dry-run unless RESPONSE_LIVE=1). RESPONSE_AUTO_APPROVE=1 executes without manual approval.
	var engine *respond.Engine
	if responder := resolveResponder(ctx, intStore); responder != nil {
		autoApprove, _ := strconv.ParseBool(os.Getenv("RESPONSE_AUTO_APPROVE"))
		engine = respond.NewEngine(respond.NewStore(st.Pool()), responder, respond.DefaultBanPolicy(), autoApprove)
		log.Printf("worker: response engine active (responder=%s, auto_approve=%v)", responder.Name(), autoApprove)
	} else {
		log.Printf("worker: response engine disabled (RESPONDER=none)")
	}

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

	// LLM worker (Phase 3): triage alerts -> verdict + summary (deuswatch.llm.*).
	if analyzer, ok := llm.AnalyzerFromEnv(); ok {
		log.Printf("worker: LLM analyzer active (%s)", analyzer.Name())
		go runLLM(ctx, st, analyzer)
	} else {
		log.Printf("worker: LLM analyzer disabled (set ANTHROPIC_API_KEY or LLM_ENABLED=1)")
	}

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

// reloadRules re-reads the enabled rules from the DB every 30s and swaps them into the
// live detectors, so rule edits in the UI take effect without restarting the worker.
func reloadRules(ctx context.Context, store *rules.Store, det *detect.SigmaDetector, runner *detect.AggregateRunner) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			single, agg, err := store.Enabled(ctx)
			if err != nil {
				log.Printf("worker: reload rules: %v", err)
				continue
			}
			det.SetRules(single)
			runner.SetRules(agg)
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
