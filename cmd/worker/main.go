// Command worker runs the DeusWatch worker. Phase 1: detection mode (SSH brute force).
// Other modes (enrich/respond/llm) are integrated and selected via env.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"deuswatch/internal/bus"
	"deuswatch/internal/detect"
	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/enrich"
	"deuswatch/internal/ingest"
	"deuswatch/internal/llm"
	"deuswatch/internal/notify"
	"deuswatch/internal/respond"
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

	bruteForce := detect.NewBruteForceDetector(detect.DefaultBruteForceConfig())

	sigmaDir := getenv("RULES_DIR", "rules/sigma")
	sigmaDet, err := detect.LoadSigmaDir(sigmaDir)
	if err != nil {
		log.Fatalf("worker: load Sigma rules from %q: %v", sigmaDir, err)
	}
	log.Printf("worker: %d single-event Sigma rules loaded from %q", sigmaDet.RuleCount(), sigmaDir)

	// Aggregation SQL path (Sigma | count() by ... > N) — ADR 0001.
	aggRules, err := sigma.LoadAggDir(sigmaDir)
	if err != nil {
		log.Fatalf("worker: load aggregation rules from %q: %v", sigmaDir, err)
	}
	aggRunner := detect.NewAggregateRunner(st, aggRules, 0)
	log.Printf("worker: %d aggregation Sigma rules loaded (SQL path)", aggRunner.RuleCount())

	// CTI enrichment: TTL cache in Postgres + real provider when configured
	// (ABUSEIPDB_API_KEY / OTX_API_KEY / GEOIP_ENABLED), otherwise mock for dev.
	provider, real := enrich.ProviderFromEnv()
	if real {
		log.Printf("worker: real CTI provider active")
	} else {
		log.Printf("worker: mock CTI provider (set ABUSEIPDB_API_KEY/OTX_API_KEY/GEOIP_ENABLED for real)")
	}
	enricher := enrich.NewEnricher(provider, enrich.NewCache(st.Pool()), enrich.DefaultTTL, enrich.EscalationFromEnv())

	// Response engine (Phase 2): block recommendations + approval + progressive ban.
	// The responder is selected via RESPONDER (default dry-run); RESPONSE_AUTO_APPROVE=1
	// executes without manual approval.
	var engine *respond.Engine
	if responder := respond.ResponderFromEnv(); responder != nil {
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

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
