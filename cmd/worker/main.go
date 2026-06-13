// Command worker menjalankan worker DeusWatch. Fase 1: mode deteksi (brute-force
// SSH). Mode lain (enrich/respond/llm) menyusul dan dipilih via flag.
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

// aggInterval: seberapa sering runner agregasi (jalur SQL Sigma) memindai events.
const aggInterval = 30 * time.Second

// llmInterval: seberapa sering worker LLM menganalisis alert yang belum bervonis.
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
		log.Fatalf("worker: muat rule Sigma dari %q: %v", sigmaDir, err)
	}
	log.Printf("worker: %d rule Sigma single-event dimuat dari %q", sigmaDet.RuleCount(), sigmaDir)

	// Jalur SQL agregasi (Sigma | count() by ... > N) — ADR 0001.
	aggRules, err := sigma.LoadAggDir(sigmaDir)
	if err != nil {
		log.Fatalf("worker: muat rule agregasi dari %q: %v", sigmaDir, err)
	}
	aggRunner := detect.NewAggregateRunner(st, aggRules, 0)
	log.Printf("worker: %d rule Sigma agregasi dimuat (jalur SQL)", aggRunner.RuleCount())

	// Enrichment CTI: cache TTL di Postgres + provider nyata bila dikonfigurasi
	// (ABUSEIPDB_API_KEY / OTX_API_KEY / GEOIP_ENABLED), selain itu mock untuk dev.
	provider, real := enrich.ProviderFromEnv()
	if real {
		log.Printf("worker: provider CTI nyata aktif")
	} else {
		log.Printf("worker: provider CTI mock (set ABUSEIPDB_API_KEY/OTX_API_KEY/GEOIP_ENABLED untuk nyata)")
	}
	enricher := enrich.NewEnricher(provider, enrich.NewCache(st.Pool()), enrich.DefaultTTL, enrich.EscalationFromEnv())

	// Response engine (Fase 2): rekomendasi blokir + approval + ban progresif.
	// Responder dipilih via RESPONDER (default dry-run); RESPONSE_AUTO_APPROVE=1
	// mengeksekusi tanpa approval manual.
	var engine *respond.Engine
	if responder := respond.ResponderFromEnv(); responder != nil {
		autoApprove, _ := strconv.ParseBool(os.Getenv("RESPONSE_AUTO_APPROVE"))
		engine = respond.NewEngine(respond.NewStore(st.Pool()), responder, respond.DefaultBanPolicy(), autoApprove)
		log.Printf("worker: response engine aktif (responder=%s, auto_approve=%v)", responder.Name(), autoApprove)
	} else {
		log.Printf("worker: response engine nonaktif (RESPONDER=none)")
	}

	// Notifikasi (Fase 2): Telegram/email/webhook + dedup/throttle.
	dispatcher, notifyOn := notify.DispatcherFromEnv()
	if notifyOn {
		log.Printf("worker: notifikasi aktif (sinks=%v)", dispatcher.SinkNames())
	} else {
		log.Printf("worker: notifikasi nonaktif (set TELEGRAM_*/WEBHOOK_URL/SMTP_* untuk aktif)")
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

	// Worker LLM (Fase 3): triase alert -> vonis + ringkasan (deuswatch.llm.*).
	if analyzer, ok := llm.AnalyzerFromEnv(); ok {
		log.Printf("worker: LLM analyzer aktif (%s)", analyzer.Name())
		go runLLM(ctx, st, analyzer)
	} else {
		log.Printf("worker: LLM analyzer nonaktif (set ANTHROPIC_API_KEY atau LLM_ENABLED=1)")
	}

	log.Printf("DeusWatch worker (detect) siap — mengonsumsi %q", bus.SubjectLogsNormalized)
	<-ctx.Done()
	log.Println("worker: shutdown")
}

// runAggregation menjalankan runner agregasi tiap aggInterval, menyimpan alert
// yang terpicu. Berhenti saat ctx dibatalkan.
// makeAlertHook menggabungkan response engine + dispatcher notifikasi menjadi satu
// worker.AlertHook (nil bila keduanya nonaktif).
func makeAlertHook(engine *respond.Engine, dispatcher *notify.Dispatcher) worker.AlertHook {
	if engine == nil && !dispatcher.Enabled() {
		return nil
	}
	return func(ctx context.Context, alert *ingest.Event) {
		if engine != nil {
			if _, err := engine.Recommend(ctx, alert); err != nil {
				log.Printf("worker: rekomendasi respons gagal: %v", err)
			}
		}
		if dispatcher.Enabled() {
			if err := dispatcher.Dispatch(ctx, notify.FromEvent(alert)); err != nil {
				log.Printf("worker: notifikasi gagal: %v", err)
			}
		}
	}
}

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
				log.Printf("worker: agregasi: %v", err)
			}
			for _, a := range alerts {
				if err := sink.InsertEvent(rc, a); err != nil {
					log.Printf("worker: simpan alert agregasi: %v", err)
					continue
				}
				log.Printf("worker: ALERT(agg) %s rule=%s grup=%s",
					a.DeusWatch.Label, a.Rule.ID, aggGroup(a))
				if onAlert != nil {
					onAlert(rc, a)
				}
			}
			cancel()
		}
	}
}

// runLLM mem-poll alert tanpa vonis LLM lalu menganalisis & menyimpan vonisnya.
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
				log.Printf("worker: ambil alert LLM: %v", err)
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
					log.Printf("worker: analisis LLM %s gagal: %v", a.ID, err)
					continue
				}
				if err := st.SetLLMVerdict(rc, a.ID, string(res.Verdict), res.Summary); err != nil {
					log.Printf("worker: simpan vonis LLM %s: %v", a.ID, err)
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
