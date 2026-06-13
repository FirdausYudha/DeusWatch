// Command worker menjalankan worker DeusWatch. Fase 1: mode deteksi (brute-force
// SSH). Mode lain (enrich/respond/llm) menyusul dan dipilih via flag.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"deuswatch/internal/bus"
	"deuswatch/internal/detect"
	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/enrich"
	"deuswatch/internal/ingest"
	"deuswatch/internal/store"
	"deuswatch/internal/worker"
)

// aggInterval: seberapa sering runner agregasi (jalur SQL Sigma) memindai events.
const aggInterval = 30 * time.Second

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

	// Enrichment CTI: cache TTL di Postgres + provider (mock untuk dev).
	enricher := enrich.NewEnricher(enrich.NewDemoProvider(), enrich.NewCache(st.Pool()), enrich.DefaultTTL)

	stop, err := b.Consume(ctx, bus.StreamLogs, "detect", bus.SubjectLogsNormalized,
		worker.Handler(ctx, st, enricher, bruteForce, sigmaDet))
	if err != nil {
		log.Fatalf("worker: consume: %v", err)
	}
	defer stop()

	if aggRunner.RuleCount() > 0 {
		go runAggregation(ctx, aggRunner, st)
	}

	log.Printf("DeusWatch worker (detect) siap — mengonsumsi %q", bus.SubjectLogsNormalized)
	<-ctx.Done()
	log.Println("worker: shutdown")
}

// runAggregation menjalankan runner agregasi tiap aggInterval, menyimpan alert
// yang terpicu. Berhenti saat ctx dibatalkan.
func runAggregation(ctx context.Context, runner *detect.AggregateRunner, sink interface {
	InsertEvent(context.Context, *ingest.Event) error
}) {
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
