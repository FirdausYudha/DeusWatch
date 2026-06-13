// Command worker menjalankan worker DeusWatch. Fase 1: mode deteksi (brute-force
// SSH). Mode lain (enrich/respond/llm) menyusul dan dipilih via flag.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"deuswatch/internal/bus"
	"deuswatch/internal/detect"
	"deuswatch/internal/enrich"
	"deuswatch/internal/store"
	"deuswatch/internal/worker"
)

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
	log.Printf("worker: %d rule Sigma dimuat dari %q", sigmaDet.RuleCount(), sigmaDir)

	// Enrichment CTI: cache TTL di Postgres + provider (mock untuk dev).
	enricher := enrich.NewEnricher(enrich.NewDemoProvider(), enrich.NewCache(st.Pool()), enrich.DefaultTTL)

	stop, err := b.Consume(ctx, bus.StreamLogs, "detect", bus.SubjectLogsNormalized,
		worker.Handler(ctx, st, enricher, bruteForce, sigmaDet))
	if err != nil {
		log.Fatalf("worker: consume: %v", err)
	}
	defer stop()

	log.Printf("DeusWatch worker (detect) siap — mengonsumsi %q", bus.SubjectLogsNormalized)
	<-ctx.Done()
	log.Println("worker: shutdown")
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
