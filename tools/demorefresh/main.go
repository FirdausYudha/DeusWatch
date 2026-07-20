// Command demorefresh recomputes the derived score tables the dashboard reads (IP scores and the
// slow-scanner watchlist) against whatever is currently in the events table.
//
// The worker does this on a timer in a running stack; this is the same code path, run once, for
// populating a demo database without waiting for a worker tick.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"deuswatch/internal/score"
	"deuswatch/internal/store"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	st, err := store.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer st.Close()

	scores, err := st.RefreshIPScores(ctx, 14*24*time.Hour, score.DefaultWeights())
	if err != nil {
		log.Fatalf("refresh ip scores: %v", err)
	}
	log.Printf("ip scores refreshed: %d", len(scores))

	slow, err := st.RefreshSlowScanners(ctx, 14*24*time.Hour, score.DefaultSlowScanWeights())
	if err != nil {
		log.Fatalf("refresh slow scanners: %v", err)
	}
	log.Printf("slow scanners refreshed: %d", len(slow))
	for _, s := range slow {
		log.Printf("  %s score=%d active_days=%d events=%d", s.IP, s.Score, s.ActiveDays, s.Events)
	}
}
