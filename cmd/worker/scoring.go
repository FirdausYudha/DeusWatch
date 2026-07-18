package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/respond"
	"deuswatch/internal/store"
)

// runIPScorer periodically recomputes the composite threat score per source IP over
// SCORE_WINDOW (default 10m) - Multi-Source Event Correlation: fired_times + AbuseIPDB +
// OTX + worst severity → one 0-100 score/band per IP, shown on the dashboard. When
// SCENARIO_BAN_SCORE > 0, any IP crossing that score is handed to the response engine as
// a ban recommendation (progressive ban + whitelist + dedup all still apply).
func runIPScorer(ctx context.Context, st *store.Store, engine *respond.Engine) {
	window := durEnv("SCORE_WINDOW", 10*time.Minute)
	interval := durEnv("SCORE_INTERVAL", 30*time.Second)
	banAt, _ := strconv.Atoi(os.Getenv("SCENARIO_BAN_SCORE")) // 0 = scenario ban disabled

	log.Printf("worker: IP scorer active (window %s, every %s%s)", window, interval,
		scenarioBanLabel(banAt))

	t := time.NewTicker(interval)
	defer t.Stop()
	// Run once shortly after start so the dashboard has scores without waiting a full tick.
	first := time.NewTimer(5 * time.Second)
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			scoreOnce(ctx, st, engine, window, banAt)
		case <-t.C:
			scoreOnce(ctx, st, engine, window, banAt)
		}
	}
}

func scoreOnce(ctx context.Context, st *store.Store, engine *respond.Engine, window time.Duration, banAt int) {
	sc, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Weights are re-read each tick so a change in Settings applies live.
	cfg, _ := st.LoadScoreConfig(sc)
	scored, err := st.RefreshIPScores(sc, window, cfg.Composite)
	if err != nil {
		log.Printf("worker: IP scoring: %v", err)
		return
	}
	if banAt <= 0 || engine == nil {
		return
	}
	for _, r := range scored {
		if r.Score < banAt {
			continue
		}
		// Synthesize an event so the engine's whitelist + dedup + progressive ban apply.
		ev := &ingest.Event{
			Timestamp: time.Now(),
			Event:     ingest.EventFields{Category: "intrusion_detection", Severity: ingest.SeverityHigh},
			Source:    &ingest.Endpoint{IP: r.IP},
			Rule:      &ingest.Rule{ID: "deuswatch_scenario_score", Name: "Composite Threat Score"},
			DeusWatch: ingest.DeusWatch{Label: "scenario_ban"},
		}
		if _, err := engine.Recommend(sc, ev); err != nil {
			log.Printf("worker: scenario ban %s (score %d): %v", r.IP, r.Score, err)
		} else {
			log.Printf("worker: scenario ban recommended for %s (score %d/%s, fired=%d abuse=%d otx=%d)",
				r.IP, r.Score, r.Band, r.FiredTimes, r.Abuse, r.OTX)
		}
	}
}

func scenarioBanLabel(banAt int) string {
	if banAt <= 0 {
		return "; scenario-ban off"
	}
	return "; scenario-ban at score >= " + strconv.Itoa(banAt)
}

// runSuspiciousScorer periodically recomputes the Suspicious-IP watchlist over a LONG window
// (SUSPICIOUS_WINDOW, default 24h): external IPs whose low-and-slow behaviour looks like
// reconnaissance even without any CTI/WAF hit. Cheaper than the composite scorer, so it runs
// less often (SUSPICIOUS_INTERVAL, default 5m).
func runSuspiciousScorer(ctx context.Context, st *store.Store) {
	window := durEnv("SUSPICIOUS_WINDOW", 24*time.Hour)
	interval := durEnv("SUSPICIOUS_INTERVAL", 5*time.Minute)
	log.Printf("worker: suspicious-IP watchlist active (window %s, every %s)", window, interval)

	run := func() {
		sc, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		cfg, _ := st.LoadScoreConfig(sc) // live-reloadable weights
		if _, err := st.RefreshSuspiciousIPs(sc, window, cfg.Suspicion); err != nil {
			log.Printf("worker: suspicious-IP scan: %v", err)
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	first := time.NewTimer(15 * time.Second)
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			run()
		case <-t.C:
			run()
		}
	}
}
