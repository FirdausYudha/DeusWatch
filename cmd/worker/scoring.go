package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/respond"
	"deuswatch/internal/score"
	"deuswatch/internal/store"
	"deuswatch/internal/vuln"
)

// runIPScorer periodically recomputes the composite threat score per source IP over
// SCORE_WINDOW (default 10m) - Multi-Source Event Correlation: fired_times + AbuseIPDB +
// OTX + worst severity → one 0-100 score/band per IP, shown on the dashboard. When
// SCENARIO_BAN_SCORE > 0, any IP crossing that score is handed to the response engine as
// a ban recommendation (progressive ban + whitelist + dedup all still apply).
func runIPScorer(ctx context.Context, st *store.Store, engine *respond.Engine) {
	interval := durEnv("SCORE_INTERVAL", 30*time.Second)
	banAt, _ := strconv.Atoi(os.Getenv("SCENARIO_BAN_SCORE")) // 0 = scenario ban disabled

	log.Printf("worker: IP scorer active (every %s%s; window is UI-configurable)", interval,
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
			scoreOnce(ctx, st, engine, banAt)
		case <-t.C:
			scoreOnce(ctx, st, engine, banAt)
		}
	}
}

func scoreOnce(ctx context.Context, st *store.Store, engine *respond.Engine, banAt int) {
	sc, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Weights AND the window are re-read each tick so a change in Settings applies live.
	cfg, _ := st.LoadScoreConfig(sc)
	scored, err := st.RefreshIPScores(sc, cfg.CompositeWindow(), cfg.Composite)
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
// runSlowScanScorer refreshes the low-and-slow reconnaissance watchlist: sources that come back on
// separate DAYS at a volume no burst rule will ever trip. It is a multi-day aggregate, so it runs
// infrequently (default hourly) over a long window (default 14 days).
func runSlowScanScorer(ctx context.Context, st *store.Store) {
	interval := durEnv("SLOWSCAN_INTERVAL", time.Hour)
	window := durEnv("SLOWSCAN_WINDOW", 14*24*time.Hour)
	log.Printf("worker: slow-scanner watchlist active (every %s over a %s window)", interval, window)

	run := func() {
		sc, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		found, err := st.RefreshSlowScanners(sc, window, score.DefaultSlowScanWeights())
		if err != nil {
			log.Printf("worker: slow-scanner scan: %v", err)
			return
		}
		if len(found) > 0 {
			log.Printf("worker: slow-scanner watchlist: %d source(s) recurring at low volume", len(found))
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	first := time.NewTimer(45 * time.Second) // let the pipeline settle after boot
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

func runSuspiciousScorer(ctx context.Context, st *store.Store) {
	interval := durEnv("SUSPICIOUS_INTERVAL", 5*time.Minute)
	log.Printf("worker: suspicious-IP watchlist active (every %s; window is UI-configurable)", interval)

	run := func() {
		sc, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		cfg, _ := st.LoadScoreConfig(sc) // live-reloadable weights + window
		if _, err := st.RefreshSuspiciousIPs(sc, cfg.SuspiciousWindow(), cfg.Suspicion); err != nil {
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

// runVulnScanner is the Vulnerability Assessment feed+match loop (phase 2). Periodically it fetches
// the vendor advisory feeds (Ubuntu USN / Debian) for the distro releases the fleet actually runs,
// caches them, and re-matches every agent's inventory against them to produce CVE findings.
//
// Feeds need the internet; matching does not. A fetch failure is logged and the cached advisories
// (and thus the last findings) are kept — the feature degrades to "last known" rather than going
// blank, in keeping with the offline design. Disabled with VULN_SCAN=0. Default cadence 12h
// (VULN_SCAN_INTERVAL), matched hourly against inventory even without a fresh feed.
func runVulnScanner(ctx context.Context, st *store.Store) {
	if v, _ := strconv.ParseBool(os.Getenv("VULN_SCAN")); os.Getenv("VULN_SCAN") != "" && !v {
		log.Printf("worker: vulnerability assessment disabled (VULN_SCAN=0)")
		return
	}
	feedInterval := durEnv("VULN_SCAN_INTERVAL", 12*time.Hour)
	log.Printf("worker: vulnerability assessment active (feed refresh every %s)", feedInterval)

	// refreshFeeds pulls advisories for whatever distro releases are present in the fleet, then
	// re-matches everyone. Bounded time — the Debian feed is large.
	refreshFeeds := func() {
		fc, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()

		// Which (feed source -> release codenames) does the fleet actually need?
		want, err := st.DistroReleasesInUse(fc)
		if err != nil {
			log.Printf("worker: vuln: read fleet distros: %v", err)
			return
		}
		if len(want) == 0 {
			return // no inventory yet
		}
		for source, releases := range want {
			keep := map[string]bool{}
			for _, r := range releases {
				keep[r] = true
			}
			var advs []vuln.Advisory
			var ferr error
			switch source {
			case "usn":
				advs, ferr = vuln.FetchUSN(fc, nil, keep)
			case "debian":
				advs, ferr = vuln.FetchDebian(fc, nil, keep)
			default:
				continue
			}
			if ferr != nil {
				log.Printf("worker: vuln: fetch %s feed failed (keeping cached): %v", source, ferr)
				continue
			}
			if err := st.ReplaceAdvisories(fc, source, advs); err != nil {
				log.Printf("worker: vuln: cache %s advisories: %v", source, err)
				continue
			}
			log.Printf("worker: vuln: %s feed refreshed (%d advisories for %v)", source, len(advs), releases)
		}
		rematch(fc, st)
	}

	feedT := time.NewTicker(feedInterval)
	defer feedT.Stop()
	// Re-match hourly even without a fresh feed, so a new agent's inventory is evaluated against
	// the cached advisories promptly rather than waiting for the next feed pull.
	matchT := time.NewTicker(time.Hour)
	defer matchT.Stop()
	first := time.NewTimer(60 * time.Second)
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			refreshFeeds()
		case <-feedT.C:
			refreshFeeds()
		case <-matchT.C:
			mc, cancel := context.WithTimeout(ctx, 5*time.Minute)
			rematch(mc, st)
			cancel()
		}
	}
}

// rematch re-evaluates every agent's inventory against the cached advisories.
func rematch(ctx context.Context, st *store.Store) {
	n, err := st.RematchAll(ctx)
	if err != nil {
		log.Printf("worker: vuln: rematch: %v", err)
		return
	}
	if n > 0 {
		log.Printf("worker: vuln: re-matched %d agent(s) against cached advisories", n)
	}
}
