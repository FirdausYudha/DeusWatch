package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/respond"
	"deuswatch/internal/score"
	"deuswatch/internal/store"
	"deuswatch/internal/trivy"
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
// (and thus the last findings) are kept, the feature degrades to "last known" rather than going
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
	// re-matches everyone. Bounded time, the Debian feed is large.
	refreshFeeds := func() {
		// Generous: the USN notices API caps pages at 20, so a single Ubuntu release is ~120
		// sequential requests (a few minutes); a multi-release fleet adds up.
		fc, cancel := context.WithTimeout(ctx, 30*time.Minute)
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
			// Enrich USN entries with per-CVE Ubuntu priority (v2.8.0). The USN notices feed
			// omits severity, without this step every USN finding shows as "unknown" in the UI.
			// Cached in cve_priority_cache with a 30-day TTL, so a cold start is the only slow
			// path; subsequent refreshes reuse the cache.
			if source == "usn" {
				ec, ecancel := context.WithTimeout(fc, 20*time.Minute)
				if err := vuln.EnrichUSNSeverity(ec, nil, st, advs, 4, 30*24*time.Hour); err != nil {
					log.Printf("worker: vuln: enrich USN severities (continuing with what we have): %v", err)
				}
				ecancel()
			}
			if err := st.ReplaceAdvisories(fc, source, advs); err != nil {
				log.Printf("worker: vuln: cache %s advisories: %v", source, err)
				continue
			}
			log.Printf("worker: vuln: %s feed refreshed (%d advisories for %v)", source, len(advs), releases)
		}
		// Rematch gets its own fresh 5-min context. Sharing fc, already partially consumed by
		// USN pagination (~120 requests per release) + per-CVE severity enrichment (thousands of
		// requests on cold cache), starved this call in v2.8.0, so agent_vulnerabilities held
		// stale empty-severity rows even though advisories.severity was correctly enriched.
		rmCtx, rmCancel := context.WithTimeout(ctx, 5*time.Minute)
		rematch(rmCtx, st)
		rmCancel()
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
			// Cold-start / new-distro catch-up: if an agent reported a distro release AFTER the
			// last feed pull, its advisories aren't cached yet and a bare re-match would find
			// nothing. Fetch now rather than waiting up to the 12h feed cycle.
			if fleetNeedsFeed(ctx, st) {
				log.Printf("worker: vuln: a fleet release has no cached advisories yet, fetching off-cycle")
				refreshFeeds()
			} else {
				mc, cancel := context.WithTimeout(ctx, 5*time.Minute)
				rematch(mc, st)
				cancel()
			}
		}
	}
}

// trivyEnabled reports whether the server-side Trivy scanner should run instead of the built-in
// USN/Debian OVAL matcher. On when TRIVY_ENABLED=1 or a TRIVY_CACHE_DIR is set (the shared DB cache).
func trivyEnabled() bool {
	if v, err := strconv.ParseBool(os.Getenv("TRIVY_ENABLED")); err == nil {
		return v
	}
	return os.Getenv("TRIVY_CACHE_DIR") != ""
}

// runTrivyScanner is the server-side Vulnerability Assessment loop backed by Trivy (the chosen
// severity source for DEB + RPM). For every agent that has reported an inventory it feeds the OS
// packages to Trivy (which owns the vuln DB) and stores the findings, which carry a real severity, so
// the Inventory donut and table show critical/high/medium/low instead of "unknown". Trivy needs the
// internet (DB refresh in the trivy service); a scan failure is logged and the last findings are kept.
func runTrivyScanner(ctx context.Context, st *store.Store) {
	cfg := trivy.Config{Bin: getenv("TRIVY_BIN", "trivy"), CacheDir: getenv("TRIVY_CACHE_DIR", "/trivy-cache")}
	interval := durEnv("TRIVY_SCAN_INTERVAL", 6*time.Hour)
	log.Printf("worker: trivy vulnerability assessment active (cache=%q, every %s)", cfg.CacheDir, interval)

	scanAll := func() {
		lc, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		targets, err := st.ListScanTargets(lc)
		if err != nil {
			log.Printf("worker: trivy: list targets: %v", err)
			return
		}
		osN, scaN := 0, 0
		var osErr, scaErr error
		for _, t := range targets {
			// Isolate each agent: a panic or runaway in one agent's scan is logged with the agent
			// name and skipped, so it can never take the whole scanner (or the worker) down, and the
			// per-agent log line is the breadcrumb that pinpoints a crash. The phase logs below name
			// the exact step the scanner is on if the process dies mid-scan.
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("worker: trivy: PANIC scanning agent %q, skipping: %v", t.Name, r)
					}
				}()
				if t.PkgManager != "" {
					log.Printf("worker: trivy: OS scan %s starting", t.Name)
					if err := scanOSPackages(lc, st, cfg, t); err != nil {
						osErr = err
					} else {
						osN++
					}
				}
				log.Printf("worker: trivy: SCA scan %s starting", t.Name)
				if had, err := scanManifests(lc, st, cfg, t.Name); err != nil {
					scaErr = err
				} else if had {
					scaN++
				}
			}()
		}
		log.Printf("worker: trivy: scanned %d agent(s) for OS vulns, %d for SCA", osN, scaN)
		recordScanStatus(lc, st, "trivy-os", osN, osErr)
		recordScanStatus(lc, st, "trivy-sca", scaN, scaErr)
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	first := time.NewTimer(90 * time.Second) // let the trivy service pull its DB first
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			scanAll()
		case <-t.C:
			scanAll()
		}
	}
}

// recordScanStatus persists a scanner's last-run outcome so the UI can explain an empty/"unknown"
// result (e.g. Trivy could not reach its DB) instead of showing stale data with no reason.
func recordScanStatus(ctx context.Context, st *store.Store, scanner string, scanned int, runErr error) {
	ok := runErr == nil
	detail := ""
	if runErr != nil {
		detail = runErr.Error()
		if len(detail) > 500 {
			detail = detail[:500]
		}
	}
	if err := st.SetScanStatus(ctx, scanner, ok, detail, scanned); err != nil {
		log.Printf("worker: trivy: record %s status: %v", scanner, err)
	}
}

// scanOSPackages runs Trivy over one agent's OS packages and stores the findings (with severity +
// CVSS). Returns nil on success; on error the agent keeps its last findings and the error is
// surfaced via scan_status.
func scanOSPackages(ctx context.Context, st *store.Store, cfg trivy.Config, t store.ScanTarget) error {
	pkgs, err := st.AgentScanPackages(ctx, t.Name)
	if err != nil {
		return fmt.Errorf("packages for %s: %w", t.Name, err)
	}
	tpkgs := make([]trivy.Package, 0, len(pkgs))
	for _, p := range pkgs {
		tpkgs = append(tpkgs, trivy.Package{Name: p.Name, Version: p.Version, Arch: p.Arch, Source: p.Source})
	}
	findings, err := cfg.ScanOS(ctx, trivy.OS{
		ID: t.OSID, Version: t.OSVersion, Codename: t.OSCodename, PkgManager: t.PkgManager,
	}, tpkgs)
	if err != nil {
		log.Printf("worker: trivy: OS scan %s failed (keeping last findings): %v", t.Name, err)
		return err
	}
	vf := make([]vuln.Finding, 0, len(findings))
	for _, f := range findings {
		vf = append(vf, vuln.Finding{
			Package: f.Package, InstalledVersion: f.InstalledVersion, FixedVersion: f.FixedVersion,
			CVE: f.CVE, Severity: f.Severity, CVSS: f.CVSS, Source: f.Source,
		})
	}
	if err := st.ReplaceAgentFindings(ctx, t.Name, vf); err != nil {
		return fmt.Errorf("store OS findings for %s: %w", t.Name, err)
	}
	return nil
}

// scanManifests runs Trivy SCA over one agent's dependency manifests and stores the findings.
// Returns had=true when the agent reported manifests, plus any scan/store error.
func scanManifests(ctx context.Context, st *store.Store, cfg trivy.Config, name string) (had bool, err error) {
	manifests, err := st.AgentManifests(ctx, name)
	if err != nil {
		return false, fmt.Errorf("manifests for %s: %w", name, err)
	}
	if len(manifests) == 0 {
		return false, nil
	}
	tm := make([]trivy.Manifest, 0, len(manifests))
	for _, m := range manifests {
		tm = append(tm, trivy.Manifest{Path: m.Path, Content: m.Content})
	}
	findings, err := cfg.ScanManifests(ctx, tm)
	if err != nil {
		log.Printf("worker: trivy: SCA scan %s failed (keeping last findings): %v", name, err)
		return true, err
	}
	sf := make([]store.SCAFinding, 0, len(findings))
	for _, f := range findings {
		sf = append(sf, store.SCAFinding{
			Target: f.Target, PkgType: f.PkgType, Package: f.Package,
			InstalledVersion: f.InstalledVersion, FixedVersion: f.FixedVersion,
			VulnID: f.VulnID, Severity: f.Severity, CVSS: f.CVSS,
		})
	}
	if err := st.ReplaceSCAFindings(ctx, name, sf); err != nil {
		return true, fmt.Errorf("store SCA findings for %s: %w", name, err)
	}
	return true, nil
}

// fleetNeedsFeed reports whether the fleet runs a distro release for which no advisories are cached
// yet, the cold-start case where an agent's inventory arrived after the last feed pull. It keeps a
// fresh setup from sitting blank until the next scheduled 12h refresh.
func fleetNeedsFeed(ctx context.Context, st *store.Store) bool {
	fc, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	want, err := st.DistroReleasesInUse(fc)
	if err != nil || len(want) == 0 {
		return false
	}
	_, byRelease, err := st.AdvisoryStats(fc)
	if err != nil {
		return false
	}
	for _, releases := range want {
		for _, r := range releases {
			if byRelease[r] == 0 {
				return true
			}
		}
	}
	return false
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
