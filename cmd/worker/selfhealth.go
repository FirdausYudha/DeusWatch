package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"deuswatch/internal/bus"
	"deuswatch/internal/selfhealth"
	"deuswatch/internal/store"
	"deuswatch/internal/worker"
)

// runAgentHealth is the self-monitoring checker (design doc section 13): every 30s it
// recomputes each agent's liveness state and, on a transition, stores the status and
// emits a selfhealth event through the normal alert pipeline - so a dead agent shows
// up on the dashboard and in Telegram exactly like an attack alert.
func runAgentHealth(ctx context.Context, st *store.Store, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {
	disconnectedAfter := durEnv("AGENT_DISCONNECT_AFTER", selfhealth.DefaultDisconnectedAfter)
	staleAfter := durEnv("AGENT_STALE_AFTER", selfhealth.DefaultStaleAfter)
	log.Printf("worker: agent health checker active (disconnected after %s, stale after %s)",
		disconnectedAfter, staleAfter)

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			hc, cancel := context.WithTimeout(ctx, 20*time.Second)
			agents, err := st.AgentHealthRows(hc)
			if err != nil {
				log.Printf("worker: agent health rows: %v", err)
				cancel()
				continue
			}
			now := time.Now()
			for _, a := range agents {
				tr := selfhealth.Evaluate(a, now, disconnectedAfter, staleAfter)
				if tr == nil {
					continue
				}
				if err := st.SetAgentStatus(hc, a.ID, tr.To); err != nil {
					log.Printf("worker: set agent %s status: %v", a.Name, err)
					continue
				}
				log.Printf("worker: agent %q %s -> %s", a.Name, tr.From, tr.To)
				if tr.Event == nil {
					continue
				}
				if annotate != nil {
					annotate(tr.Event)
				}
				if err := st.InsertEvent(hc, tr.Event); err != nil {
					log.Printf("worker: store selfhealth event: %v", err)
					continue
				}
				if onAlert != nil {
					onAlert(hc, tr.Event)
				}
			}
			cancel()
		}
	}
}

// runDiskJanitor is the disk-watermark safety net (design doc section 8): when the log
// DB crosses STORAGE_JANITOR_PERCENT of STORAGE_BUDGET_GB (default 90%, deliberately
// not ~98% - Postgres running out of disk risks corruption), it drops the OLDEST event
// chunks earlier than their retention schedule until usage falls below the watermark,
// and every trigger raises a HIGH selfhealth alert so the admin knows the disk needs
// growing or retention needs tightening. Inactive without a budget.
func runDiskJanitor(ctx context.Context, st *store.Store, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {
	budgetGB, _ := strconv.ParseFloat(os.Getenv("STORAGE_BUDGET_GB"), 64)
	pct := 90
	if v, err := strconv.Atoi(os.Getenv("STORAGE_JANITOR_PERCENT")); err == nil {
		pct = v
	}
	if budgetGB <= 0 || pct <= 0 {
		log.Printf("worker: disk janitor disabled (set STORAGE_BUDGET_GB, and STORAGE_JANITOR_PERCENT>0)")
		return
	}
	budget := int64(budgetGB * 1024 * 1024 * 1024)
	budgetLabel := fmt.Sprintf("%.0f GB", budgetGB)
	log.Printf("worker: disk janitor active (drops oldest chunks at %d%% of %s)", pct, budgetLabel)

	const maxDropsPerRun = 6 // safety valve: never mass-purge in one sweep

	run := func() {
		jc, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		s := st.StorageStatus(jc, budget)
		if !s.Reachable || s.UsedPercent < pct {
			return
		}
		triggeredAt := s.UsedPercent
		dropped := 0
		var lastBefore time.Time
		for dropped < maxDropsPerRun {
			end, count, err := st.OldestEventChunk(jc)
			if err != nil || end == nil || count <= 1 {
				break // keep at least the newest chunk - never drop today's data
			}
			n, err := st.DropEventChunksBefore(jc, *end)
			if err != nil {
				log.Printf("worker: janitor drop: %v", err)
				break
			}
			if n == 0 {
				break
			}
			dropped += n
			lastBefore = *end
			if s = st.StorageStatus(jc, budget); !s.Reachable || s.UsedPercent < pct {
				break
			}
		}
		if dropped == 0 {
			log.Printf("worker: janitor: DB at %d%% of budget but no droppable chunks (grow the disk or tighten retention)", triggeredAt)
			return
		}
		log.Printf("worker: janitor dropped %d chunk(s); DB %d%% -> %d%% of %s", dropped, triggeredAt, s.UsedPercent, budgetLabel)
		ev := selfhealth.JanitorEvent(time.Now(), dropped, lastBefore, triggeredAt, budgetLabel)
		if annotate != nil {
			annotate(ev)
		}
		if err := st.InsertEvent(jc, ev); err != nil {
			log.Printf("worker: store janitor alert: %v", err)
			return
		}
		if onAlert != nil {
			onAlert(jc, ev)
		}
	}

	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	run() // once on startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// runHealthProbe is the `/app -healthcheck` mode used as the container's HEALTHCHECK. The worker
// image is distroless: there is no shell, curl or wget inside it, so the binary has to be able to
// probe itself. Exits 0 when /healthz is OK, 1 otherwise, which is exactly what Docker expects.
func runHealthProbe() int {
	addr := getenv("WORKER_HTTP_ADDR", ":8090")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		fmt.Fprintf(os.Stderr, "healthcheck: HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}
	return 0
}

// serveHealth exposes /healthz (liveness) and /readyz (Postgres + NATS reachable) on
// WORKER_HTTP_ADDR, mirroring the api/gateway endpoints, so the worker is no longer
// the one component whose death nothing notices.
func serveHealth(ctx context.Context, st *store.Store, b *bus.Bus) {
	addr := getenv("WORKER_HTTP_ADDR", ":8090")
	mux := http.NewServeMux()
	// /healthz reports real liveness, not just "the HTTP server is up". It fails once the worker has
	// not managed a heartbeat for the stall window, which is the same condition that means detection
	// has stopped. An unconditional 200 here would have reported a wedged worker as healthy, making
	// the endpoint useless for a container healthcheck.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if last := lastHeartbeatOK.Load(); last > 0 {
			if since := time.Since(time.Unix(0, last)); since > heartbeatStallLimit {
				http.Error(w, fmt.Sprintf("no heartbeat for %s", since.Round(time.Second)), http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		rc, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := st.Pool().Ping(rc); err != nil {
			http.Error(w, "postgres unreachable", http.StatusServiceUnavailable)
			return
		}
		if !b.Connected() {
			http.Error(w, "nats disconnected", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	log.Printf("worker: health endpoints on %s (/healthz, /readyz)", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("worker: health server: %v", err)
	}
}

// runAgentReaper periodically hard-deletes tombstoned agents (deleted by the operator while still
// valid → revoked + hidden) once they have been silent long enough to be considered self-uninstalled.
// The grace window (AGENT_REAP_GRACE, default 15m) must comfortably exceed the agent heartbeat so a
// briefly-offline agent that is about to receive its 410 uninstall signal is not reaped early.
func runAgentReaper(ctx context.Context, st *store.Store) {
	grace := durEnv("AGENT_REAP_GRACE", 15*time.Minute)
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rc, cancel := context.WithTimeout(ctx, 30*time.Second)
			n, err := st.ReapDeletedAgents(rc, grace)
			cancel()
			if err != nil {
				log.Printf("worker: agent reaper: %v", err)
			} else if n > 0 {
				log.Printf("worker: agent reaper: purged %d deleted agent(s)", n)
			}
		}
	}
}

// durEnv reads a Go duration from env with a default.
func durEnv(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(key)); err == nil && d > 0 {
		return d
	}
	return def
}
