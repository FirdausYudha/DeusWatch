package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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
func runAgentHealth(ctx context.Context, st *store.Store, onAlert worker.AlertHook) {
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
func runDiskJanitor(ctx context.Context, st *store.Store, onAlert worker.AlertHook) {
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

// serveHealth exposes /healthz (liveness) and /readyz (Postgres + NATS reachable) on
// WORKER_HTTP_ADDR, mirroring the api/gateway endpoints, so the worker is no longer
// the one component whose death nothing notices.
func serveHealth(ctx context.Context, st *store.Store, b *bus.Bus) {
	addr := getenv("WORKER_HTTP_ADDR", ":8090")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
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

// durEnv reads a Go duration from env with a default.
func durEnv(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(key)); err == nil && d > 0 {
		return d
	}
	return def
}
