// Command api adalah API server DeusWatch.
//
// Menyajikan healthcheck (liveness/readiness) dan endpoint baca data Fase 1
// (events, alerts, stats) dari PostgreSQL+TimescaleDB untuk Web UI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"deuswatch/internal/auth"
	"deuswatch/internal/store"
)

const version = "0.1.0-foundation"

func main() {
	addr := getenv("HTTP_ADDR", ":8080")

	// Koneksi store opsional: bila DB belum siap, endpoint /api/* membalas 503,
	// tetapi liveness tetap hidup.
	var st *store.Store
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if s, err := store.Connect(ctx, dsn); err != nil {
			log.Printf("api: store tak tersedia (lanjut tanpa DB): %v", err)
		} else {
			st = s
			defer s.Close()
			log.Printf("api: store tersambung")
		}
		cancel()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/readyz", readyzHandler)

	if st != nil {
		authStore := auth.NewStore(st.Pool())
		seedAdmin(authStore)

		// Publik (tanpa token).
		mux.HandleFunc("/api/login", authStore.LoginHandler())

		// Terproteksi: wajib sesi valid + permission.
		protect := func(p auth.Permission, h http.HandlerFunc) http.Handler {
			return authStore.Middleware(auth.RequirePermission(p, h))
		}
		mux.Handle("/api/me", authStore.Middleware(auth.MeHandler()))
		mux.Handle("/api/logout", authStore.Middleware(authStore.LogoutHandler()))
		mux.Handle("/api/events", protect(auth.PermViewDashboard, eventsHandler(st)))
		mux.Handle("/api/alerts", protect(auth.PermViewDashboard, alertsHandler(st)))
		mux.Handle("/api/stats", protect(auth.PermViewDashboard, statsHandler(st)))
	} else {
		// Tanpa DB: endpoint membalas 503.
		mux.HandleFunc("/api/events", eventsHandler(nil))
		mux.HandleFunc("/api/alerts", alertsHandler(nil))
		mux.HandleFunc("/api/stats", statsHandler(nil))
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("DeusWatch API %s listening on %s", version, addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// seedAdmin membuat user admin awal bila belum ada user.
func seedAdmin(authStore *auth.Store) {
	user := getenv("ADMIN_USERNAME", "admin")
	pass := os.Getenv("ADMIN_PASSWORD")
	if pass == "" {
		pass = "deuswatch-admin"
		log.Printf("api: ADMIN_PASSWORD kosong — pakai default dev (GANTI untuk produksi!)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	created, err := authStore.EnsureAdmin(ctx, user, pass)
	if err != nil {
		log.Printf("api: seed admin gagal: %v", err)
		return
	}
	if created {
		log.Printf("api: user admin awal %q dibuat", user)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "DeusWatch API",
		"version": version,
		"status":  "ok",
	})
}

// healthzHandler = liveness.
func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

// readyzHandler = readiness (Postgres & NATS reachable). Tahap fondasi: TCP dial.
func readyzHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	targets := map[string]string{
		"postgres": getenv("POSTGRES_ADDR", "db:5432"),
		"nats":     getenv("NATS_ADDR", "nats:4222"),
	}
	deps := make(map[string]string, len(targets))
	allReady := true
	for name, target := range targets {
		if err := dialTCP(ctx, target); err != nil {
			deps[name] = "unreachable: " + err.Error()
			allReady = false
			continue
		}
		deps[name] = "reachable"
	}
	status, overall := http.StatusOK, "ready"
	if !allReady {
		status, overall = http.StatusServiceUnavailable, "not_ready"
	}
	writeJSON(w, status, map[string]any{"status": overall, "dependencies": deps})
}

func eventsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, "database tidak tersedia", http.StatusServiceUnavailable)
			return
		}
		rows, err := st.RecentEvents(r.Context(), queryLimit(r, 50, 500))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

func alertsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, "database tidak tersedia", http.StatusServiceUnavailable)
			return
		}
		rows, err := st.RecentAlerts(r.Context(), queryLimit(r, 50, 500))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

func statsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, "database tidak tersedia", http.StatusServiceUnavailable)
			return
		}
		s, err := st.Stats(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, s)
	}
}

func queryLimit(r *http.Request, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func dialTCP(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}
