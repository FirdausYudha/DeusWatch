// Command api adalah API server DeusWatch.
//
// Tahap fondasi (langkah 2): hello-world + healthcheck yang membuktikan service
// Go bisa bicara ke PostgreSQL+TimescaleDB dan NATS JetStream lewat docker-compose.
// Sengaja zero-dependency (stdlib saja) agar build cepat dan offline-friendly;
// klien Postgres/NATS sungguhan menyusul saat paket internal/store & internal/bus dibuat.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const version = "0.0.1-foundation"

func main() {
	addr := getenv("HTTP_ADDR", ":8080")

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/readyz", readyzHandler)

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
		"message": "fondasi hidup — lanjut ke mTLS & schema DCS",
	})
}

// healthzHandler = liveness: proses hidup, tanpa mengecek dependensi.
func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

// readyzHandler = readiness: dependensi siap (Postgres reachable, NATS connected).
// Tahap fondasi memakai TCP dial stdlib untuk membuktikan jaringan docker-compose
// tersambung; cek ping/handshake sungguhan menyusul bersama internal/store & internal/bus.
func readyzHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	targets := map[string]string{
		"postgres": getenv("POSTGRES_ADDR", "db:5432"),
		"nats":     getenv("NATS_ADDR", "nats:4222"),
	}

	deps := make(map[string]string, len(targets))
	allReady := true
	for name, addr := range targets {
		if err := dialTCP(ctx, addr); err != nil {
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

func dialTCP(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}
