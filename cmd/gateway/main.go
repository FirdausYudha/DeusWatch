// Command gateway adalah ingest gateway DeusWatch (mTLS wajib). Menerima log
// mentah dari agent, menormalkan ke DCS, dan menerbitkannya ke NATS.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"deuswatch/internal/bus"
	"deuswatch/internal/gateway"
	"deuswatch/internal/mtls"
)

func main() {
	addr := getenv("GATEWAY_ADDR", ":8443")
	certDir := getenv("CERT_DIR", "deploy/certs")
	natsURL := getenv("NATS_URL", "nats://localhost:4222")

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	tlsCfg, err := mtls.ServerConfig(mtls.Paths(certDir))
	if err != nil {
		log.Fatalf("gateway: muat sertifikat dari %q (jalankan certgen dulu?): %v", certDir, err)
	}

	b, err := bus.Connect(ctx, natsURL)
	if err != nil {
		log.Fatalf("gateway: bus: %v", err)
	}
	defer b.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", gateway.LogsHandler(b))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"alive"}`))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("DeusWatch gateway (mTLS) listening on %s", addr)
		// Sertifikat sudah ada di TLSConfig, argumen file dikosongkan.
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("gateway: serve: %v", err)
		}
	}()

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	log.Println("gateway: shutdown")
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
