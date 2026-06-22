// Command gateway is the DeusWatch ingest gateway (mTLS required). It receives raw
// logs from agents, normalizes them to DCS, and publishes them to NATS.
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
	"deuswatch/internal/enroll"
	"deuswatch/internal/gateway"
	"deuswatch/internal/integrations"
	"deuswatch/internal/mtls"
	"deuswatch/internal/respond"
	"deuswatch/internal/store"
)

func main() {
	addr := getenv("GATEWAY_ADDR", ":8443")
	certDir := getenv("CERT_DIR", "deploy/certs")
	natsURL := getenv("NATS_URL", "nats://localhost:4222")

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	tlsCfg, err := mtls.ServerConfig(mtls.Paths(certDir))
	if err != nil {
		log.Fatalf("gateway: load certs from %q (run certgen first?): %v", certDir, err)
	}

	b, err := bus.Connect(ctx, natsURL)
	if err != nil {
		log.Fatalf("gateway: bus: %v", err)
	}
	defer b.Close()

	// Revocation + config push + agent-block feed (optional): needs DB access.
	var revoked gateway.RevokedFunc
	var cfgFunc gateway.ConfigFunc
	var seenFunc gateway.SeenFunc
	var blockFunc gateway.BlocklistFunc
	if dsn := os.Getenv("STORE_DSN"); dsn != "" {
		if st, err := store.Connect(ctx, dsn); err != nil {
			log.Printf("gateway: store unavailable — revocation/config/heartbeat disabled: %v", err)
		} else {
			defer st.Close()
			es := enroll.NewStore(st.Pool(), nil)
			revoked = es.IsRevoked
			cfgFunc = es.GetConfigByName
			seenFunc = es.MarkSeen
			// Agent-side auto-block: only feed the blocklist when the admin has enabled an
			// nftables_agent integration; the IPs are the active response-engine blocks.
			rs := respond.NewStore(st.Pool())
			pool := st.Pool()
			blockFunc = func(ctx context.Context) ([]string, error) {
				on, err := integrations.HasEnabled(ctx, pool, "nftables_agent")
				if err != nil || !on {
					return nil, err
				}
				return rs.ActiveBlocks(ctx)
			}
			log.Printf("gateway: revocation, config push, heartbeat & agent-block feed enabled")
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", gateway.LogsHandler(b, revoked))
	mux.HandleFunc("GET /v1/config", gateway.ConfigHandler(cfgFunc))
	mux.HandleFunc("POST /v1/heartbeat", gateway.HeartbeatHandler(seenFunc))
	mux.HandleFunc("GET /v1/blocklist", gateway.BlocklistHandler(blockFunc))
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
		// Certificates are already in TLSConfig, so the file arguments are empty.
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
