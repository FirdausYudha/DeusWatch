// Command gateway is the DeusWatch ingest gateway (mTLS required). It receives raw
// logs from agents, normalizes them to DCS, and publishes them to NATS.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	var quarantineFunc gateway.QuarantineFunc
	var containFunc gateway.ContainmentFunc
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
			// Endpoint file quarantine: only feed the known-bad file list when the admin has
			// enabled the file_quarantine integration. Agents must also opt in on the host.
			quarantineFunc = func(ctx context.Context) ([]gateway.FileTarget, error) {
				on, err := integrations.HasEnabled(ctx, pool, "file_quarantine")
				if err != nil || !on {
					return nil, err
				}
				targets, err := st.QuarantineTargets(ctx)
				if err != nil {
					return nil, err
				}
				out := make([]gateway.FileTarget, len(targets))
				for i, t := range targets {
					out[i] = gateway.FileTarget{Path: t.Path, SHA256: t.SHA256}
				}
				return out, nil
			}
			// Network containment: serve each agent its host-isolation directive, derived from
			// the active containment row. AllowIPs (manager/DNS the isolated host must keep
			// reaching) come from DEUSWATCH_CONTAINMENT_ALLOW_IPS; the agent also always keeps
			// its own gateway reachable, so its link to the manager can never be cut.
			allowIPs := splitCSV(os.Getenv("DEUSWATCH_CONTAINMENT_ALLOW_IPS"))
			containFunc = func(ctx context.Context, cn string) (gateway.ContainmentDirective, error) {
				c, err := rs.ActiveContainmentByAgent(ctx, cn)
				if err != nil || c == nil {
					return gateway.ContainmentDirective{}, err
				}
				return gateway.ContainmentDirective{Isolate: true, AllowIPs: allowIPs, Reason: c.Reason}, nil
			}
			log.Printf("gateway: revocation, config push, heartbeat, agent-block, file-quarantine & containment feeds enabled")
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", gateway.LogsHandler(b, revoked))
	mux.HandleFunc("GET /v1/config", gateway.ConfigHandler(cfgFunc))
	mux.HandleFunc("POST /v1/heartbeat", gateway.HeartbeatHandler(seenFunc, revoked))
	mux.HandleFunc("GET /v1/blocklist", gateway.BlocklistHandler(blockFunc))
	mux.HandleFunc("GET /v1/quarantine", gateway.QuarantineHandler(quarantineFunc))
	mux.HandleFunc("GET /v1/containment", gateway.ContainmentHandler(containFunc))
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

// splitCSV parses a comma-separated env value into a trimmed, non-empty slice.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
