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
	"deuswatch/internal/decoders"
	"deuswatch/internal/enroll"
	"deuswatch/internal/gateway"
	"deuswatch/internal/ingest"
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

	// Custom decoders (optional, data-driven): regex-based field extraction for log sources
	// without a built-in normalizer. Loaded once at startup from DECODERS_DIR.
	decoderDir := getenv("DECODERS_DIR", "/decoders")
	if ds, derr := ingest.LoadDecoderDir(decoderDir); derr != nil {
		log.Printf("gateway: custom decoders disabled (%v)", derr)
	} else if n := ds.Count(); n > 0 {
		ingest.SetDecoders(ds)
		log.Printf("gateway: loaded %d custom decoder(s) from %s", n, decoderDir)
	}

	// Revocation + config push + agent-block feed (optional): needs DB access.
	var revoked gateway.RevokedFunc
	var cfgFunc gateway.ConfigFunc
	var seenFunc gateway.SeenFunc
	var healthFunc gateway.HealthFunc
	var blockFunc gateway.BlocklistFunc
	var quarantineFunc gateway.QuarantineFunc
	var containFunc gateway.ContainmentFunc
	var restoreFunc gateway.RestoreFunc
	var snapshotFunc gateway.SnapshotFunc
	var fileActionsFunc gateway.FileActionsFunc
	var fileActionResultFunc gateway.FileActionResultFunc
	if dsn := os.Getenv("STORE_DSN"); dsn != "" {
		if st, err := store.Connect(ctx, dsn); err != nil {
			log.Printf("gateway: store unavailable — revocation/config/heartbeat disabled: %v", err)
		} else {
			defer st.Close()
			// Custom decoders from the DB, live-reloaded so UI edits take effect without a
			// restart (overrides the file bootstrap above once the DB is reachable).
			go runDecoderReload(ctx, decoders.NewStore(st.Pool()))
			es := enroll.NewStore(st.Pool(), nil)
			revoked = es.IsRevoked
			cfgFunc = es.GetConfigByName
			seenFunc = es.MarkSeen
			restoreFunc = st.PendingRestores
			healthFunc = es.MarkHealth
			// Versioned FIM snapshots (ADR 0002): record each uploaded version's metadata; the
			// content itself stays on the agent (storage="agent"). RecordSnapshot de-dups an
			// unchanged latest hash, so re-reported versions are no-ops.
			snapStore := st
			snapshotFunc = func(ctx context.Context, cn string, snaps []gateway.SnapshotMeta) error {
				for _, sm := range snaps {
					// The admin's storage choice: manager-side means the agent uploaded the
					// content, which we retain centrally (storage="manager"); otherwise the
					// content stays on the host (storage="agent") and only metadata is recorded.
					storage := "agent"
					var content []byte
					if sm.Content != "" {
						storage = "manager"
						content = []byte(sm.Content)
					}
					if _, err := snapStore.RecordSnapshot(ctx, store.FIMSnapshot{
						AgentName: cn, Path: sm.Path, SHA256: sm.SHA256, Size: sm.Size,
						Storage: storage, Trigger: sm.Trigger, Diff: sm.Diff,
					}, content); err != nil {
						return err
					}
				}
				return nil
			}
			// On-demand file actions (snapshot_now / quarantine): serve the agent its queue and
			// record the outcome it reports back (ADR 0002 Phase 3).
			fileActionsFunc = func(ctx context.Context, cn string) ([]gateway.FileActionItem, error) {
				acts, err := st.PendingFileActions(ctx, cn)
				if err != nil {
					return nil, err
				}
				out := make([]gateway.FileActionItem, len(acts))
				for i, a := range acts {
					item := gateway.FileActionItem{
						ID: a.ID, Path: a.Path, Action: a.Action, VersionSHA256: a.VersionSHA,
						PID: a.PID, ProcName: a.ProcName, ProcStart: a.ProcStart,
					}
					// For a manager-stored version, ship the content so the agent can restore even
					// if it no longer has the local blob (durability — survives host reprovision).
					if a.Action == "restore_version" && a.VersionSHA != "" {
						if content, ok, cerr := st.SnapshotContent(ctx, cn, a.Path, a.VersionSHA); cerr == nil && ok {
							item.Content = string(content)
						}
					}
					out[i] = item
				}
				return out, nil
			}
			fileActionResultFunc = st.SetFileActionResult
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
	mux.HandleFunc("POST /v1/heartbeat", gateway.HeartbeatHandler(seenFunc, healthFunc, revoked))
	mux.HandleFunc("GET /v1/blocklist", gateway.BlocklistHandler(blockFunc))
	mux.HandleFunc("GET /v1/quarantine", gateway.QuarantineHandler(quarantineFunc))
	mux.HandleFunc("GET /v1/containment", gateway.ContainmentHandler(containFunc))
	mux.HandleFunc("GET /v1/restore", gateway.RestoreHandler(restoreFunc))
	mux.HandleFunc("POST /v1/snapshots", gateway.SnapshotHandler(snapshotFunc, revoked))
	mux.HandleFunc("GET /v1/file-actions", gateway.FileActionsHandler(fileActionsFunc, revoked))
	mux.HandleFunc("POST /v1/file-actions/result", gateway.FileActionResultHandler(fileActionResultFunc, revoked))
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

// runDecoderReload installs the enabled custom decoders from the DB and re-reads them every 30s,
// so decoders added/edited/toggled in the UI take effect without restarting the gateway.
func runDecoderReload(ctx context.Context, ds *decoders.Store) {
	load := func() {
		rc, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		set, err := ds.EnabledSet(rc)
		if err != nil {
			log.Printf("gateway: decoder reload: %v", err)
			return
		}
		ingest.SetDecoders(set)
	}
	load()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			load()
		}
	}
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
