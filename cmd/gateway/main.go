// Command gateway is the DeusWatch ingest gateway (mTLS required). It receives raw
// logs from agents, normalizes them to DCS, and publishes them to NATS.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"deuswatch/internal/agent"
	"deuswatch/internal/bus"
	"deuswatch/internal/decoders"
	"deuswatch/internal/enroll"
	"deuswatch/internal/gateway"
	"deuswatch/internal/ingest"
	"deuswatch/internal/integrations"
	"deuswatch/internal/mtls"
	"deuswatch/internal/respond"
	"deuswatch/internal/store"
	"deuswatch/internal/yara"
)

// blockLogRate is the minimum interval between two "nftables push" log lines for the SAME
// agent CN. Prevents a busy fleet's 30s poll cadence from spamming syslog while still giving
// operators one line per minute per agent for at-a-glance troubleshooting.
const blockLogRate = 60 * time.Second

type blockLogState struct {
	mu    sync.Mutex
	lastT map[string]time.Time
	lastK map[string]string // last decision key we logged for this CN — always log the FIRST different one
}

var blockLog = &blockLogState{lastT: map[string]time.Time{}, lastK: map[string]string{}}

// logBlockDecision writes one INFO line per (agent, decision) transition, plus a heartbeat every
// blockLogRate seconds even while nothing changes. Enables an operator staring at
// `docker compose logs gateway` to see whether an agent is (a) polling at all, (b) matching an
// integration's agent_scope, and (c) receiving IPs — the three failure modes the v2.11 UI
// integration collapses into "the deuswatch table isn't appearing on my agent".
func logBlockDecision(cn, scope string, nIPs int, enabled bool, reason string) {
	if cn == "" {
		cn = "(no-cn)"
	}
	key := reason // reason encodes enable + match + IP-count changes indirectly
	if enabled {
		key = "on:" + key
	}
	blockLog.mu.Lock()
	prev, hadKey := blockLog.lastK[cn]
	last := blockLog.lastT[cn]
	changed := !hadKey || prev != key
	timeToLog := changed || time.Since(last) >= blockLogRate
	if timeToLog {
		blockLog.lastT[cn] = time.Now()
		blockLog.lastK[cn] = key
	}
	blockLog.mu.Unlock()
	if !timeToLog {
		return
	}
	log.Printf("gateway: nftables push cn=%q enabled=%v scope=%q ips=%d reason=%s", cn, enabled, scope, nIPs, reason)
}

// buildVersion is injected at compile time via -ldflags="-X main.buildVersion=<tag>" from
// deploy/Dockerfile. NOTE: Go silently ignores -X for a symbol that does not exist, so this
// declaration is load-bearing — without it the Dockerfile's ldflag was a no-op for the
// gateway (the bug fixed in v2.14.5).
var buildVersion = ""

// fallbackVersion is the compiled-in semver used when neither the ldflag nor the env var
// supplied one. Keep in lockstep with `const version` in cmd/api/main.go on every release.
const fallbackVersion = "2.14.5"

// resolveVersion picks the gateway's reported version: build-time ldflag first (the intended
// path), then the DEUSWATCH_VERSION env var (backwards-compat with deployments that set it),
// then the compiled-in const. Never returns the un-comparable sentinel "dev" unless someone
// explicitly sets DEUSWATCH_VERSION=dev.
func resolveVersion() string {
	if buildVersion != "" && buildVersion != "dev" {
		return buildVersion
	}
	if v := os.Getenv("DEUSWATCH_VERSION"); v != "" && v != "dev" {
		return v
	}
	return fallbackVersion
}

func main() {
	addr := getenv("GATEWAY_ADDR", ":8443")
	certDir := getenv("CERT_DIR", "deploy/certs")
	natsURL := getenv("NATS_URL", "nats://localhost:4222")
	// managerVersion drives v2.12.0's heartbeat self-update flow: it (a) auto-clears the
	// update_requested_at flag once an agent reports the same version, and (b) is the target
	// version in the directive handed to out-of-date agents.
	//
	// v2.14.5 fix: this used to read ONLY the DEUSWATCH_VERSION env var, which compose never
	// set on the gateway container (it was passed as a *build* arg, not an environment entry).
	// So managerVersion was permanently "dev" — the compare against an agent that ALSO reported
	// "dev" matched, silently clearing the update flag while nothing had actually upgraded.
	// That is the "badge disappears, version unchanged" symptom. Resolution order is now
	// ldflag → env → compiled-in const, so no single missing wire can degrade it to "dev".
	managerVersion := resolveVersion()

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

	// YARA scanner (optional; ADR: manager-side scan on FIM snapshot upload). Loads *.yar files
	// from YARA_RULES_DIR (default /rules/yara). Silently no-ops when the dir is missing, empty, or
	// the binary was built without CGO (Windows dev). Live-reload isn't wired yet — restart the
	// gateway to pick up new rules. Content that matches yields an alert event with dw_label =
	// "yara_malicious" so the whole existing enrichment/alert/response pipeline picks it up.
	yaraScanner := yara.New()
	defer yaraScanner.Close()
	yaraDir := getenv("YARA_RULES_DIR", "/rules/yara")
	if n, yerr := yaraScanner.LoadFromDir(yaraDir); yerr != nil {
		log.Printf("gateway: yara: load %s: %v (scanning disabled)", yaraDir, yerr)
	} else if n > 0 {
		log.Printf("gateway: yara: loaded %d ruleset(s) from %s", n, yaraDir)
	} else {
		log.Printf("gateway: yara: no rules (%s empty or missing, or built without CGO)", yaraDir)
	}

	// Revocation + config push + agent-block feed (optional): needs DB access.
	var revoked gateway.RevokedFunc
	var cfgFunc gateway.ConfigFunc
	var seenFunc gateway.SeenFunc
	var healthFunc gateway.HealthFunc
	var healthVFunc gateway.HealthWithVersionFunc
	var updateFunc gateway.UpdateDirectiveFunc
	var blockCfgFunc gateway.BlocklistConfigFunc
	var quarantineFunc gateway.QuarantineFunc
	var containFunc gateway.ContainmentFunc
	var restoreFunc gateway.RestoreFunc
	var snapshotFunc gateway.SnapshotFunc
	var fileActionsFunc gateway.FileActionsFunc
	var fileActionResultFunc gateway.FileActionResultFunc
	var inventoryFunc gateway.InventoryFunc
	if dsn := os.Getenv("STORE_DSN"); dsn != "" {
		// The gateway serves every agent regardless of tenant (mTLS CN auth, config, revocation,
		// heartbeat, FIM snapshots, file-action results), so it connects with the RLS super-admin
		// bypass — it must see/write across all tenants' agent data.
		if st, err := store.ConnectSuperadmin(ctx, dsn); err != nil {
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
			// v2.12.0: capture the agent's reported version + evaluate pending update directive so
			// the heartbeat response can tell an out-of-date agent to self-upgrade. v2.14.1 fix:
			// serve the binary from the gateway itself (relative URL) instead of the internal
			// Docker api hostname — agents on separate hosts can't resolve `api` DNS. Agent
			// prefixes the relative URL with its own gateway URL (which it already trusts via
			// mTLS) so no extra network path is needed.
			healthVFunc = func(ctx context.Context, cn string, degraded bool, detail, version string) error {
				return es.MarkHealthWithVersion(ctx, cn, degraded, detail, version, managerVersion)
			}
			// updateLog throttles the per-directive log line to once per (CN, decision) transition
			// + a heartbeat every minute per CN, so the log tells the story without spamming (the
			// heartbeat cadence is 30 s per agent — unthrottled would be 2 lines/agent/minute).
			var updateLogMu sync.Mutex
			updateLogLast := map[string]time.Time{}
			updateFunc = func(ctx context.Context, cn string) (*gateway.UpdateDirective, error) {
				pending, err := es.PendingAgentUpdate(ctx, cn, managerVersion)
				if err != nil {
					return nil, err
				}
				now := time.Now()
				logDecision := func(msg string) {
					updateLogMu.Lock()
					defer updateLogMu.Unlock()
					key := cn + "|" + msg
					if last, ok := updateLogLast[key]; ok && now.Sub(last) < time.Minute {
						return
					}
					updateLogLast[key] = now
					log.Printf("gateway: agent-update: %s cn=%q manager=%q", msg, cn, managerVersion)
				}
				if !pending {
					logDecision("no pending directive")
					return nil, nil
				}
				logDecision("pushing directive")
				// {arch} substituted by the agent on receipt so a single directive works across
				// amd64 and arm64 fleets.
				return &gateway.UpdateDirective{
					URL:     "/v1/agent-binary/{arch}",
					Version: managerVersion,
				}, nil
			}
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
					// YARA scan (only when we actually HAVE content — agent-storage mode ships
					// only metadata). Errors are logged, not returned: the snapshot itself is
					// already recorded, so a scanner glitch mustn't fail the upload.
					if len(content) > 0 && yaraScanner.HasRules() {
						matches, serr := yaraScanner.Scan(content)
						if serr != nil {
							log.Printf("gateway: yara scan %s@%s: %v", cn, sm.Path, serr)
							continue
						}
						if len(matches) > 0 {
							if perr := publishYARAAlert(ctx, b, cn, sm, matches); perr != nil {
								log.Printf("gateway: yara alert publish %s@%s: %v", cn, sm.Path, perr)
							} else {
								log.Printf("gateway: yara MATCH %s@%s: %d rule(s) — %s",
									cn, sm.Path, len(matches), matchNames(matches))
							}
						}
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
			// Software inventory (VA phase 1): unmarshal the agent's report and replace its stored
			// inventory. Unmarshalling here keeps the gateway package free of the agent import.
			inventoryFunc = func(ctx context.Context, cn string, body []byte) error {
				var inv agent.Inventory
				if err := json.Unmarshal(body, &inv); err != nil {
					return err
				}
				return st.ReplaceInventory(ctx, cn, inv)
			}
			// Agent-side auto-block: return a per-agent envelope. The manager's nftables_agent
			// integration is the source of truth — agent_scope filters which CNs it applies to;
			// table/set from the integration config override the agent's defaults. Pre-v2.11
			// this only returned IPs and the agent had to have AGENT_FIREWALL=nftables set
			// locally to do anything, which meant the UI integration was silently useless if
			// the operator hadn't also configured the env var. The v2.11 envelope makes the
			// integration the single source of truth.
			rs := respond.NewStore(st.Pool())
			pool := st.Pool()
			blockCfgFunc = func(ctx context.Context, agentCN string) (gateway.BlocklistConfig, error) {
				out := gateway.BlocklistConfig{Table: "deuswatch", Set: "blocklist", IPs: []string{}}
				cfgs, err := integrations.ListEnabledConfigs(ctx, pool, "nftables_agent")
				if err != nil {
					logBlockDecision(agentCN, "", 0, false, "resolve integrations failed: "+err.Error())
					return out, err
				}
				var match *integrations.EnabledConfig
				var scopeSeen string
				for i := range cfgs {
					sc := cfgs[i].Config["agent_scope"]
					if scopeSeen == "" {
						scopeSeen = sc
					}
					if integrations.AgentScopeMatches(sc, agentCN) {
						match = &cfgs[i]
						break
					}
				}
				if match == nil {
					reason := "no enabled nftables_agent integration"
					if len(cfgs) > 0 {
						reason = "agent_scope did not match (scope=" + scopeSeen + ")"
					}
					logBlockDecision(agentCN, scopeSeen, 0, false, reason)
					return out, nil // Enabled stays false — agent will not touch its firewall
				}
				if v := strings.TrimSpace(match.Config["table"]); v != "" {
					out.Table = v
				}
				if v := strings.TrimSpace(match.Config["set"]); v != "" {
					out.Set = v
				}
				ips, err := rs.ActiveBlocks(ctx)
				if err != nil {
					logBlockDecision(agentCN, match.Config["agent_scope"], 0, true, "ActiveBlocks failed: "+err.Error())
					return out, err
				}
				out.Enabled = true
				if ips != nil {
					out.IPs = ips
				}
				logBlockDecision(agentCN, match.Config["agent_scope"], len(out.IPs), true, "matched integration "+match.Name)
				return out, nil
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
	mux.HandleFunc("POST /v1/heartbeat", gateway.HeartbeatHandlerFull(seenFunc, healthFunc, healthVFunc, revoked, updateFunc))
	// v2.14.1: self-update binary served over mTLS, same trust boundary as every other agent-
	// facing endpoint. Points at /agents (baked into the runtime-cgo image by the api build
	// stage in deploy/Dockerfile — same directory the api's /api/agent/binary route reads from).
	mux.HandleFunc("GET /v1/agent-binary/{arch}", gateway.AgentBinaryHandler("/agents"))
	mux.HandleFunc("GET /v1/blocklist", gateway.BlocklistConfigHandler(blockCfgFunc))
	mux.HandleFunc("GET /v1/quarantine", gateway.QuarantineHandler(quarantineFunc))
	mux.HandleFunc("GET /v1/containment", gateway.ContainmentHandler(containFunc))
	mux.HandleFunc("GET /v1/restore", gateway.RestoreHandler(restoreFunc))
	mux.HandleFunc("POST /v1/snapshots", gateway.SnapshotHandler(snapshotFunc, revoked))
	mux.HandleFunc("POST /v1/inventory", gateway.InventoryHandler(inventoryFunc, revoked))
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
		log.Printf("DeusWatch gateway %s (mTLS) listening on %s", managerVersion, addr)
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

// publishYARAAlert emits an ingest.Event that flows through the same normalize→enrich→detect→store
// pipeline as any other alert. Choices made here:
//   - dw_label = "yara_malicious" so the dashboard treats it as an alert (dw_label is the "this is
//     surfaced" marker) and severity escalation ladder can bump it further.
//   - event.severity starts at HIGH: a YARA match on a file dropped/changed on one of our hosts is
//     never routine noise. It stays at HIGH here and the enricher can escalate to critical if the
//     file hash also matches a known-bad reputation (community consensus).
//   - dw_filehash_verdict/detail carry the match — the FIM verdict column on the Events & Alerts
//     table already renders these, so the UI shows the YARA verdict with zero UI changes.
//   - action = "yara_match" is a stable string the response layer can decision-table on later.
func publishYARAAlert(ctx context.Context, b *bus.Bus, agentName string, sm gateway.SnapshotMeta, matches []yara.Match) error {
	names := matchNames(matches)
	ev := &ingest.Event{
		Timestamp: time.Now(),
		Event: ingest.EventFields{
			Category: "malware",
			Action:   "yara_match",
			Outcome:  "detected",
			Severity: ingest.SeverityHigh,
			Dataset:  "yara",
			Original: "yara scan matched " + names,
		},
		Agent:     &ingest.Agent{ID: agentName},
		File:      &ingest.File{Path: sm.Path, HashSHA256: sm.SHA256},
		Rule:      &ingest.Rule{ID: "deuswatch_yara", Name: "YARA match: " + names},
		DeusWatch: ingest.DeusWatch{Label: "yara_malicious"},
	}
	ev.DeusWatch.FileHash.Verdict = "yara_malicious"
	ev.DeusWatch.FileHash.Detail = "matched: " + names
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return b.Publish(ctx, bus.SubjectLogsNormalized, body)
}

// matchNames formats a compact, deterministic "rule1, rule2, rule3" string for logs + UI.
func matchNames(matches []yara.Match) string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.Rule)
	}
	return strings.Join(names, ", ")
}
