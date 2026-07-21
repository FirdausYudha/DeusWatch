// Command agent is the DeusWatch endpoint log collector (Linux & Windows).
//
// Default sources are selected per-OS at compile time (Linux: auth/syslog files;
// Windows: Event Log) — see internal/agent. Override with a single source via
// LOG_FILE. All lines are sent to the manager (gateway) over mTLS.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"deuswatch/internal/agent"
	"deuswatch/internal/ingest"
	"deuswatch/internal/mtls"
)

func main() {
	enrollMode := flag.Bool("enroll", false, "exchange an enrollment token for a certificate then exit")
	enrollToken := flag.String("token", "", "enrollment token (-enroll mode)")
	enrollName := flag.String("name", "", "agent name (-enroll mode)")
	enrollManager := flag.String("manager", "http://localhost:8080", "manager URL for enroll")
	outDir := flag.String("out", "", "certificate output directory (default CERT_DIR)")
	serviceCmd := flag.String("service", "", "Windows Service control: install|uninstall|start|stop (Windows only)")
	uninstall := flag.Bool("uninstall", false, "stop the agent service and remove all installed files, then exit")
	flag.Parse()

	if *uninstall {
		selfUninstall()
		return
	}

	if *enrollMode {
		dir := *outDir
		if dir == "" {
			dir = getenv("CERT_DIR", "deploy/certs")
		}
		if err := doEnroll(*enrollManager, *enrollToken, *enrollName, dir); err != nil {
			log.Fatalf("agent: enroll failed: %v", err)
		}
		return
	}

	// Service control (install/uninstall/start/stop) — per-OS implementation.
	if *serviceCmd != "" {
		if err := controlService(*serviceCmd); err != nil {
			log.Fatalf("agent: service %s: %v", *serviceCmd, err)
		}
		return
	}

	// When launched by the Windows Service Control Manager, run as a native service
	// (runService sets up ctx & reports status). Otherwise run in the console.
	if runningAsService() {
		setupServiceLogging() // SCM discards stderr; send logs to a file so they're visible
		runService()
		return
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	runAgent(ctx, stopSignals)
}

// runAgent runs the agent collector loop until ctx is cancelled. onConfigChange is
// called when the manager pushes a new config version (triggers shutdown so the
// supervisor — systemd/SCM — restarts the agent with the new config).
func runAgent(ctx context.Context, onConfigChange func()) {
	gatewayURL := getenv("GATEWAY_URL", "https://localhost:8443")
	certDir := getenv("CERT_DIR", "deploy/certs")
	host := getenv("HOST_NAME", hostname())
	fromStart := os.Getenv("FROM_START") == "1"

	shipper, err := agent.NewShipper(gatewayURL, mtls.Paths(certDir))
	if err != nil {
		log.Fatalf("agent: shipper (certificates in %q?): %v", certDir, err)
	}

	buf, err := agent.NewBuffer(getenv("BUFFER_DIR", "agent-buffer"), 1000)
	if err != nil {
		log.Fatalf("agent: buffer: %v", err)
	}

	// FIM known-good snapshots (enables one-click restore of a defaced/modified text file).
	// On by default; set FIM_SNAPSHOTS=0 to disable (diff still works, restore doesn't).
	var snapStore *agent.SnapshotStore
	if os.Getenv("FIM_SNAPSHOTS") != "0" {
		if ss, serr := agent.NewSnapshotStore(getenv("FIM_SNAPSHOT_DIR", agent.DefaultSnapshotDir())); serr != nil {
			log.Printf("agent: fim snapshots disabled: %v", serr)
		} else {
			agent.SetFIMSnapshots(ss)
			snapStore = ss
			// Versioned snapshots (ADR 0002): the FIM scanner captures dated versions locally and
			// pushes their metadata into snapCh; the uploader batches them to the manager.
			snapCh := make(chan agent.SnapshotMeta, 256)
			agent.SetFIMSnapshotSink(func(m agent.SnapshotMeta) {
				select {
				case snapCh <- m:
				default: // uploader is behind — drop this metadata rather than block the scan
				}
			})
			go runSnapshotUploader(ctx, shipper, snapCh)
		}
	}

	// Sources: pushed config from the manager if present, otherwise per-OS defaults / LOG_FILE.
	sources := resolveSources()
	var configVersion int
	if cfg, err := shipper.FetchConfig(ctx); err != nil {
		log.Printf("agent: failed to fetch pushed config (using defaults): %v", err)
	} else if cfg != nil && len(cfg.Sources) > 0 {
		sources, configVersion = cfg.Sources, cfg.Version
		log.Printf("agent: pushed config v%d applied from the manager", cfg.Version)
	}
	if len(sources) == 0 {
		log.Fatalf("agent: no log sources — set LOG_FILE or run on a supported OS")
	}

	// Watch for config changes; a new version -> shutdown so the service-manager restarts & applies it.
	go watchConfig(ctx, shipper, configVersion, onConfigChange)
	// Resend buffered batches (store-and-forward) + heartbeat.
	go drainBuffer(ctx, shipper, buf)
	go heartbeatLoop(ctx, shipper, buf, onConfigChange)
	// Agent-side firewall auto-block (opt-in via AGENT_FIREWALL=nftables, Linux only):
	// poll the manager's blocklist and apply it to a local nftables set.
	if strings.EqualFold(os.Getenv("AGENT_FIREWALL"), "nftables") {
		go runFirewall(ctx, shipper)
	}
	// Endpoint file remediation (opt-in via AGENT_FILE_REMEDIATION=quarantine|delete):
	// poll the manager's known-bad file list and quarantine/delete matching files.
	if mode := strings.ToLower(strings.TrimSpace(os.Getenv("AGENT_FILE_REMEDIATION"))); mode == "quarantine" || mode == "delete" {
		go runFileRemediation(ctx, shipper, mode)
	}
	// FIM one-click restore: poll the manager's restore requests and write the known-good
	// snapshot back to each file. Active whenever snapshots are enabled (the default).
	if snapStore != nil {
		go runFimRestore(ctx, shipper, snapStore, host)
	}
	// On-demand FIM file actions (snapshot_now / quarantine / restore_version) from the UI.
	go runFileActions(ctx, snapStore, shipper, host)
	// Software inventory (Vulnerability Assessment): report installed packages + OS release
	// periodically. On by default; INVENTORY=0 disables it.
	if os.Getenv("INVENTORY") != "0" {
		go runInventory(ctx, shipper)
	}
	// Host network containment (opt-in via AGENT_CONTAINMENT=1): poll the manager's isolation
	// directive and firewall the host off from the LAN (except the manager) when told to.
	if containmentEnabled(os.Getenv("AGENT_CONTAINMENT")) {
		go runContainment(ctx, shipper, gatewayURL)
	}

	// FIM who-data (opt-in via AGENT_WHODATA=1, Linux + root + auditd): attribute each file
	// change to the process/user that made it, via the audit subsystem. Best-effort — if it
	// can't be enabled, FIM keeps working without the "who". Set before Collect so the FIM
	// scanner picks it up.
	if b, _ := strconv.ParseBool(os.Getenv("AGENT_WHODATA")); b {
		var fimRoots []string
		for _, s := range sources {
			if s.Type != "fim" {
				continue
			}
			for _, p := range strings.Split(s.Path, ",") {
				if p = strings.TrimSpace(p); p != "" {
					fimRoots = append(fimRoots, p)
				}
			}
		}
		if len(fimRoots) == 0 {
			log.Printf("agent: AGENT_WHODATA set but no FIM sources — who-data idle")
		} else if wd, werr := agent.StartWhoData(ctx, fimRoots, os.Getenv("AGENT_AUDIT_LOG")); werr != nil {
			log.Printf("agent: who-data disabled: %v", werr)
		} else {
			agent.SetFIMWhoData(wd)
		}
	}

	lines := make(chan agent.Line, 256)
	go func() {
		agent.Collect(ctx, sources, fromStart, lines)
		close(lines)
	}()

	log.Printf("DeusWatch agent: host=%s, %d sources -> %s", host, len(sources), gatewayURL)
	for _, s := range sources {
		log.Printf("  source: dataset=%s type=%s path=%s", s.Dataset, s.Type, s.Path)
	}

	batch := make([]ingest.RawLog, 0, 64)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if body, err := json.Marshal(batch); err == nil {
			if serr := shipper.SendRaw(ctx, body); serr != nil {
				if berr := buf.Save(body); berr == nil {
					log.Printf("agent: manager offline — %d lines buffered (%v)", len(batch), serr)
				} else {
					log.Printf("agent: failed to send & buffer: %v / %v", serr, berr)
				}
			} else {
				log.Printf("agent: sent %d lines", len(batch))
			}
		}
		batch = batch[:0]
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case line, ok := <-lines:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ingest.RawLog{
				Timestamp: time.Now(), Host: host, Dataset: line.Dataset, Message: line.Message,
			})
			if len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// runInventory reports the host's software inventory (installed packages + OS release) shortly
// after startup and then on a slow interval — inventory changes rarely, so the default is 12h
// (INVENTORY_INTERVAL overrides, Go duration). A collect/ship failure is logged and retried next
// tick; it never blocks the agent.
func runInventory(ctx context.Context, shipper *agent.Shipper) {
	interval := 12 * time.Hour
	if d, err := time.ParseDuration(os.Getenv("INVENTORY_INTERVAL")); err == nil && d > 0 {
		interval = d
	}
	report := func() {
		inv := agent.CollectInventory(ctx)
		if err := shipper.PostInventory(ctx, inv); err != nil {
			log.Printf("agent: inventory report failed: %v", err)
			return
		}
		log.Printf("agent: inventory reported (%s %s, %d packages)", inv.OSID, inv.OSVersion, len(inv.Packages))
	}
	// A short delay so it doesn't contend with the rest of startup, then the first report.
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	report()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report()
		}
	}
}

// resolveSources: LOG_FILE (a single source) if set, otherwise per-OS defaults.
func resolveSources() []agent.Source {
	if lf := os.Getenv("LOG_FILE"); lf != "" {
		return []agent.Source{{Dataset: getenv("DATASET", "file"), Type: "file", Path: lf}}
	}
	return agent.DefaultSources()
}

// watchConfig polls the pushed config; if the version increases, it triggers a
// shutdown so the service-manager restarts the agent with the new config (simple
// atomic apply).
func watchConfig(ctx context.Context, shipper *agent.Shipper, current int, stop func()) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cfg, err := shipper.FetchConfig(ctx)
			if err != nil || cfg == nil {
				continue
			}
			if cfg.Version > current {
				log.Printf("agent: new config v%d detected — restarting to apply", cfg.Version)
				stop()
				return
			}
		}
	}
}

// drainBuffer resends disk-buffered batches when the manager comes back online.
func drainBuffer(ctx context.Context, shipper *agent.Shipper, buf *agent.Buffer) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			files, err := buf.Pending()
			if err != nil {
				continue
			}
			for _, f := range files {
				body, rerr := os.ReadFile(f)
				if rerr != nil {
					_ = buf.Remove(f)
					continue
				}
				if serr := shipper.SendRaw(ctx, body); serr != nil {
					break // manager still offline; retry later
				}
				_ = buf.Remove(f)
				log.Printf("agent: buffer resent (%s)", filepath.Base(f))
			}
		}
	}
}

// runFirewall polls the manager's blocklist and syncs it into the local nftables set.
// Table/set names come from NFT_TABLE/NFT_SET (defaults deuswatch/blocklist).
func runFirewall(ctx context.Context, shipper *agent.Shipper) {
	table := getenv("NFT_TABLE", "deuswatch")
	set := getenv("NFT_SET", "blocklist")
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ips, err := shipper.FetchBlocklist(ctx)
			if err != nil {
				log.Printf("agent: fetch blocklist: %v", err)
				continue
			}
			key := strings.Join(ips, ",")
			if key == last {
				continue // unchanged
			}
			if err := agent.ApplyBlocklist(table, set, ips); err != nil {
				log.Printf("agent: apply blocklist: %v", err)
				continue
			}
			last = key
			log.Printf("agent: firewall synced %d blocked IP(s) into nft set %s/%s", len(ips), table, set)
		}
	}
}

// containmentEnabled reports whether AGENT_CONTAINMENT opts the host into isolation.
// Any non-empty value except 0/false/off/no enables it (so "1", "nftables", "netsh" all work).
func containmentEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

// runContainment polls the manager's host-isolation directive and applies/clears local
// isolation live. The agent ALWAYS keeps its own gateway reachable, so containment can never
// sever the agent↔manager link (and thus this very poll loop that also lifts the isolation).
func runContainment(ctx context.Context, shipper *agent.Shipper, gatewayURL string) {
	selfAllow := gatewayIPs(gatewayURL)
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	isolated := false
	lastKey := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d, err := shipper.FetchContainment(ctx)
			if err != nil {
				log.Printf("agent: fetch containment: %v", err)
				continue
			}
			if d.Isolate {
				allow := append(append([]string{}, selfAllow...), d.AllowIPs...)
				key := strings.Join(allow, ",")
				if isolated && key == lastKey {
					continue // already isolated with the same allow-list
				}
				if err := agent.ApplyIsolation(allow); err != nil {
					log.Printf("agent: apply isolation: %v", err)
					continue
				}
				isolated, lastKey = true, key
				log.Printf("agent: HOST ISOLATED (reason=%q; %d allow IP(s)) — LAN cut except manager", d.Reason, len(allow))
			} else if isolated {
				if err := agent.ClearIsolation(); err != nil {
					log.Printf("agent: clear isolation: %v", err)
					continue
				}
				isolated, lastKey = false, ""
				log.Printf("agent: isolation lifted — connectivity restored")
			}
		}
	}
}

// gatewayIPs resolves the manager/gateway host to IP literals the agent must always allow
// while isolated, so its lifeline to the manager is never cut.
func gatewayIPs(gatewayURL string) []string {
	u, err := url.Parse(gatewayURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	return addrs
}

// runFileRemediation polls the manager's known-bad file list and quarantines/deletes any
// local file whose current hash still matches (mode comes from AGENT_FILE_REMEDIATION).
func runFileRemediation(ctx context.Context, shipper *agent.Shipper, mode string) {
	dir := getenv("QUARANTINE_DIR", agent.DefaultQuarantineDir())
	log.Printf("agent: file remediation active (mode=%s, dir=%s)", mode, dir)
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			targets, err := shipper.FetchQuarantine(ctx)
			if err != nil {
				continue
			}
			for _, ft := range targets {
				if acted, err := agent.RemediateFile(ft.Path, ft.SHA256, mode, dir); err != nil {
					log.Printf("agent: remediate %s: %v", ft.Path, err)
				} else if acted {
					log.Printf("agent: %sd known-bad file %s (sha256 %s…)", mode, ft.Path, ft.SHA256[:12])
				}
			}
		}
	}
}

// runFimRestore polls the manager's restore requests and writes each file's known-good
// snapshot back (undo a defacement). It emits a FIM 'restored' event so the action is
// visible in the timeline. Restores run every 15s (faster than the FIM scan) so a one-click
// restore feels responsive.
func runFimRestore(ctx context.Context, shipper *agent.Shipper, snaps *agent.SnapshotStore, host string) {
	log.Printf("agent: FIM one-click restore active")
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			paths, err := shipper.FetchRestore(ctx)
			if err != nil {
				continue
			}
			for _, p := range paths {
				if rerr := snaps.Restore(p); rerr != nil {
					log.Printf("agent: fim restore %s: %v", p, rerr)
					continue
				}
				log.Printf("agent: restored %s to its known-good snapshot", p)
				// Emit a restored event so the dashboard shows the action.
				c := agent.FIMChange{Path: p, Action: "restored"}
				if body, merr := json.Marshal(c); merr == nil {
					_ = shipper.Send(ctx, []ingest.RawLog{{
						Timestamp: time.Now(), Host: host, Dataset: "fim", Message: string(body),
					}})
				}
			}
		}
	}
}

// runFileActions polls the manager for on-demand file operations and executes them (ADR 0002):
// "snapshot_now" captures a version immediately; "quarantine" moves the current file into the
// agent's quarantine dir (read-only) for blue-team analysis; "restore_version" writes a specific
// dated version back to the file. Each outcome is reported back to the manager.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func runFileActions(ctx context.Context, snaps *agent.SnapshotStore, shipper *agent.Shipper, host string) {
	qdir := getenv("QUARANTINE_DIR", agent.DefaultQuarantineDir())
	// Kill-switch process control. procSrc is nil on platforms without verified introspection,
	// which KillSwitch turns into an explicit failure rather than a silent skip.
	procSrc := agent.NewProcSource()
	// Business-critical processes this deployment must never kill, however strong the detection
	// (an ERP, a database, a line-of-business service). DeusWatch cannot know these; the admin
	// declares them. Comma-separated process names, e.g. KILL_PROTECTED=sapstartsrv,oracle
	var protectedProcs []string
	for _, p := range strings.Split(getenv("KILL_PROTECTED", ""), ",") {
		if p = strings.TrimSpace(p); p != "" {
			protectedProcs = append(protectedProcs, p)
		}
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			actions, err := shipper.FetchFileActions(ctx)
			if err != nil {
				continue
			}
			for _, a := range actions {
				status, result := "done", ""
				switch a.Action {
				case "snapshot_now":
					if meta, ok := agent.CaptureVersionNow(a.Path); ok {
						if serr := shipper.PostSnapshots(ctx, []agent.SnapshotMeta{meta}); serr != nil {
							status, result = "failed", "upload: "+serr.Error()
						} else {
							result = "captured version " + meta.SHA256[:12]
						}
					} else {
						status, result = "failed", "not a small text file, or snapshots disabled"
					}
				case "quarantine":
					if dest, qerr := agent.QuarantineForAnalysis(a.Path, qdir); qerr != nil {
						status, result = "failed", qerr.Error()
					} else {
						result = "quarantined to " + dest
						// Surface the action on the dashboard too.
						c := agent.FIMChange{Path: a.Path, Action: "quarantined"}
						if body, merr := json.Marshal(c); merr == nil {
							_ = shipper.Send(ctx, []ingest.RawLog{{
								Timestamp: time.Now(), Host: host, Dataset: "fim", Message: string(body),
							}})
						}
						log.Printf("agent: quarantined %s -> %s", a.Path, dest)
					}
				case "restore_version":
					if snaps == nil {
						status, result = "failed", "snapshots disabled on this agent"
						break
					}
					// Safety: capture the CURRENT content as a version first, so restoring never
					// loses the pre-restore state (best-effort — ignored if not a small text file).
					if meta, ok := agent.CaptureVersionNow(a.Path); ok {
						_ = shipper.PostSnapshots(ctx, []agent.SnapshotMeta{meta})
					}
					// Prefer manager-supplied content (Phase 5 storage / host-loss recovery); else
					// resolve the version from the agent's local content-addressed blob store.
					var rerr error
					if a.Content != "" {
						rerr = snaps.RestoreContent(a.Path, a.Content)
					} else {
						rerr = snaps.RestoreVersion(a.Path, a.VersionSHA256)
					}
					if rerr != nil {
						status, result = "failed", rerr.Error()
					} else {
						result = "restored to version " + shortHash(a.VersionSHA256)
						c := agent.FIMChange{Path: a.Path, Action: "restored"}
						if body, merr := json.Marshal(c); merr == nil {
							_ = shipper.Send(ctx, []ingest.RawLog{{
								Timestamp: time.Now(), Host: host, Dataset: "fim", Message: string(body),
							}})
						}
						log.Printf("agent: restored %s to version %s", a.Path, shortHash(a.VersionSHA256))
					}
				case "kill_process":
					// The manager proposed this kill and a human (or KILL_SWITCH_AUTO) approved it,
					// but the agent is the last line of defence and re-verifies independently: the
					// live process must still match the identity captured at detection, and must not
					// be protected. See internal/agent/killproc.go for the full policy.
					outcome, why := agent.KillSwitch(
						agent.KillTarget{PID: a.PID, WantExe: a.Path, WantName: a.ProcName, WantStart: a.ProcStart},
						procSrc, os.Getpid(), os.Getppid(), protectedProcs)
					// Only a genuine failure is reported as failed. A deliberate refusal is a
					// completed decision, carried in the result so the UI can show WHY nothing was
					// killed instead of implying containment.
					if outcome == agent.KillFailed {
						status = "failed"
					}
					result = string(outcome)
					if why != "" {
						result += ": " + why
					}
					c := agent.FIMChange{Path: a.Path, Action: "kill_" + string(outcome)}
					if body, merr := json.Marshal(c); merr == nil {
						_ = shipper.Send(ctx, []ingest.RawLog{{
							Timestamp: time.Now(), Host: host, Dataset: "fim", Message: string(body),
						}})
					}
					log.Printf("agent: kill-switch pid %d (%s): %s", a.PID, a.ProcName, result)
				default:
					status, result = "failed", "unknown action"
				}
				if rerr := shipper.PostFileActionResult(ctx, a.ID, status, result); rerr != nil {
					log.Printf("agent: report file-action %d: %v", a.ID, rerr)
				}
			}
		}
	}
}

// maxSnapshotUploadBytes keeps each snapshot POST safely under the gateway's 8 MiB body cap —
// important in manager-storage mode, where each version carries its (up to multi-MiB) content.
const maxSnapshotUploadBytes = 7 << 20

// metaBytes is the rough wire size of one snapshot metadata item (content + diff + overhead).
func metaBytes(m agent.SnapshotMeta) int { return len(m.Content) + len(m.Diff) + 256 }

// runSnapshotUploader batches captured FIM version metadata and ships it to the manager every
// few seconds (ADR 0002 Phase 2). It flushes on item count, accumulated BYTES (so a manager-mode
// batch of large files never exceeds the gateway body limit), or the tick.
func runSnapshotUploader(ctx context.Context, shipper *agent.Shipper, in <-chan agent.SnapshotMeta) {
	log.Printf("agent: FIM versioned-snapshot uploader active")
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	var batch []agent.SnapshotMeta
	batchBytes := 0
	recount := func() {
		batchBytes = 0
		for _, m := range batch {
			batchBytes += metaBytes(m)
		}
	}
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := shipper.PostSnapshots(ctx, batch); err != nil {
			log.Printf("agent: upload snapshots (%d): %v", len(batch), err)
			// Keep the batch to retry on the next tick (bounded — drop if it grows too large).
			if len(batch) > 2000 {
				batch = batch[len(batch)-2000:]
			}
			recount()
			return
		}
		batch = nil
		batchBytes = 0
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case m := <-in:
			// Flush first if adding this item (esp. its manager-mode content) would push the
			// batch over the wire limit.
			if len(batch) > 0 && batchBytes+metaBytes(m) > maxSnapshotUploadBytes {
				flush()
			}
			batch = append(batch, m)
			batchBytes += metaBytes(m)
			if len(batch) >= 100 || batchBytes >= maxSnapshotUploadBytes {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// heartbeatLoop sends periodic heartbeats to the manager, carrying self-reported
// health: degraded when the offline buffer is piling up (log shipping is failing even
// though the heartbeat itself gets through). If the manager reports the agent as
// revoked (ErrRevoked), the agent self-uninstalls and stops.
func heartbeatLoop(ctx context.Context, shipper *agent.Shipper, buf *agent.Buffer, stop func()) {
	health := func() agent.Health {
		if buf == nil {
			return agent.Health{}
		}
		pending, err := buf.Pending()
		if err != nil || len(pending) == 0 {
			return agent.Health{}
		}
		return agent.Health{Degraded: true,
			Detail: fmt.Sprintf("%d buffered batch(es) awaiting delivery", len(pending))}
	}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := shipper.Heartbeat(ctx, health()); err != nil {
				if errors.Is(err, agent.ErrRevoked) {
					log.Printf("agent: this agent was revoked by the manager — self-uninstalling")
					selfUninstall()
					stop()
					return
				}
				log.Printf("agent: heartbeat failed: %v", err)
			}
		}
	}
}

// doEnroll exchanges an enrollment token for a unique client certificate and
// saves it (ca.crt, client.crt, client.key) to dir.
func doEnroll(manager, token, name, dir string) error {
	if token == "" || name == "" {
		return fmt.Errorf("-token and -name are required")
	}
	body, _ := json.Marshal(map[string]string{"token": token, "name": name, "os": runtime.GOOS})
	resp, err := http.Post(strings.TrimRight(manager, "/")+"/api/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("manager rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var bundle struct {
		AgentID    string `json:"agent_id"`
		CACert     string `json:"ca_cert"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	p := mtls.Paths(dir)
	if err := os.WriteFile(p.CACert, []byte(bundle.CACert), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p.ClientCert, []byte(bundle.ClientCert), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p.ClientKey, []byte(bundle.ClientKey), 0o600); err != nil {
		return err
	}
	log.Printf("agent: enrolled as %q (id=%s); certificates saved in %s", name, bundle.AgentID, dir)
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}
