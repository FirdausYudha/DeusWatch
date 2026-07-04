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
	go heartbeatLoop(ctx, shipper, onConfigChange)
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
	// Host network containment (opt-in via AGENT_CONTAINMENT=1): poll the manager's isolation
	// directive and firewall the host off from the LAN (except the manager) when told to.
	if containmentEnabled(os.Getenv("AGENT_CONTAINMENT")) {
		go runContainment(ctx, shipper, gatewayURL)
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

// heartbeatLoop sends periodic heartbeats to the manager. If the manager reports the
// agent as revoked (ErrRevoked), the agent self-uninstalls and stops.
func heartbeatLoop(ctx context.Context, shipper *agent.Shipper, stop func()) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := shipper.Heartbeat(ctx); err != nil {
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
