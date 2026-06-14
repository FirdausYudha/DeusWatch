package respond

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// runnerFunc runs an external command; stubbed in tests so the CLI-based responders
// (nftables/cscli) are tested without actually executing anything.
type runnerFunc func(ctx context.Context, name string, args ...string) error

func execRunner(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ── DryRun ────────────────────────────────────────────────

// DryRunResponder only logs the action it WOULD run — the safe default.
type DryRunResponder struct{ backend string }

func NewDryRunResponder(backend string) *DryRunResponder {
	if backend == "" {
		backend = "none"
	}
	return &DryRunResponder{backend: backend}
}

func (d *DryRunResponder) Name() string { return "dryrun(" + d.backend + ")" }

func (d *DryRunResponder) Block(_ context.Context, ip string, dur time.Duration) error {
	log.Printf("respond[dry-run]: BLOCK %s for %s via %s", ip, durLabel(dur), d.backend)
	return nil
}

func (d *DryRunResponder) Unblock(_ context.Context, ip string) error {
	log.Printf("respond[dry-run]: UNBLOCK %s via %s", ip, d.backend)
	return nil
}

// ── nftables (Linux) ──────────────────────────────────────

// NftablesResponder adds/removes IPs in a named nftables set. The set must already
// be created with the timeout flag, e.g.:
//
//	nft add table inet deuswatch
//	nft add set inet deuswatch banlist { type ipv4_addr\; flags timeout\; }
//	nft add rule inet deuswatch input ip saddr @banlist drop
type NftablesResponder struct {
	table string
	set   string
	run   runnerFunc
}

func NewNftablesResponder(table, set string) *NftablesResponder {
	if table == "" {
		table = "deuswatch"
	}
	if set == "" {
		set = "banlist"
	}
	return &NftablesResponder{table: table, set: set, run: execRunner}
}

func (n *NftablesResponder) Name() string { return "nftables" }

func (n *NftablesResponder) Block(ctx context.Context, ip string, dur time.Duration) error {
	elem := ip
	if dur > 0 {
		elem = fmt.Sprintf("%s timeout %ds", ip, int(dur.Seconds()))
	}
	return n.run(ctx, "nft", "add", "element", "inet", n.table, n.set, "{ "+elem+" }")
}

func (n *NftablesResponder) Unblock(ctx context.Context, ip string) error {
	return n.run(ctx, "nft", "delete", "element", "inet", n.table, n.set, "{ "+ip+" }")
}

// ── CrowdSec (cscli) ──────────────────────────────────────

// CrowdSecResponder creates/removes a decision via cscli (local LAPI).
type CrowdSecResponder struct{ run runnerFunc }

func NewCrowdSecResponder() *CrowdSecResponder { return &CrowdSecResponder{run: execRunner} }

func (c *CrowdSecResponder) Name() string { return "crowdsec" }

func (c *CrowdSecResponder) Block(ctx context.Context, ip string, dur time.Duration) error {
	d := "8760h" // permanent ~ 1 year
	if dur > 0 {
		d = crowdsecDuration(dur)
	}
	return c.run(ctx, "cscli", "decisions", "add", "--ip", ip, "--duration", d, "--type", "ban", "--reason", "deuswatch")
}

func (c *CrowdSecResponder) Unblock(ctx context.Context, ip string) error {
	return c.run(ctx, "cscli", "decisions", "delete", "--ip", ip)
}

// ── Mikrotik (RouterOS REST v7) ───────────────────────────

// MikrotikResponder adds the IP to a RouterOS address-list via the REST API; the
// admin's own firewall filter rule that drops that list does the actual blocking.
type MikrotikResponder struct {
	baseURL string // e.g. https://192.168.88.1
	user    string
	pass    string
	list    string
	hc      *http.Client
}

func NewMikrotikResponder(baseURL, user, pass, list string) *MikrotikResponder {
	if list == "" {
		list = "deuswatch_ban"
	}
	return &MikrotikResponder{
		baseURL: strings.TrimRight(baseURL, "/"), user: user, pass: pass, list: list,
		hc: &http.Client{Timeout: 8 * time.Second},
	}
}

func (m *MikrotikResponder) Name() string { return "mikrotik" }

func (m *MikrotikResponder) Block(ctx context.Context, ip string, dur time.Duration) error {
	payload := map[string]string{"list": m.list, "address": ip, "comment": "deuswatch"}
	if dur > 0 {
		payload["timeout"] = mikrotikDuration(dur)
	}
	body, _ := json.Marshal(payload)
	return m.do(ctx, http.MethodPut, "/rest/ip/firewall/address-list", body)
}

func (m *MikrotikResponder) Unblock(ctx context.Context, ip string) error {
	// RouterOS: removing by .id query; kept simple here — POST remove by address.
	body, _ := json.Marshal(map[string]string{"list": m.list, "address": ip})
	return m.do(ctx, http.MethodPost, "/rest/ip/firewall/address-list/remove", body)
}

func (m *MikrotikResponder) do(ctx context.Context, method, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, m.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(m.user, m.pass)
	resp, err := m.hc.Do(req)
	if err != nil {
		return fmt.Errorf("mikrotik: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mikrotik: HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── duration & env-selection utils ────────────────────────

func durLabel(d time.Duration) string {
	if d <= 0 {
		return "permanent"
	}
	return d.String()
}

// crowdsecDuration: cscli accepts a Go duration ("10m","1h","24h").
func crowdsecDuration(d time.Duration) string { return d.String() }

// mikrotikDuration: RouterOS uses a format like "10m","1h","1d".
func mikrotikDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
	return d.String()
}

// ResponderFromEnv selects a responder from the RESPONDER env var:
//
//	dryrun (default) | nftables | crowdsec | mikrotik | none
//
// none disables execution entirely (returns nil). Unless RESPONSE_LIVE=1,
// nftables/crowdsec/mikrotik are WRAPPED in dry-run so there are no accidental blocks in dev.
func ResponderFromEnv() Responder {
	switch strings.ToLower(os.Getenv("RESPONDER")) {
	case "", "dryrun":
		return NewDryRunResponder("none")
	case "none":
		return nil
	case "nftables":
		return liveOrDry(NewNftablesResponder(os.Getenv("NFT_TABLE"), os.Getenv("NFT_SET")))
	case "crowdsec":
		return liveOrDry(NewCrowdSecResponder())
	case "mikrotik":
		return liveOrDry(NewMikrotikResponder(
			os.Getenv("MIKROTIK_URL"), os.Getenv("MIKROTIK_USER"),
			os.Getenv("MIKROTIK_PASS"), os.Getenv("MIKROTIK_LIST")))
	default:
		log.Printf("respond: unknown RESPONDER %q — using dry-run", os.Getenv("RESPONDER"))
		return NewDryRunResponder("none")
	}
}

func liveOrDry(r Responder) Responder {
	if live, _ := strconv.ParseBool(os.Getenv("RESPONSE_LIVE")); live {
		log.Printf("respond: LIVE responder active: %s", r.Name())
		return r
	}
	log.Printf("respond: responder %s wrapped in dry-run (set RESPONSE_LIVE=1 for real execution)", r.Name())
	return NewDryRunResponder(r.Name())
}
