package respond

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
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

// NewMikrotikResponder builds a responder for one router. insecure=true skips TLS
// certificate verification - RouterOS ships a self-signed cert, so this is the common
// setting when the router is reached over a trusted tunnel (WireGuard/IPsec). Leave it
// false when the router presents a CA-trusted certificate.
func NewMikrotikResponder(baseURL, user, pass, list string, insecure bool) *MikrotikResponder {
	if list == "" {
		list = "deuswatch_ban"
	}
	// Tolerate an address entered without a scheme (e.g. "10.10.10.8"): the RouterOS REST
	// API is HTTPS-only, so default to https:// so a bare IP/host still works.
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL != "" && !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	hc := &http.Client{Timeout: 8 * time.Second}
	if insecure {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return &MikrotikResponder{baseURL: baseURL, user: user, pass: pass, list: list, hc: hc}
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

// mtEntry is one RouterOS address-list row.
type mtEntry struct {
	ID      string `json:".id"`
	Address string `json:"address"`
	Comment string `json:"comment"`
}

// Sync reconciles the router's DeusWatch-managed address-list to `desired`: it adds any
// wanted IP not present and removes any managed IP no longer wanted. Only entries this
// responder created (comment "deuswatch") are ever removed - manually-added entries are
// left untouched. This is what makes a ban/unban in DeusWatch propagate to the router
// within one sync interval and self-heal after a reboot.
func (m *MikrotikResponder) Sync(ctx context.Context, desired []string) error {
	current, err := m.currentManaged(ctx)
	if err != nil {
		return err
	}
	want := make(map[string]bool, len(desired))
	for _, ip := range desired {
		want[ip] = true
	}
	var firstErr error
	// Add missing.
	for ip := range want {
		if _, present := current[ip]; !present {
			if err := m.Block(ctx, ip, 0); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	// Remove stale (managed but no longer wanted).
	for ip, e := range current {
		if !want[ip] {
			if err := m.removeByID(ctx, e.ID); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// currentManaged returns the DeusWatch-managed entries of the address-list, keyed by IP.
func (m *MikrotikResponder) currentManaged(ctx context.Context) (map[string]mtEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		m.baseURL+"/rest/ip/firewall/address-list?list="+url.QueryEscape(m.list), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(m.user, m.pass)
	resp, err := m.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mikrotik: list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mikrotik: list HTTP %d", resp.StatusCode)
	}
	var entries []mtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("mikrotik: decode list: %w", err)
	}
	out := make(map[string]mtEntry, len(entries))
	for _, e := range entries {
		if strings.Contains(e.Comment, "deuswatch") { // only ours
			out[e.Address] = e
		}
	}
	return out, nil
}

func (m *MikrotikResponder) removeByID(ctx context.Context, id string) error {
	body, _ := json.Marshal(map[string]string{".id": id})
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
		insecure, _ := strconv.ParseBool(os.Getenv("MIKROTIK_INSECURE"))
		return liveOrDry(NewMikrotikResponder(
			os.Getenv("MIKROTIK_URL"), os.Getenv("MIKROTIK_USER"),
			os.Getenv("MIKROTIK_PASS"), os.Getenv("MIKROTIK_LIST"), insecure))
	default:
		log.Printf("respond: unknown RESPONDER %q — using dry-run", os.Getenv("RESPONDER"))
		return NewDryRunResponder("none")
	}
}

// MikrotikResponderFromConfig builds a MikroTik responder from explicit config (used
// when the connector comes from the Integrations registry). Wrapped in dry-run unless
// RESPONSE_LIVE=1, like the env path.
func MikrotikResponderFromConfig(baseURL, user, pass, list string, insecure bool) Responder {
	return liveOrDry(NewMikrotikResponder(baseURL, user, pass, list, insecure))
}

// MikrotikConfig is one router's connection settings (from an Integrations row).
type MikrotikConfig struct {
	Address, User, Pass, List string
	Insecure                  bool // skip TLS verify (self-signed RouterOS cert over a tunnel)
}

// MikrotikMultiFromConfigs builds a responder that fans Block/Unblock/Sync out to EVERY
// configured MikroTik, so one ban/unban in DeusWatch reaches all routers and the periodic
// sync keeps them all reconciled. Wrapped in dry-run unless RESPONSE_LIVE=1. nil if empty.
func MikrotikMultiFromConfigs(cfgs []MikrotikConfig) Responder {
	switch len(cfgs) {
	case 0:
		return nil
	case 1:
		c := cfgs[0]
		return liveOrDry(NewMikrotikResponder(c.Address, c.User, c.Pass, c.List, c.Insecure))
	default:
		rs := make([]Responder, 0, len(cfgs))
		for _, c := range cfgs {
			rs = append(rs, NewMikrotikResponder(c.Address, c.User, c.Pass, c.List, c.Insecure))
		}
		return liveOrDry(NewMultiResponder(rs))
	}
}

// MultiResponder fans every action out to several responders (e.g. many MikroTik routers).
// It is also a Syncer when its members are - Sync reconciles them all.
type MultiResponder struct{ members []Responder }

func NewMultiResponder(members []Responder) *MultiResponder { return &MultiResponder{members: members} }

func (mr *MultiResponder) Name() string { return fmt.Sprintf("multi(%d)", len(mr.members)) }

func (mr *MultiResponder) Block(ctx context.Context, ip string, d time.Duration) error {
	var firstErr error
	for _, r := range mr.members {
		if err := r.Block(ctx, ip, d); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (mr *MultiResponder) Unblock(ctx context.Context, ip string) error {
	var firstErr error
	for _, r := range mr.members {
		if err := r.Unblock(ctx, ip); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (mr *MultiResponder) Sync(ctx context.Context, desired []string) error {
	var firstErr error
	for _, r := range mr.members {
		if s, ok := r.(Syncer); ok {
			if err := s.Sync(ctx, desired); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func liveOrDry(r Responder) Responder {
	if live, _ := strconv.ParseBool(os.Getenv("RESPONSE_LIVE")); live {
		log.Printf("respond: LIVE responder active: %s", r.Name())
		return r
	}
	log.Printf("respond: responder %s wrapped in dry-run (set RESPONSE_LIVE=1 for real execution)", r.Name())
	return NewDryRunResponder(r.Name())
}
