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

// runnerFunc menjalankan perintah eksternal; di-stub di test agar responder berbasis
// CLI (nftables/cscli) teruji tanpa benar-benar mengeksekusi.
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

// DryRunResponder hanya mencatat aksi yang AKAN dijalankan — default aman.
type DryRunResponder struct{ backend string }

func NewDryRunResponder(backend string) *DryRunResponder {
	if backend == "" {
		backend = "none"
	}
	return &DryRunResponder{backend: backend}
}

func (d *DryRunResponder) Name() string { return "dryrun(" + d.backend + ")" }

func (d *DryRunResponder) Block(_ context.Context, ip string, dur time.Duration) error {
	log.Printf("respond[dry-run]: BLOCK %s selama %s via %s", ip, durLabel(dur), d.backend)
	return nil
}

func (d *DryRunResponder) Unblock(_ context.Context, ip string) error {
	log.Printf("respond[dry-run]: UNBLOCK %s via %s", ip, d.backend)
	return nil
}

// ── nftables (Linux) ──────────────────────────────────────

// NftablesResponder menambah/menghapus IP pada sebuah named set nftables. Set harus
// sudah dibuat dengan flag timeout, mis.:
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

// CrowdSecResponder membuat/menghapus decision via cscli (LAPI lokal).
type CrowdSecResponder struct{ run runnerFunc }

func NewCrowdSecResponder() *CrowdSecResponder { return &CrowdSecResponder{run: execRunner} }

func (c *CrowdSecResponder) Name() string { return "crowdsec" }

func (c *CrowdSecResponder) Block(ctx context.Context, ip string, dur time.Duration) error {
	d := "8760h" // permanen ~ 1 tahun
	if dur > 0 {
		d = crowdsecDuration(dur)
	}
	return c.run(ctx, "cscli", "decisions", "add", "--ip", ip, "--duration", d, "--type", "ban", "--reason", "deuswatch")
}

func (c *CrowdSecResponder) Unblock(ctx context.Context, ip string) error {
	return c.run(ctx, "cscli", "decisions", "delete", "--ip", ip)
}

// ── Mikrotik (RouterOS REST v7) ───────────────────────────

// MikrotikResponder menambah IP ke address-list RouterOS via REST API, lalu firewall
// filter rule milik admin yang mem-drop list itu yang melakukan blok sebenarnya.
type MikrotikResponder struct {
	baseURL string // mis. https://192.168.88.1
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
	// RouterOS: hapus berdasarkan query .id; di sini sederhana — POST remove by address.
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

// ── util durasi & seleksi dari env ────────────────────────

func durLabel(d time.Duration) string {
	if d <= 0 {
		return "permanen"
	}
	return d.String()
}

// crowdsecDuration: cscli menerima Go duration ("10m","1h","24h").
func crowdsecDuration(d time.Duration) string { return d.String() }

// mikrotikDuration: RouterOS memakai format seperti "10m","1h","1d".
func mikrotikDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
	return d.String()
}

// ResponderFromEnv memilih responder dari env RESPONDER:
//
//	dryrun (default) | nftables | crowdsec | mikrotik | none
//
// none menonaktifkan eksekusi sama sekali (kembali nil). Kecuali RESPONSE_LIVE=1,
// nftables/crowdsec/mikrotik DIBUNGKUS dry-run agar tak ada blok tak sengaja saat dev.
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
		log.Printf("respond: RESPONDER tak dikenal %q — memakai dry-run", os.Getenv("RESPONDER"))
		return NewDryRunResponder("none")
	}
}

func liveOrDry(r Responder) Responder {
	if live, _ := strconv.ParseBool(os.Getenv("RESPONSE_LIVE")); live {
		log.Printf("respond: responder LIVE aktif: %s", r.Name())
		return r
	}
	log.Printf("respond: responder %s dibungkus dry-run (set RESPONSE_LIVE=1 untuk eksekusi nyata)", r.Name())
	return NewDryRunResponder(r.Name())
}
