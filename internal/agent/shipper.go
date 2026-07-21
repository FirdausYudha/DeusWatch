package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/mtls"
)

// ErrRevoked is returned when the manager reports this agent as revoked (HTTP 410 Gone).
// The agent reacts by self-uninstalling.
var ErrRevoked = errors.New("agent: revoked by the manager")

// Shipper sends RawLog batches to the gateway over mTLS.
type Shipper struct {
	url    string
	client *http.Client
}

// NewShipper creates a shipper that presents the client certificate from certs.
func NewShipper(gatewayURL string, certs mtls.CertPaths) (*Shipper, error) {
	cfg, err := mtls.ClientConfig(certs)
	if err != nil {
		return nil, err
	}
	return &Shipper{
		url: gatewayURL,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: cfg},
		},
	}, nil
}

// Send marshals the batch then sends it to POST {url}/v1/logs.
func (s *Shipper) Send(ctx context.Context, batch []ingest.RawLog) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	return s.SendRaw(ctx, body)
}

// SendRaw sends an already-marshaled JSON body (also used for batches from the disk
// buffer).
func (s *Shipper) SendRaw(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/v1/logs", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("agent: send to gateway: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent: gateway rejected (status %d)", resp.StatusCode)
	}
	return nil
}

// PostSnapshots ships captured FIM version metadata to the manager (POST {url}/v1/snapshots).
// The content itself stays on the agent; only this metadata is uploaded (ADR 0002 Phase 2).
func (s *Shipper) PostSnapshots(ctx context.Context, snaps []SnapshotMeta) error {
	if len(snaps) == 0 {
		return nil
	}
	body, err := json.Marshal(snaps)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/v1/snapshots", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("agent: post snapshots: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone {
		return ErrRevoked
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("agent: snapshots rejected (status %d)", resp.StatusCode)
	}
	return nil
}

// PostInventory ships the host's software inventory (OS release + installed packages) to the
// manager. A revoked agent gets ErrRevoked.
func (s *Shipper) PostInventory(ctx context.Context, inv Inventory) error {
	body, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("agent: post inventory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone {
		return ErrRevoked
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("agent: inventory rejected (status %d)", resp.StatusCode)
	}
	return nil
}

// FileActionItem is one manager-requested on-demand file operation (ADR 0002 Phase 3).
type FileActionItem struct {
	ID            int64  `json:"id"`
	Path          string `json:"path"`
	Action        string `json:"action"`                   // snapshot_now | quarantine | restore_version | kill_process
	VersionSHA256 string `json:"version_sha256,omitempty"` // target version for restore_version
	Content       string `json:"content,omitempty"`        // manager-stored content for restore_version
	// kill_process only. Path carries the executable. The agent re-verifies this identity
	// against the live process before terminating - see internal/agent/killproc.go.
	PID       int    `json:"pid,omitempty"`
	ProcName  string `json:"proc_name,omitempty"`
	ProcStart string `json:"proc_start,omitempty"`
}

// FetchFileActions retrieves the actions the manager wants this agent to perform
// (GET /v1/file-actions). Returns an empty slice when none/disabled.
func (s *Shipper) FetchFileActions(ctx context.Context) ([]FileActionItem, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/v1/file-actions", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: fetch file-actions (status %d)", resp.StatusCode)
	}
	var body struct {
		Actions []FileActionItem `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Actions, nil
}

// PostFileActionResult reports the outcome of one action back to the manager
// (POST /v1/file-actions/result). status is "done" or "failed".
func (s *Shipper) PostFileActionResult(ctx context.Context, id int64, status, result string) error {
	body, err := json.Marshal(map[string]any{"id": id, "status": status, "result": result})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/v1/file-actions/result", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("agent: post file-action result: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("agent: file-action result rejected (status %d)", resp.StatusCode)
	}
	return nil
}

// Health is the agent's self-reported state carried on the heartbeat. Degraded means
// "alive but not fully working" - e.g. the offline buffer is piling up because log
// batches are not getting through while the heartbeat itself still succeeds.
type Health struct {
	Degraded bool   `json:"degraded"`
	Detail   string `json:"detail,omitempty"`
}

// Heartbeat sends a liveness signal to POST {url}/v1/heartbeat (the manager updates
// the agent's last_seen and records the self-reported health).
func (s *Shipper) Heartbeat(ctx context.Context, health Health) error {
	body, err := json.Marshal(health)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone {
		return ErrRevoked
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent: heartbeat rejected (status %d)", resp.StatusCode)
	}
	return nil
}

// FetchBlocklist retrieves the source IPs the manager wants this agent's firewall to
// block (GET /v1/blocklist). Returns an empty slice when none/disabled.
func (s *Shipper) FetchBlocklist(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/v1/blocklist", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: fetch blocklist (status %d)", resp.StatusCode)
	}
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, err
	}
	return body.IPs, nil
}

// FetchQuarantine retrieves the known-bad files the manager wants this agent to
// quarantine/delete (GET /v1/quarantine). Returns an empty slice when none/disabled.
func (s *Shipper) FetchQuarantine(ctx context.Context) ([]FileTarget, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/v1/quarantine", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: fetch quarantine (status %d)", resp.StatusCode)
	}
	var body struct {
		Files []FileTarget `json:"files"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, err
	}
	return body.Files, nil
}

// FetchRestore retrieves the file paths the manager wants this agent to restore to their
// known-good snapshot (GET /v1/restore). Returns an empty slice when none/disabled.
func (s *Shipper) FetchRestore(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/v1/restore", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: fetch restore (status %d)", resp.StatusCode)
	}
	var body struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, err
	}
	return body.Paths, nil
}

// ContainmentDirective is the manager's host-isolation instruction for this agent
// (GET /v1/containment). Isolate=true means firewall the host off from the LAN except AllowIPs.
type ContainmentDirective struct {
	Isolate  bool     `json:"isolate"`
	AllowIPs []string `json:"allow_ips"`
	Reason   string   `json:"reason,omitempty"`
}

// FetchContainment retrieves this agent's host-isolation directive from the manager
// (GET /v1/containment). A zero value (Isolate=false) means "do not isolate".
func (s *Shipper) FetchContainment(ctx context.Context) (ContainmentDirective, error) {
	var d ContainmentDirective
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/v1/containment", nil)
	if err != nil {
		return d, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("agent: fetch containment (status %d)", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return d, err
	}
	return d, nil
}

// FetchConfig retrieves this agent's push-config from the manager (GET /v1/config).
// Returns (nil, nil) when the manager has not set a config yet (HTTP 204).
func (s *Shipper) FetchConfig(ctx context.Context) (*Config, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/v1/config", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: fetch config (status %d)", resp.StatusCode)
	}
	var cfg Config
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
