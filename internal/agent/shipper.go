package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/mtls"
)

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

// Heartbeat sends a liveness signal to POST {url}/v1/heartbeat (the manager updates
// the agent's last_seen).
func (s *Shipper) Heartbeat(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/v1/heartbeat", nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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
