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

// Shipper mengirim batch RawLog ke gateway lewat mTLS.
type Shipper struct {
	url    string
	client *http.Client
}

// NewShipper membuat shipper yang menyodorkan sertifikat client dari certs.
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

// Send memarshal batch lalu mengirimkannya ke POST {url}/v1/logs.
func (s *Shipper) Send(ctx context.Context, batch []ingest.RawLog) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	return s.SendRaw(ctx, body)
}

// SendRaw mengirim body JSON yang sudah ter-marshal (dipakai juga untuk batch
// dari buffer disk).
func (s *Shipper) SendRaw(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/v1/logs", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("agent: kirim ke gateway: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent: gateway menolak (status %d)", resp.StatusCode)
	}
	return nil
}

// Heartbeat mengirim sinyal hidup ke POST {url}/v1/heartbeat (manager memperbarui
// last_seen agent).
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
		return fmt.Errorf("agent: heartbeat ditolak (status %d)", resp.StatusCode)
	}
	return nil
}

// FetchConfig mengambil config push untuk agent ini dari manager (GET /v1/config).
// Mengembalikan (nil, nil) bila manager belum menetapkan config (HTTP 204).
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
		return nil, fmt.Errorf("agent: ambil config (status %d)", resp.StatusCode)
	}
	var cfg Config
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
