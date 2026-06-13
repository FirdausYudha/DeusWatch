package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// Send mengirim satu batch ke POST {url}/v1/logs.
func (s *Shipper) Send(ctx context.Context, batch []ingest.RawLog) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
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
