// Package integrations is the admin-managed registry of external connectors:
// firewalls (MikroTik, agent-side nftables), the CrowdSec bouncer, and CTI
// providers (AbuseIPDB, AlienVault OTX). Each connector's secret config fields
// (API keys, device passwords) are encrypted at rest and never read back.
//
// This package owns storage + the config schema (Catalog). Wiring the stored
// connectors into the response/enrichment engines is layered on top separately.
package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/secret"
)

// Field describes one config field of an integration type (drives the UI form).
type Field struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret,omitempty"`
	Optional bool   `json:"optional,omitempty"`
	Help     string `json:"help,omitempty"`
}

// TypeInfo describes an integration type and its config schema.
type TypeInfo struct {
	Type     string  `json:"type"`
	Label    string  `json:"label"`
	Category string  `json:"category"` // firewall | bouncer | cti
	Desc     string  `json:"desc"`
	Fields   []Field `json:"fields"`
}

// Catalog is the supported integration types. Adding a connector = adding an entry.
var Catalog = []TypeInfo{
	{
		Type: "mikrotik", Label: "MikroTik (RouterOS API)", Category: "firewall",
		Desc: "Block source IPs by pushing them to a RouterOS address-list at the network edge.",
		Fields: []Field{
			{Key: "address", Label: "Address (host:port)", Help: "e.g. 192.168.88.1:8728"},
			{Key: "username", Label: "Username"},
			{Key: "password", Label: "Password", Secret: true},
			{Key: "address_list", Label: "Address list", Optional: true, Help: "RouterOS address-list name (default: deuswatch)"},
		},
	},
	{
		Type: "crowdsec", Label: "CrowdSec LAPI (bouncer)", Category: "bouncer",
		Desc: "Push block decisions to the CrowdSec Local API so any CrowdSec bouncer enforces them.",
		Fields: []Field{
			{Key: "lapi_url", Label: "LAPI URL", Help: "e.g. http://127.0.0.1:8080"},
			{Key: "api_key", Label: "Bouncer API key", Secret: true},
		},
	},
	{
		Type: "nftables_agent", Label: "Linux firewall — nftables (agent-side)", Category: "firewall",
		Desc: "Auto-block on the endpoint: the agent adds blocking rules to a local nftables set.",
		Fields: []Field{
			{Key: "table", Label: "nft table", Optional: true, Help: "default: deuswatch"},
			{Key: "set", Label: "nft set", Optional: true, Help: "default: blocklist"},
			{Key: "agent_scope", Label: "Apply to agents", Optional: true, Help: "agent name/tag, comma-separated; blank = all agents"},
		},
	},
	{
		Type: "abuseipdb", Label: "AbuseIPDB (CTI)", Category: "cti",
		Desc: "Enrich source IPs with an abuse-confidence score. Paid plans raise rate limits.",
		Fields: []Field{
			{Key: "api_key", Label: "API key", Secret: true},
		},
	},
	{
		Type: "otx", Label: "AlienVault OTX (CTI)", Category: "cti",
		Desc: "Enrich source IPs with OTX pulse counts (threat-intel mentions).",
		Fields: []Field{
			{Key: "api_key", Label: "OTX API key", Secret: true},
		},
	},
	{
		Type: "circl_hashlookup", Label: "CIRCL hashlookup (file-hash reputation)", Category: "fim",
		Desc:   "Free, no API key — classify FIM file hashes as known-good (NSRL) / known-bad / unknown.",
		Fields: []Field{},
	},
	{
		Type: "virustotal", Label: "VirusTotal (file-hash reputation)", Category: "fim",
		Desc: "Look up FIM file hashes against 70+ AV engines. Free tier ≈4 req/min, 500/day; results are cached.",
		Fields: []Field{
			{Key: "api_key", Label: "API key", Secret: true},
		},
	},
	{
		Type: "llm", Label: "LLM analyzer (AI triage)", Category: "llm",
		Desc: "AI triage of alerts (verdict + summary). Use a free, self-hosted, open-source model via Ollama / any OpenAI-compatible endpoint — or Anthropic Claude.",
		Fields: []Field{
			{Key: "provider", Label: "Provider", Help: "ollama | openai-compatible | anthropic"},
			{Key: "base_url", Label: "Base URL", Optional: true, Help: "OpenAI-compatible endpoint, e.g. http://host.docker.internal:11434/v1 (Ollama). Leave blank for anthropic."},
			{Key: "model", Label: "Model", Optional: true, Help: "e.g. llama3.1, qwen2.5, mistral, or claude-opus-4-8"},
			{Key: "api_key", Label: "API key", Secret: true, Optional: true, Help: "Not needed for local Ollama; required for hosted providers / Anthropic."},
		},
	},
}

// HasEnabled reports whether any enabled integration of the given type exists. It reads
// no secrets, so callers (e.g. the gateway) can use it without a cipher.
func HasEnabled(ctx context.Context, pool *pgxpool.Pool, typ string) (bool, error) {
	var ok bool
	err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM integrations WHERE type=$1 AND enabled)`, typ).Scan(&ok)
	return ok, err
}

func typeInfo(t string) (TypeInfo, bool) {
	for _, ti := range Catalog {
		if ti.Type == t {
			return ti, true
		}
	}
	return TypeInfo{}, false
}

// Integration is a stored connector. Through the API, Config never contains secret
// values; SecretsSet flags which secret fields currently hold a value.
type Integration struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Enabled    bool              `json:"enabled"`
	Config     map[string]string `json:"config"`
	SecretsSet map[string]bool   `json:"secrets_set"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// Store persists integrations, encrypting secret config fields at rest.
type Store struct {
	pool   *pgxpool.Pool
	cipher *secret.Cipher
}

func NewStore(pool *pgxpool.Pool, cipher *secret.Cipher) *Store {
	return &Store{pool: pool, cipher: cipher}
}

const selectCols = `id, type, name, enabled, config, created_at, updated_at`

func scan(row interface {
	Scan(...any) error
}) (*Integration, map[string]string, error) {
	var (
		it  Integration
		raw []byte
	)
	if err := row.Scan(&it.ID, &it.Type, &it.Name, &it.Enabled, &raw, &it.CreatedAt, &it.UpdatedAt); err != nil {
		return nil, nil, err
	}
	stored := map[string]string{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &stored)
	}
	it.Config = map[string]string{}
	for k, v := range stored {
		it.Config[k] = v
	}
	return &it, stored, nil
}

// mask removes secret values from Config (write-only fields) and records which are set.
func (s *Store) mask(it *Integration) {
	it.SecretsSet = map[string]bool{}
	ti, ok := typeInfo(it.Type)
	if !ok {
		return
	}
	for _, f := range ti.Fields {
		if f.Secret {
			if it.Config[f.Key] != "" {
				it.SecretsSet[f.Key] = true
			}
			delete(it.Config, f.Key)
		}
	}
}

// mergeConfig builds the to-store config: non-secret fields are taken from input;
// secret fields are encrypted when provided, or preserved from existing when blank.
func (s *Store) mergeConfig(ti TypeInfo, input, existing map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range ti.Fields {
		v := input[f.Key]
		if !f.Secret {
			out[f.Key] = v
			continue
		}
		if v == "" { // keep the existing secret (write-only field left blank)
			if existing != nil && existing[f.Key] != "" {
				out[f.Key] = existing[f.Key]
			}
			continue
		}
		enc, err := s.cipher.Encrypt(v)
		if err != nil {
			return nil, err
		}
		out[f.Key] = enc
	}
	return out, nil
}

// List returns all integrations (secrets masked), newest first.
func (s *Store) List(ctx context.Context) ([]Integration, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+selectCols+` FROM integrations ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("integrations: list: %w", err)
	}
	defer rows.Close()
	out := make([]Integration, 0, 8)
	for rows.Next() {
		it, _, err := scan(rows)
		if err != nil {
			return nil, err
		}
		s.mask(it)
		out = append(out, *it)
	}
	return out, rows.Err()
}

// Create stores a new integration of the given type.
func (s *Store) Create(ctx context.Context, typ, name string, config map[string]string) (*Integration, error) {
	ti, ok := typeInfo(typ)
	if !ok {
		return nil, fmt.Errorf("integrations: unknown type %q", typ)
	}
	if name == "" {
		return nil, fmt.Errorf("integrations: name is required")
	}
	merged, err := s.mergeConfig(ti, config, nil)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(merged)
	it, _, err := scan(s.pool.QueryRow(ctx,
		`INSERT INTO integrations (type, name, config) VALUES ($1,$2,$3) RETURNING `+selectCols,
		typ, name, b))
	if err != nil {
		return nil, fmt.Errorf("integrations: create: %w", err)
	}
	s.mask(it)
	return it, nil
}

// Update replaces an integration's name, enabled flag, and config (secret fields
// left blank are preserved from the existing row).
func (s *Store) Update(ctx context.Context, id, name string, enabled bool, config map[string]string) (*Integration, error) {
	cur, existing, err := scan(s.pool.QueryRow(ctx, `SELECT `+selectCols+` FROM integrations WHERE id=$1`, id))
	if err != nil {
		return nil, fmt.Errorf("integrations: not found: %w", err)
	}
	ti, ok := typeInfo(cur.Type)
	if !ok {
		return nil, fmt.Errorf("integrations: unknown type %q", cur.Type)
	}
	if name == "" {
		name = cur.Name
	}
	merged, err := s.mergeConfig(ti, config, existing)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(merged)
	it, _, err := scan(s.pool.QueryRow(ctx,
		`UPDATE integrations SET name=$1, enabled=$2, config=$3, updated_at=now() WHERE id=$4 RETURNING `+selectCols,
		name, enabled, b, id))
	if err != nil {
		return nil, fmt.Errorf("integrations: update: %w", err)
	}
	s.mask(it)
	return it, nil
}

// Delete removes an integration.
func (s *Store) Delete(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM integrations WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("integrations: delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("integrations: not found")
	}
	return nil
}

// Resolve returns the enabled integrations of a type with secret fields DECRYPTED.
// Used by the response/enrichment engines (not exposed through the API).
func (s *Store) Resolve(ctx context.Context, typ string) ([]Integration, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+selectCols+` FROM integrations WHERE type=$1 AND enabled ORDER BY created_at`, typ)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Integration, 0, 4)
	for rows.Next() {
		it, _, err := scan(rows)
		if err != nil {
			return nil, err
		}
		for k, v := range it.Config {
			if dec, derr := s.cipher.Decrypt(v); derr == nil {
				it.Config[k] = dec
			}
		}
		it.SecretsSet = nil
		out = append(out, *it)
	}
	return out, rows.Err()
}
