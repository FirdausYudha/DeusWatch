package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// WebhookToken returns the current inbound ingest-webhook token ("" = webhook disabled).
// It is read per request by the webhook handler so a regenerate/disable from the UI takes
// effect immediately without a restart.
func (s *Store) WebhookToken(ctx context.Context) (string, error) {
	var tok string
	err := s.q(ctx).QueryRow(ctx, `SELECT token FROM ingest_webhook WHERE id = 1`).Scan(&tok)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: webhook token: %w", err)
	}
	return tok, nil
}

// SetWebhookToken upserts the inbound ingest-webhook token ("" disables the endpoint).
func (s *Store) SetWebhookToken(ctx context.Context, token string) error {
	_, err := s.q(ctx).Exec(ctx,
		`INSERT INTO ingest_webhook (id, token, updated_at) VALUES (1, $1, now())
		 ON CONFLICT (id) DO UPDATE SET token = $1, updated_at = now()`, token)
	if err != nil {
		return fmt.Errorf("store: set webhook token: %w", err)
	}
	return nil
}

// WebhookDefaultTenantID returns the workspace UUID that inbound webhook events should be stamped
// with ("" = fall back to per-agent lookup / Default tenant, historical behavior). Read per
// request so a UI change takes effect immediately.
func (s *Store) WebhookDefaultTenantID(ctx context.Context) (string, error) {
	var tid *string
	err := s.q(ctx).QueryRow(ctx, `SELECT default_tenant_id::text FROM ingest_webhook WHERE id = 1`).Scan(&tid)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: webhook default tenant: %w", err)
	}
	if tid == nil {
		return "", nil
	}
	return *tid, nil
}

// SetWebhookDefaultTenantID sets (or clears with "") the default tenant for inbound webhook events.
func (s *Store) SetWebhookDefaultTenantID(ctx context.Context, tenantID string) error {
	var val any = nil
	if tenantID != "" {
		val = tenantID
	}
	_, err := s.q(ctx).Exec(ctx,
		`INSERT INTO ingest_webhook (id, token, default_tenant_id, updated_at)
		 VALUES (1, '', $1::uuid, now())
		 ON CONFLICT (id) DO UPDATE SET default_tenant_id = $1::uuid, updated_at = now()`, val)
	if err != nil {
		return fmt.Errorf("store: set webhook default tenant: %w", err)
	}
	return nil
}

// SeedWebhookTokenFromEnv writes envToken into the DB only if no token is stored yet, so an
// existing INGEST_WEBHOOK_TOKEN deployment keeps working and becomes UI-manageable. No-op if
// env is empty or a token already exists.
func (s *Store) SeedWebhookTokenFromEnv(ctx context.Context, envToken string) error {
	if envToken == "" {
		return nil
	}
	cur, err := s.WebhookToken(ctx)
	if err != nil || cur != "" {
		return err
	}
	return s.SetWebhookToken(ctx, envToken)
}

// GetCursor returns the persisted resume cursor for a named pull source ("" = none yet).
func (s *Store) GetCursor(ctx context.Context, name string) (string, error) {
	var cur string
	err := s.q(ctx).QueryRow(ctx, `SELECT cursor FROM ingest_cursor WHERE name = $1`, name).Scan(&cur)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: get cursor: %w", err)
	}
	return cur, nil
}

// SetCursor upserts the resume cursor for a named pull source.
func (s *Store) SetCursor(ctx context.Context, name, cursor string) error {
	_, err := s.q(ctx).Exec(ctx,
		`INSERT INTO ingest_cursor (name, cursor, updated_at) VALUES ($1, $2, now())
		 ON CONFLICT (name) DO UPDATE SET cursor = $2, updated_at = now()`, name, cursor)
	if err != nil {
		return fmt.Errorf("store: set cursor: %w", err)
	}
	return nil
}
