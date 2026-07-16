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
	err := s.pool.QueryRow(ctx, `SELECT token FROM ingest_webhook WHERE id = 1`).Scan(&tok)
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
	_, err := s.pool.Exec(ctx,
		`INSERT INTO ingest_webhook (id, token, updated_at) VALUES (1, $1, now())
		 ON CONFLICT (id) DO UPDATE SET token = $1, updated_at = now()`, token)
	if err != nil {
		return fmt.Errorf("store: set webhook token: %w", err)
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
