package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"deuswatch/internal/score"
)

// ScoreConfig is the UI-managed weighting for both IP scorers. Composite = the current-threat
// score (fired times + AbuseIPDB + OTX + severity); Suspicion = the low-and-slow watchlist
// (fan-out + failure ratio + time spread + volume).
type ScoreConfig struct {
	Composite score.Weights          `json:"composite"`
	Suspicion score.SuspicionWeights `json:"suspicion"`
}

// DefaultScoreConfig is the built-in weighting.
func DefaultScoreConfig() ScoreConfig {
	return ScoreConfig{Composite: score.DefaultWeights(), Suspicion: score.DefaultSuspicionWeights()}
}

// LoadScoreConfig reads the stored weights, OVERLAID on the defaults so a partial/empty row
// simply keeps the built-in values for anything not set. Always returns a usable config.
func (s *Store) LoadScoreConfig(ctx context.Context) (ScoreConfig, error) {
	c := DefaultScoreConfig()
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT config FROM score_config WHERE id = 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("store: load score config: %w", err)
	}
	if len(raw) > 0 {
		// Unmarshal over the defaults: present fields win, missing ones keep the default.
		_ = json.Unmarshal(raw, &c)
	}
	return c.sanitized(), nil
}

// SaveScoreConfig validates and upserts the weights.
func (s *Store) SaveScoreConfig(ctx context.Context, c ScoreConfig) error {
	c = c.sanitized()
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO score_config (id, config, updated_at) VALUES (1, $1, now())
		 ON CONFLICT (id) DO UPDATE SET config = $1, updated_at = now()`, b)
	if err != nil {
		return fmt.Errorf("store: save score config: %w", err)
	}
	return nil
}

// sanitized clamps negatives and falls back to defaults when a whole weight-set is unusable
// (all weights zero would score everything 0), and keeps caps positive.
func (c ScoreConfig) sanitized() ScoreConfig {
	d := DefaultScoreConfig()
	nn := func(v float64) float64 {
		if v < 0 {
			return 0
		}
		return v
	}
	c.Composite.Abuse, c.Composite.FiredTimes = nn(c.Composite.Abuse), nn(c.Composite.FiredTimes)
	c.Composite.OTX, c.Composite.Severity = nn(c.Composite.OTX), nn(c.Composite.Severity)
	if c.Composite.Abuse+c.Composite.FiredTimes+c.Composite.OTX+c.Composite.Severity <= 0 {
		c.Composite = d.Composite
	}
	if c.Composite.OTXCap <= 0 {
		c.Composite.OTXCap = d.Composite.OTXCap
	}
	if c.Composite.FiredCap <= 0 {
		c.Composite.FiredCap = d.Composite.FiredCap
	}

	c.Suspicion.FanOut, c.Suspicion.FailRatio = nn(c.Suspicion.FanOut), nn(c.Suspicion.FailRatio)
	c.Suspicion.Spread, c.Suspicion.Volume = nn(c.Suspicion.Spread), nn(c.Suspicion.Volume)
	if c.Suspicion.FanOut+c.Suspicion.FailRatio+c.Suspicion.Spread+c.Suspicion.Volume <= 0 {
		c.Suspicion = d.Suspicion
	}
	if c.Suspicion.FanOutCap <= 0 {
		c.Suspicion.FanOutCap = d.Suspicion.FanOutCap
	}
	if c.Suspicion.SpreadCap <= 0 {
		c.Suspicion.SpreadCap = d.Suspicion.SpreadCap
	}
	if c.Suspicion.VolumeCap <= 0 {
		c.Suspicion.VolumeCap = d.Suspicion.VolumeCap
	}
	return c
}
