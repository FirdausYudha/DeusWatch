package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"deuswatch/internal/score"
)

// ScoreConfig is the UI-managed configuration for both IP scorers. Composite = the current-threat
// score (fired times + AbuseIPDB + OTX + severity); Suspicion = the low-and-slow watchlist
// (fan-out + failure ratio + time spread + volume). The windows control how far back each scorer
// looks — a longer composite window keeps the dashboard doughnut on an event for longer.
type ScoreConfig struct {
	Composite score.Weights          `json:"composite"`
	Suspicion score.SuspicionWeights `json:"suspicion"`
	// Lookback windows in SECONDS. Default to the SCORE_WINDOW / SUSPICIOUS_WINDOW env values
	// (so an existing deployment is unchanged); the UI overrides them.
	CompositeWindowSecs  int `json:"composite_window_secs"`
	SuspiciousWindowSecs int `json:"suspicious_window_secs"`
}

// DefaultScoreConfig is the built-in configuration. Windows seed from env so SCORE_WINDOW /
// SUSPICIOUS_WINDOW keep working as the default until an operator tunes them in the UI.
func DefaultScoreConfig() ScoreConfig {
	return ScoreConfig{
		Composite:            score.DefaultWeights(),
		Suspicion:            score.DefaultSuspicionWeights(),
		CompositeWindowSecs:  envSecs("SCORE_WINDOW", 10*time.Minute),
		SuspiciousWindowSecs: envSecs("SUSPICIOUS_WINDOW", 24*time.Hour),
	}
}

// CompositeWindow / SuspiciousWindow return the configured lookback as a duration.
func (c ScoreConfig) CompositeWindow() time.Duration {
	return time.Duration(c.CompositeWindowSecs) * time.Second
}
func (c ScoreConfig) SuspiciousWindow() time.Duration {
	return time.Duration(c.SuspiciousWindowSecs) * time.Second
}

func envSecs(key string, def time.Duration) int {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return int(d.Seconds())
		}
	}
	return int(def.Seconds())
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

	// Windows: fall back to the default when unset, and clamp to a sane range (1 min .. 30 days).
	const minW, maxW = 60, 30 * 24 * 60 * 60
	if c.CompositeWindowSecs <= 0 {
		c.CompositeWindowSecs = d.CompositeWindowSecs
	}
	if c.SuspiciousWindowSecs <= 0 {
		c.SuspiciousWindowSecs = d.SuspiciousWindowSecs
	}
	c.CompositeWindowSecs = clampInt(c.CompositeWindowSecs, minW, maxW)
	c.SuspiciousWindowSecs = clampInt(c.SuspiciousWindowSecs, minW, maxW)
	return c
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
