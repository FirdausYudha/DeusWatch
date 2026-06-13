package enrich

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Cache adalah penyimpanan hasil CTI ber-TTL di Postgres (tabel cti_indicators).
type Cache struct {
	pool *pgxpool.Pool
}

func NewCache(pool *pgxpool.Pool) *Cache { return &Cache{pool: pool} }

// Get mengembalikan indikator untuk ip bila ada DAN belum kedaluwarsa (TTL aktif).
func (c *Cache) Get(ctx context.Context, ip string) (Indicator, bool, error) {
	var ind Indicator
	var country, city, feed *string
	err := c.pool.QueryRow(ctx, `
		SELECT abuse_confidence, otx_pulse_count, country_iso, city, feed_name
		FROM cti_indicators
		WHERE ip = $1::inet AND expires_at > now()`, ip).
		Scan(&ind.AbuseConfidence, &ind.OTXPulseCount, &country, &city, &feed)
	if errors.Is(err, pgx.ErrNoRows) {
		return Indicator{}, false, nil
	}
	if err != nil {
		return Indicator{}, false, fmt.Errorf("enrich: cache get: %w", err)
	}
	if country != nil {
		ind.CountryISO = *country
	}
	if city != nil {
		ind.City = *city
	}
	if feed != nil {
		ind.FeedName = *feed
	}
	return ind, true, nil
}

// Put menyimpan/memperbarui indikator dengan TTL. UPSERT (ON CONFLICT) membuat
// dua worker yang lookup IP sama secara bersamaan tidak pernah bertabrakan.
func (c *Cache) Put(ctx context.Context, ip string, ind Indicator, ttl time.Duration) error {
	_, err := c.pool.Exec(ctx, `
		INSERT INTO cti_indicators (ip, abuse_confidence, otx_pulse_count, country_iso, city, feed_name, checked_at, expires_at)
		VALUES ($1::inet, $2, $3, $4, $5, $6, now(), $7)
		ON CONFLICT (ip) DO UPDATE SET
			abuse_confidence = EXCLUDED.abuse_confidence,
			otx_pulse_count  = EXCLUDED.otx_pulse_count,
			country_iso      = EXCLUDED.country_iso,
			city             = EXCLUDED.city,
			feed_name        = EXCLUDED.feed_name,
			checked_at       = now(),
			expires_at       = EXCLUDED.expires_at`,
		ip, ind.AbuseConfidence, ind.OTXPulseCount, nilIfEmpty(ind.CountryISO), nilIfEmpty(ind.City),
		nilIfEmpty(ind.FeedName), time.Now().Add(ttl))
	if err != nil {
		return fmt.Errorf("enrich: cache put: %w", err)
	}
	return nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
