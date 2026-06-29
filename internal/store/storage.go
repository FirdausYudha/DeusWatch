package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ReplStatus summarizes PostgreSQL streaming replication (from pg_stat_replication).
type ReplStatus struct {
	Enabled  bool     `json:"enabled"`  // at least one standby is streaming
	Standbys []string `json:"standbys"` // "client_addr (state)" per connected standby
}

// StorageStatus is the log-storage health shown on the dashboard. DeusWatch stores logs
// in PostgreSQL + TimescaleDB; lifecycle is handled by TimescaleDB retention (auto-drop of
// old chunks) + compression — the relational equivalent of Elasticsearch ILM.
type StorageStatus struct {
	Reachable       bool       `json:"reachable"`        // the log DB answered
	Host            string     `json:"host"`             // DB host (e.g. "db", or Server B's address)
	DBSizeBytes     int64      `json:"db_size_bytes"`    //
	DBSizePretty    string     `json:"db_size_pretty"`   // human-readable
	EventsCount     int64      `json:"events_count"`     //
	BudgetBytes     int64      `json:"budget_bytes"`     // configured soft cap (0 = unset)
	UsedPercent     int        `json:"used_percent"`     // db_size / budget (0 if no budget)
	RetentionDays   *int       `json:"retention_days"`   // TimescaleDB retention policy
	CompressionDays *int       `json:"compression_days"` // TimescaleDB compression policy
	Replication     ReplStatus `json:"replication"`      //
}

// StorageStatus gathers log-storage health. budgetBytes is the configured soft cap used to
// compute UsedPercent (0 = no budget). Returns Reachable=false (and no error) when the DB
// cannot be queried, so the dashboard can render a degraded state instead of failing.
func (s *Store) StorageStatus(ctx context.Context, budgetBytes int64) StorageStatus {
	st := StorageStatus{BudgetBytes: budgetBytes, Replication: ReplStatus{Standbys: []string{}}}
	if cfg := s.pool.Config(); cfg != nil && cfg.ConnConfig != nil {
		st.Host = cfg.ConnConfig.Host
	}

	if err := s.pool.QueryRow(ctx,
		`SELECT pg_database_size(current_database()), pg_size_pretty(pg_database_size(current_database()))`).
		Scan(&st.DBSizeBytes, &st.DBSizePretty); err != nil {
		return st // Reachable stays false
	}
	st.Reachable = true
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&st.EventsCount)
	if budgetBytes > 0 {
		st.UsedPercent = int(st.DBSizeBytes * 100 / budgetBytes)
	}

	// TimescaleDB lifecycle policies (best-effort; nil if not present / not TimescaleDB).
	st.RetentionDays = tsPolicyDays(ctx, s.pool, "policy_retention", "drop_after")
	st.CompressionDays = tsPolicyDays(ctx, s.pool, "policy_compression", "compress_after")

	// Streaming replication standbys (requires the connecting role to see pg_stat_replication).
	if rows, err := s.pool.Query(ctx, `SELECT client_addr, state FROM pg_stat_replication`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var addr, state *string
			if rows.Scan(&addr, &state) != nil {
				continue
			}
			a, ss := "unknown", ""
			if addr != nil {
				a = *addr
			}
			if state != nil {
				ss = *state
			}
			st.Replication.Standbys = append(st.Replication.Standbys, fmt.Sprintf("%s (%s)", a, ss))
			if ss == "streaming" {
				st.Replication.Enabled = true
			}
		}
	}
	return st
}

// SetLifecycle re-applies the TimescaleDB retention and/or compression policies on the
// events hypertable (the relational equivalent of changing an Elasticsearch ILM policy).
// Pass 0 for a value to leave that policy unchanged. retentionDays must exceed
// compressionDays so data is compressed before it is dropped.
func (s *Store) SetLifecycle(ctx context.Context, retentionDays, compressionDays int) error {
	if compressionDays > 0 {
		if _, err := s.pool.Exec(ctx, `SELECT remove_compression_policy('events', if_exists => true)`); err != nil {
			return fmt.Errorf("store: remove compression policy: %w", err)
		}
		if _, err := s.pool.Exec(ctx,
			`SELECT add_compression_policy('events', compress_after => make_interval(days => $1))`, compressionDays); err != nil {
			return fmt.Errorf("store: set compression policy: %w", err)
		}
	}
	if retentionDays > 0 {
		if _, err := s.pool.Exec(ctx, `SELECT remove_retention_policy('events', if_exists => true)`); err != nil {
			return fmt.Errorf("store: remove retention policy: %w", err)
		}
		if _, err := s.pool.Exec(ctx,
			`SELECT add_retention_policy('events', drop_after => make_interval(days => $1))`, retentionDays); err != nil {
			return fmt.Errorf("store: set retention policy: %w", err)
		}
	}
	return nil
}

// tsPolicyDays reads a TimescaleDB background-job policy interval (e.g. retention's
// drop_after) and returns it in whole days. key is a fixed internal field name, not user
// input. Returns nil when the policy/view is absent (e.g. plain PostgreSQL).
func tsPolicyDays(ctx context.Context, pool *pgxpool.Pool, proc, key string) *int {
	var days float64
	q := fmt.Sprintf(
		`SELECT EXTRACT(epoch FROM (config->>'%s')::interval)/86400
		 FROM timescaledb_information.jobs WHERE proc_name=$1 LIMIT 1`, key)
	if err := pool.QueryRow(ctx, q, proc).Scan(&days); err != nil {
		return nil
	}
	d := int(days)
	return &d
}
