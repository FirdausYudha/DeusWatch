package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Service names written into service_heartbeats. One constant per component so the writer and
// the reader can never drift on a string literal.
const ServiceWorker = "worker"

// WorkerStaleAfter is how long the api waits before calling the worker missing. The worker beats
// every 30s (see runServiceHeartbeat in cmd/worker), so this tolerates three missed beats plus
// slack — long enough that a slow GC pause or a brief DB blip does not raise a false alarm, short
// enough that a crashed worker is visible within two minutes rather than eleven hours.
const WorkerStaleAfter = 100 * time.Second

// ServiceHealth is one component's liveness as the manager sees it.
type ServiceHealth struct {
	Service  string     `json:"service"`
	Alive    bool       `json:"alive"`
	LastSeen *time.Time `json:"last_seen_at"`
	Age      float64    `json:"age_seconds"` // seconds since the last heartbeat; 0 when never seen
	Version  string     `json:"version,omitempty"`
	Detail   string     `json:"detail,omitempty"`
	// EverSeen distinguishes "this component has never reported" (a fresh deploy, or a worker
	// that was never started at all) from "it reported and then stopped". Those need different
	// advice, and collapsing them into one "down" state is what made the original incident so
	// hard to read.
	EverSeen bool `json:"ever_seen"`
}

// UpsertServiceHeartbeat records that `service` is alive right now. Called on a timer by the
// component itself; the primary key means a restarted container reuses its row.
func (s *Store) UpsertServiceHeartbeat(ctx context.Context, service, version, detail string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO service_heartbeats (service, last_seen_at, version, detail)
		 VALUES ($1, now(), $2, $3)
		 ON CONFLICT (service) DO UPDATE SET
		     last_seen_at = now(), version = EXCLUDED.version, detail = EXCLUDED.detail`,
		service, version, detail)
	if err != nil {
		return fmt.Errorf("store: service heartbeat: %w", err)
	}
	return nil
}

// ServiceHealthFor reports one component's liveness. A component that has never written a
// heartbeat comes back with EverSeen=false rather than an error — "never reported" is a real
// state the UI must be able to describe, not a failure to look it up.
func (s *Store) ServiceHealthFor(ctx context.Context, service string, staleAfter time.Duration) (ServiceHealth, error) {
	out := ServiceHealth{Service: service}
	var (
		last    time.Time
		version string
		detail  string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT last_seen_at, version, detail FROM service_heartbeats WHERE service = $1`,
		service).Scan(&last, &version, &detail)
	if err != nil {
		// No row: never reported. Every other error is a real lookup failure and must surface —
		// reporting a DB outage as "the worker is down" would send the operator hunting the
		// wrong component.
		if errors.Is(err, pgx.ErrNoRows) {
			return out, nil
		}
		return out, fmt.Errorf("store: read service heartbeat: %w", err)
	}
	age := time.Since(last)
	out.EverSeen = true
	out.LastSeen = &last
	out.Age = age.Seconds()
	out.Alive = age <= staleAfter
	out.Version = version
	out.Detail = detail
	return out, nil
}
