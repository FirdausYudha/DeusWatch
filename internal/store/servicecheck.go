package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Service/API health checks (migration 000073).
//
// The store deliberately treats the request headers as an OPAQUE encrypted string. Credentials
// for an integration's web services (the BPJS username and token are sent on every call) are
// sealed by the caller with secret.Cipher before they arrive here and unsealed by the prober that
// needs them, so the database never holds them in the clear and no query can accidentally select
// them into a log line.

// ServiceCheck is one configured endpoint plus the live state the prober maintains on it.
type ServiceCheck struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"service_group"` // business function: pendaftaran | klaim | finger
	Kind  string `json:"kind"`          // http | tcp
	// Target is the URL (http) or host:port (tcp).
	Target       string `json:"target"`
	Method       string `json:"method"`
	ExpectStatus int    `json:"expect_status"`
	// HeadersEnc is the encrypted JSON object of request headers. Never returned to the UI.
	HeadersEnc    string `json:"-"`
	ExpectBody    string `json:"expect_body"`
	IntervalSecs  int    `json:"interval_secs"`
	TimeoutSecs   int    `json:"timeout_secs"`
	LatencyWarnMS int    `json:"latency_warn_ms"`
	FailThreshold int    `json:"fail_threshold"`
	Enabled       bool   `json:"enabled"`

	// Live state, maintained by the prober.
	LastCheckedAt  *time.Time `json:"last_checked_at"`
	LastOK         *bool      `json:"last_ok"`
	LastStatus     int        `json:"last_status"`
	LastLatencyMS  int        `json:"last_latency_ms"`
	LastError      string     `json:"last_error"`
	ConsecFailures int        `json:"consec_failures"`
	Alerting       bool       `json:"alerting"`
	UpdatedAt      time.Time  `json:"updated_at"`

	// HasHeaders tells the UI that credentials are configured without revealing them.
	HasHeaders bool `json:"has_headers"`
}

// ServiceCheckResult is one probe observation, as the prober reports it.
type ServiceCheckResult struct {
	OK        bool
	Status    int
	LatencyMS int
	Error     string
}

// ServiceCheckPoint is one row of probe history.
type ServiceCheckPoint struct {
	Time      time.Time `json:"time"`
	OK        bool      `json:"ok"`
	Status    int       `json:"status"`
	LatencyMS int       `json:"latency_ms"`
	Error     string    `json:"error"`
}

// Transition kinds returned by RecordServiceCheckResult.
const (
	TransitionNone      = ""
	TransitionDown      = "down"
	TransitionRecovered = "recovered"
)

const serviceCheckCols = `id, name, service_group, kind, target, method, expect_status,
	COALESCE(headers_enc,''), COALESCE(expect_body,''), interval_secs, timeout_secs,
	latency_warn_ms, fail_threshold, enabled, last_checked_at, last_ok,
	COALESCE(last_status,0), COALESCE(last_latency_ms,0), COALESCE(last_error,''),
	consec_failures, alerting, updated_at`

func scanServiceCheck(row pgx.Row) (ServiceCheck, error) {
	var c ServiceCheck
	err := row.Scan(&c.ID, &c.Name, &c.Group, &c.Kind, &c.Target, &c.Method, &c.ExpectStatus,
		&c.HeadersEnc, &c.ExpectBody, &c.IntervalSecs, &c.TimeoutSecs, &c.LatencyWarnMS,
		&c.FailThreshold, &c.Enabled, &c.LastCheckedAt, &c.LastOK, &c.LastStatus,
		&c.LastLatencyMS, &c.LastError, &c.ConsecFailures, &c.Alerting, &c.UpdatedAt)
	c.HasHeaders = c.HeadersEnc != ""
	return c, err
}

// ListServiceChecks returns every configured check, grouped first by business function so the
// status page can render sections without sorting again.
func (s *Store) ListServiceChecks(ctx context.Context) ([]ServiceCheck, error) {
	rows, err := s.q(ctx).Query(ctx,
		`SELECT `+serviceCheckCols+` FROM service_checks ORDER BY service_group, name`)
	if err != nil {
		return nil, fmt.Errorf("store: list service checks: %w", err)
	}
	defer rows.Close()
	out := make([]ServiceCheck, 0, 16)
	for rows.Next() {
		c, serr := scanServiceCheck(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// EnabledServiceChecks returns the checks the prober should run.
func (s *Store) EnabledServiceChecks(ctx context.Context) ([]ServiceCheck, error) {
	rows, err := s.q(ctx).Query(ctx,
		`SELECT `+serviceCheckCols+` FROM service_checks WHERE enabled ORDER BY service_group, name`)
	if err != nil {
		return nil, fmt.Errorf("store: enabled service checks: %w", err)
	}
	defer rows.Close()
	out := make([]ServiceCheck, 0, 16)
	for rows.Next() {
		c, serr := scanServiceCheck(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetServiceCheck returns one check. ok=false (no error) when it does not exist.
func (s *Store) GetServiceCheck(ctx context.Context, id string) (ServiceCheck, bool, error) {
	c, err := scanServiceCheck(s.q(ctx).QueryRow(ctx,
		`SELECT `+serviceCheckCols+` FROM service_checks WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceCheck{}, false, nil
	}
	if err != nil {
		return ServiceCheck{}, false, fmt.Errorf("store: get service check: %w", err)
	}
	return c, true, nil
}

// normalise clamps the operator-supplied numbers to values the prober can actually honour. A
// one-second interval against a hospital's upstream integration is a denial of service aimed at
// the thing being monitored, and a zero timeout would never complete.
func (c *ServiceCheck) normalise() {
	if c.Kind != "tcp" {
		c.Kind = "http"
	}
	if c.Method == "" {
		c.Method = "GET"
	}
	if c.IntervalSecs < 10 {
		c.IntervalSecs = 10
	}
	if c.IntervalSecs > 86400 {
		c.IntervalSecs = 86400
	}
	if c.TimeoutSecs < 1 {
		c.TimeoutSecs = 10
	}
	if c.TimeoutSecs > 120 {
		c.TimeoutSecs = 120
	}
	// A timeout longer than the interval would overlap probes of the same endpoint.
	if c.TimeoutSecs > c.IntervalSecs {
		c.TimeoutSecs = c.IntervalSecs
	}
	if c.FailThreshold < 1 {
		c.FailThreshold = 1
	}
	if c.FailThreshold > 100 {
		c.FailThreshold = 100
	}
	if c.LatencyWarnMS < 0 {
		c.LatencyWarnMS = 0
	}
	if c.ExpectStatus < 0 || c.ExpectStatus > 599 {
		c.ExpectStatus = 0
	}
}

// CreateServiceCheck inserts a check and fills in its generated id.
func (s *Store) CreateServiceCheck(ctx context.Context, c *ServiceCheck) error {
	c.normalise()
	err := s.q(ctx).QueryRow(ctx, `
		INSERT INTO service_checks
		  (name, service_group, kind, target, method, expect_status, headers_enc, expect_body,
		   interval_secs, timeout_secs, latency_warn_ms, fail_threshold, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''),$9,$10,$11,$12,$13)
		RETURNING id`,
		c.Name, c.Group, c.Kind, c.Target, c.Method, c.ExpectStatus, c.HeadersEnc, c.ExpectBody,
		c.IntervalSecs, c.TimeoutSecs, c.LatencyWarnMS, c.FailThreshold, c.Enabled).Scan(&c.ID)
	if err != nil {
		return fmt.Errorf("store: create service check: %w", err)
	}
	return nil
}

// UpdateServiceCheck saves an edited check. An empty HeadersEnc leaves the stored credentials
// alone: the UI never receives them, so it cannot send them back, and treating "not sent" as
// "clear them" would silently break every check the moment someone renamed one.
func (s *Store) UpdateServiceCheck(ctx context.Context, c *ServiceCheck) error {
	c.normalise()
	tag, err := s.q(ctx).Exec(ctx, `
		UPDATE service_checks SET
		  name=$2, service_group=$3, kind=$4, target=$5, method=$6, expect_status=$7,
		  headers_enc=COALESCE(NULLIF($8,''), headers_enc), expect_body=NULLIF($9,''),
		  interval_secs=$10, timeout_secs=$11, latency_warn_ms=$12, fail_threshold=$13,
		  enabled=$14, updated_at=now()
		WHERE id=$1`,
		c.ID, c.Name, c.Group, c.Kind, c.Target, c.Method, c.ExpectStatus, c.HeadersEnc,
		c.ExpectBody, c.IntervalSecs, c.TimeoutSecs, c.LatencyWarnMS, c.FailThreshold, c.Enabled)
	if err != nil {
		return fmt.Errorf("store: update service check: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: service check %s not found", c.ID)
	}
	return nil
}

// ClearServiceCheckHeaders removes the stored credentials for a check.
func (s *Store) ClearServiceCheckHeaders(ctx context.Context, id string) error {
	_, err := s.q(ctx).Exec(ctx,
		`UPDATE service_checks SET headers_enc=NULL, updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("store: clear service check headers: %w", err)
	}
	return nil
}

// DeleteServiceCheck removes a check. Its history goes with it on the next retention sweep.
func (s *Store) DeleteServiceCheck(ctx context.Context, id string) error {
	if _, err := s.q(ctx).Exec(ctx, `DELETE FROM service_check_results WHERE check_id=$1`, id); err != nil {
		return fmt.Errorf("store: delete service check history: %w", err)
	}
	if _, err := s.q(ctx).Exec(ctx, `DELETE FROM service_checks WHERE id=$1`, id); err != nil {
		return fmt.Errorf("store: delete service check: %w", err)
	}
	return nil
}

// RecordServiceCheckResult appends the observation and advances the check's live state, returning
// the alert transition the caller should act on.
//
// The latch is the point. Without it a service that is down for an hour raises an alert on every
// probe interval, which trains people to mute the channel; with it, one outage produces exactly
// one "down" and one "recovered". The threshold is separate and does the other half: a single
// failed probe across somebody else's network is noise, three in a row is an outage.
func (s *Store) RecordServiceCheckResult(ctx context.Context, id string, r ServiceCheckResult) (string, ServiceCheck, error) {
	cur, ok, err := s.GetServiceCheck(ctx, id)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("store: service check %s not found", id)
		}
		return TransitionNone, ServiceCheck{}, err
	}

	if _, err := s.q(ctx).Exec(ctx, `
		INSERT INTO service_check_results (time, check_id, ok, status, latency_ms, error)
		VALUES (now(), $1, $2, NULLIF($3,0), $4, NULLIF($5,''))`,
		id, r.OK, r.Status, r.LatencyMS, r.Error); err != nil {
		return TransitionNone, cur, fmt.Errorf("store: record service check result: %w", err)
	}

	transition := TransitionNone
	consec := cur.ConsecFailures
	alerting := cur.Alerting
	switch {
	case r.OK:
		consec = 0
		if alerting {
			alerting = false
			transition = TransitionRecovered
		}
	default:
		consec++
		if !alerting && consec >= cur.FailThreshold {
			alerting = true
			transition = TransitionDown
		}
	}

	if _, err := s.q(ctx).Exec(ctx, `
		UPDATE service_checks SET
		  last_checked_at=now(), last_ok=$2, last_status=NULLIF($3,0), last_latency_ms=$4,
		  last_error=NULLIF($5,''), consec_failures=$6, alerting=$7
		WHERE id=$1`,
		id, r.OK, r.Status, r.LatencyMS, r.Error, consec, alerting); err != nil {
		return TransitionNone, cur, fmt.Errorf("store: update service check state: %w", err)
	}

	now := time.Now()
	cur.LastCheckedAt, cur.LastOK = &now, &r.OK
	cur.LastStatus, cur.LastLatencyMS, cur.LastError = r.Status, r.LatencyMS, r.Error
	cur.ConsecFailures, cur.Alerting = consec, alerting
	return transition, cur, nil
}

// ServiceCheckHistory returns one check's probe history, newest first, capped.
func (s *Store) ServiceCheckHistory(ctx context.Context, id string, since time.Time, limit int) ([]ServiceCheckPoint, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := s.q(ctx).Query(ctx, `
		SELECT time, ok, COALESCE(status,0), COALESCE(latency_ms,0), COALESCE(error,'')
		FROM service_check_results
		WHERE check_id=$1 AND time >= $2
		ORDER BY time DESC LIMIT $3`, id, since, limit)
	if err != nil {
		return nil, fmt.Errorf("store: service check history: %w", err)
	}
	defer rows.Close()
	out := make([]ServiceCheckPoint, 0, 64)
	for rows.Next() {
		var p ServiceCheckPoint
		if err := rows.Scan(&p.Time, &p.OK, &p.Status, &p.LatencyMS, &p.Error); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
