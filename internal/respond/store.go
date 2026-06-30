package respond

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store maps response_actions to Postgres. It satisfies ActionStore.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Insert stores a new action (initial status) and returns its id.
func (s *Store) Insert(ctx context.Context, a *Action) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO response_actions
			(source_ip, action, reason, rule_id, ban_seconds, offense_count, source, status)
		VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`,
		a.SourceIP, a.ActionType, strOrNil(a.Reason), strOrNil(a.RuleID),
		a.BanSeconds, a.OffenseCount, a.Source, string(a.Status)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("respond: insert: %w", err)
	}
	return id, nil
}

// Offenses counts how many times this IP has ALREADY been blocked (status executed) —
// used for the progressive ban. When `since` is non-zero, only offenses within that
// window are counted (the ban policy's observation window).
func (s *Store) Offenses(ctx context.Context, ip string, since time.Time) (int, error) {
	var n int
	var err error
	if since.IsZero() {
		err = s.pool.QueryRow(ctx,
			`SELECT count(*) FROM response_actions WHERE source_ip = $1::inet AND status = 'executed'`, ip).Scan(&n)
	} else {
		err = s.pool.QueryRow(ctx,
			`SELECT count(*) FROM response_actions WHERE source_ip = $1::inet AND status = 'executed'
			 AND COALESCE(executed_at, created_at) >= $2`, ip, since).Scan(&n)
	}
	if err != nil {
		return 0, fmt.Errorf("respond: offenses: %w", err)
	}
	return n, nil
}

// DismissPendingForIP dismisses every still-recommended action for an IP in one
// shot (the "dismiss all" bulk action). Returns how many rows were dismissed.
func (s *Store) DismissPendingForIP(ctx context.Context, ip, by string) (int, error) {
	ct, err := s.pool.Exec(ctx,
		`UPDATE response_actions SET status='dismissed', decided_by=$2, decided_at=now()
		 WHERE source_ip=$1::inet AND status='recommended'`,
		ip, strOrNil(by))
	if err != nil {
		return 0, fmt.Errorf("respond: dismiss pending for ip: %w", err)
	}
	return int(ct.RowsAffected()), nil
}

// HasOpenAction reports whether an IP already has an "open" action: a pending
// recommendation, or an active block (approved/executed whose ban window has not
// expired; ban_seconds = 0 = permanent). Used to dedup — one open action per IP —
// so a brute-force burst doesn't pile up hundreds of identical rows. Once the ban
// expires, the next event produces a fresh (escalated) recommendation.
func (s *Store) HasOpenAction(ctx context.Context, ip string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM response_actions
			WHERE source_ip = $1::inet
			  AND (
			      status = 'recommended'
			      OR (status IN ('approved','executed')
			          AND (ban_seconds = 0
			               OR COALESCE(executed_at, decided_at, created_at) + make_interval(secs => ban_seconds) > now()))
			  )
		)`, ip).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("respond: has open action: %w", err)
	}
	return exists, nil
}

// LoadPolicy reads the configurable ban policy (falls back to the default when unset).
func (s *Store) LoadPolicy(ctx context.Context) (BanPolicy, error) {
	var (
		secs      []int32
		permanent bool
		window    int
		autoApp   bool
	)
	err := s.pool.QueryRow(ctx,
		`SELECT durations, permanent, window_secs, auto_approve FROM ban_policy WHERE id = 1`).
		Scan(&secs, &permanent, &window, &autoApp)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultBanPolicy(), nil
	}
	if err != nil {
		return DefaultBanPolicy(), fmt.Errorf("respond: load ban policy: %w", err)
	}
	durs := make([]time.Duration, len(secs))
	for i, sx := range secs {
		durs[i] = time.Duration(sx) * time.Second
	}
	return BanPolicy{Durations: durs, Permanent: permanent, Window: time.Duration(window) * time.Second, AutoApprove: autoApp}, nil
}

// SavePolicy upserts the ban policy (single row).
func (s *Store) SavePolicy(ctx context.Context, p BanPolicy) error {
	secs := make([]int32, len(p.Durations))
	for i, d := range p.Durations {
		secs[i] = int32(d.Seconds())
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO ban_policy (id, durations, permanent, window_secs, auto_approve) VALUES (1,$1,$2,$3,$4)
		 ON CONFLICT (id) DO UPDATE SET durations=$1, permanent=$2, window_secs=$3, auto_approve=$4, updated_at=now()`,
		secs, p.Permanent, int(p.Window.Seconds()), p.AutoApprove)
	if err != nil {
		return fmt.Errorf("respond: save ban policy: %w", err)
	}
	return nil
}

// Offender is a per-IP rollup of response actions for the IP-centric view.
type Offender struct {
	SourceIP     string     `json:"source_ip"`
	Offenses     int        `json:"offenses"`      // executed blocks (drives the progressive ladder)
	Total        int        `json:"total"`         // all actions for this IP
	Pending      int        `json:"pending"`       // recommendations awaiting a decision
	LastSeen     time.Time  `json:"last_seen"`     // most recent action
	LastStatus   string     `json:"last_status"`   // status of the most recent action
	LastReason   string     `json:"last_reason"`   // reason of the most recent action
	LastBanSecs  int        `json:"last_ban_secs"` // ban duration of the most recent action
	PendingID    string     `json:"pending_id"`    // newest recommended action id (for approve/dismiss), "" if none
	BlockedUntil *time.Time `json:"blocked_until"` // when the current block expires (nil = none / permanent)
	Blocked      bool       `json:"blocked"`       // currently enforced
}

// Offenders returns one rollup row per source IP, most-recently-active first.
func (s *Store) Offenders(ctx context.Context, limit int) ([]Offender, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT host(source_ip),
		       count(*) FILTER (WHERE status = 'executed')                                     AS offenses,
		       count(*)                                                                         AS total,
		       count(*) FILTER (WHERE status = 'recommended')                                   AS pending,
		       max(created_at)                                                                  AS last_seen,
		       (array_agg(status      ORDER BY created_at DESC))[1]                             AS last_status,
		       (array_agg(COALESCE(reason,'') ORDER BY created_at DESC))[1]                     AS last_reason,
		       (array_agg(ban_seconds ORDER BY created_at DESC))[1]                             AS last_ban,
		       (array_agg(id ORDER BY created_at DESC) FILTER (WHERE status = 'recommended'))[1] AS pending_id,
		       max(COALESCE(executed_at, decided_at, created_at) + make_interval(secs => ban_seconds))
		           FILTER (WHERE status IN ('approved','executed') AND ban_seconds > 0)         AS blocked_until,
		       bool_or(status IN ('approved','executed')
		               AND (ban_seconds = 0
		                    OR COALESCE(executed_at, decided_at, created_at) + make_interval(secs => ban_seconds) > now())) AS blocked
		FROM response_actions
		GROUP BY source_ip
		ORDER BY last_seen DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("respond: offenders: %w", err)
	}
	defer rows.Close()
	out := make([]Offender, 0, 64)
	for rows.Next() {
		var o Offender
		var pendingID *string
		if err := rows.Scan(&o.SourceIP, &o.Offenses, &o.Total, &o.Pending, &o.LastSeen,
			&o.LastStatus, &o.LastReason, &o.LastBanSecs, &pendingID, &o.BlockedUntil, &o.Blocked); err != nil {
			return nil, err
		}
		if pendingID != nil {
			o.PendingID = *pendingID
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

const actionCols = `id, created_at, host(source_ip), action, COALESCE(reason,''), COALESCE(rule_id,''),
	ban_seconds, offense_count, source, status, COALESCE(responder,''),
	COALESCE(decided_by,''), decided_at, executed_at, COALESCE(error,'')`

func scanAction(row pgx.Row) (*Action, error) {
	var a Action
	var status, action string
	if err := row.Scan(&a.ID, &a.CreatedAt, &a.SourceIP, &action, &a.Reason, &a.RuleID,
		&a.BanSeconds, &a.OffenseCount, &a.Source, &status, &a.Responder,
		&a.DecidedBy, &a.DecidedAt, &a.ExecutedAt, &a.Error); err != nil {
		return nil, err
	}
	a.ActionType, a.Status = action, Status(status)
	return &a, nil
}

// Get fetches one action by id.
func (s *Store) Get(ctx context.Context, id string) (*Action, error) {
	a, err := scanAction(s.pool.QueryRow(ctx, `SELECT `+actionCols+` FROM response_actions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("respond: action not found")
	}
	if err != nil {
		return nil, fmt.Errorf("respond: get: %w", err)
	}
	return a, nil
}

// SetStatus changes the status + records the decision (approve/dismiss).
func (s *Store) SetStatus(ctx context.Context, id string, status Status, decidedBy string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE response_actions SET status = $2, decided_by = $3, decided_at = now() WHERE id = $1`,
		id, string(status), strOrNil(decidedBy))
	if err != nil {
		return fmt.Errorf("respond: set status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("respond: action not found")
	}
	return nil
}

// SetExecuted records the execution result: executed if execErr is nil, otherwise failed.
func (s *Store) SetExecuted(ctx context.Context, id, responder string, execErr error) error {
	status, errMsg := StatusExecuted, ""
	if execErr != nil {
		status, errMsg = StatusFailed, execErr.Error()
	}
	var execAt any = time.Now()
	if execErr != nil {
		execAt = nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE response_actions SET status = $2, responder = $3, executed_at = $4, error = $5 WHERE id = $1`,
		id, string(status), strOrNil(responder), execAt, strOrNil(errMsg))
	if err != nil {
		return fmt.Errorf("respond: set executed: %w", err)
	}
	return nil
}

// List returns the most recent actions; if status != "" only that status.
func (s *Store) List(ctx context.Context, status, search string, limit int) ([]Action, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var conds []string
	args := []any{}
	if status != "" {
		args = append(args, status)
		conds = append(conds, fmt.Sprintf("status = $%d", len(args)))
	}
	if search != "" {
		args = append(args, "%"+search+"%")
		n := len(args)
		conds = append(conds, fmt.Sprintf("(host(source_ip) ILIKE $%d OR rule_id ILIKE $%d OR reason ILIKE $%d)", n, n, n))
	}
	q := `SELECT ` + actionCols + ` FROM response_actions`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d`, limit)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("respond: list: %w", err)
	}
	defer rows.Close()
	out := make([]Action, 0, 32)
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// ActiveBlocks returns the source IPs that should currently be blocked: approved or
// executed block actions whose ban window has not expired (ban_seconds = 0 = permanent).
// Used to feed agent-side firewalls.
func (s *Store) ActiveBlocks(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT host(source_ip) FROM response_actions
		WHERE action = 'block' AND status IN ('approved','executed')
		  AND (ban_seconds = 0
		       OR COALESCE(executed_at, decided_at, created_at) + make_interval(secs => ban_seconds) > now())`)
	if err != nil {
		return nil, fmt.Errorf("respond: active blocks: %w", err)
	}
	defer rows.Close()
	out := make([]string, 0, 32)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
