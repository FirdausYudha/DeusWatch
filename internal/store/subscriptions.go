package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrNotFound is returned when a subscription lookup/mutation matches no row.
var ErrNotFound = errors.New("store: not found")

// Subscription is one external subscriber of the rich-log API. The plaintext API key is never
// stored — only its SHA-256 (TokenHash). Usage counters support billing and revocation.
type Subscription struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Scopes      []string   `json:"scopes"` // events | indicators
	MinSeverity int        `json:"min_severity"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RequestCnt  int64      `json:"request_count"`
}

// HashSubscriptionKey returns the storage hash (sha256 hex) of a presented API key. Auth hashes
// the presented key and looks up the row by this value, so the plaintext key is never persisted.
func HashSubscriptionKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// generateSubscriptionKey returns a new random API key with a recognizable prefix.
func generateSubscriptionKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "dws_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// CreateSubscription inserts a subscriber and returns it together with the ONE-TIME plaintext
// API key (never retrievable again). scopes defaults to {"events"}; unknown scopes are dropped.
func (s *Store) CreateSubscription(ctx context.Context, name string, scopes []string, minSev int) (Subscription, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Subscription{}, "", errors.New("store: subscription name required")
	}
	scopes = sanitizeScopes(scopes)
	if minSev < 0 {
		minSev = 0
	}
	key, err := generateSubscriptionKey()
	if err != nil {
		return Subscription{}, "", err
	}
	var sub Subscription
	err = s.pool.QueryRow(ctx, `
		INSERT INTO subscriptions (name, token_hash, scopes, min_severity)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, scopes, min_severity, enabled, created_at, last_used_at, request_count`,
		name, HashSubscriptionKey(key), scopes, minSev).
		Scan(&sub.ID, &sub.Name, &sub.Scopes, &sub.MinSeverity, &sub.Enabled, &sub.CreatedAt, &sub.LastUsedAt, &sub.RequestCnt)
	if err != nil {
		return Subscription{}, "", fmt.Errorf("store: create subscription: %w", err)
	}
	return sub, key, nil
}

// ListSubscriptions returns all subscribers, newest first (no secrets).
func (s *Store) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, scopes, min_severity, enabled, created_at, last_used_at, request_count
		FROM subscriptions ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list subscriptions: %w", err)
	}
	defer rows.Close()
	out := make([]Subscription, 0, 16)
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(&sub.ID, &sub.Name, &sub.Scopes, &sub.MinSeverity, &sub.Enabled,
			&sub.CreatedAt, &sub.LastUsedAt, &sub.RequestCnt); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// SetSubscriptionEnabled enables/disables a subscriber (a disabled key is rejected at auth).
func (s *Store) SetSubscriptionEnabled(ctx context.Context, id string, enabled bool) error {
	ct, err := s.pool.Exec(ctx, `UPDATE subscriptions SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return fmt.Errorf("store: set subscription enabled: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSubscription removes a subscriber permanently.
func (s *Store) DeleteSubscription(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM subscriptions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete subscription: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AuthenticateSubscription resolves a presented API key to an ENABLED subscriber, or returns
// ErrNotFound. It bumps the usage counters on success. The lookup is by key hash, so no
// plaintext comparison happens.
func (s *Store) AuthenticateSubscription(ctx context.Context, presentedKey string) (*Subscription, error) {
	presentedKey = strings.TrimSpace(presentedKey)
	if presentedKey == "" {
		return nil, ErrNotFound
	}
	var sub Subscription
	err := s.pool.QueryRow(ctx, `
		UPDATE subscriptions
		SET last_used_at = now(), request_count = request_count + 1
		WHERE token_hash = $1 AND enabled = true
		RETURNING id, name, scopes, min_severity, enabled, created_at, last_used_at, request_count`,
		HashSubscriptionKey(presentedKey)).
		Scan(&sub.ID, &sub.Name, &sub.Scopes, &sub.MinSeverity, &sub.Enabled, &sub.CreatedAt, &sub.LastUsedAt, &sub.RequestCnt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: authenticate subscription: %w", err)
	}
	return &sub, nil
}

// HasScope reports whether the subscription is allowed the given scope.
func (sub *Subscription) HasScope(scope string) bool {
	for _, s := range sub.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// SubEventsPage is one page of the subscription events feed.
type SubEventsPage struct {
	Events     []EventRow `json:"events"`
	NextCursor string     `json:"next_cursor"`
	HasMore    bool       `json:"has_more"`
}

// SubscriptionEvents returns a forward-only, cursor-paginated page of enriched events for a
// subscriber. Only events older than `lag` are served, so CTI/score enrichment has settled
// before an event becomes visible. minSev filters by severity; from (used only when cursor is
// empty) sets the starting point, otherwise the whole history is walked from the beginning.
func (s *Store) SubscriptionEvents(ctx context.Context, cursor string, minSev int, lag time.Duration, from time.Time, limit int) (SubEventsPage, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	curTime, curID, err := decodeEventCursor(cursor)
	if err != nil {
		return SubEventsPage{}, err
	}
	if cursor == "" && !from.IsZero() {
		curTime = from
	}
	settleCutoff := time.Now().Add(-lag)

	rows, err := s.pool.Query(ctx, `
		SELECT id::text, `+selectCols+`
		FROM events
		WHERE time <= $1
		  AND (time > $2 OR (time = $2 AND id::text > $3))
		  AND COALESCE(event_severity,0) >= $4
		ORDER BY time ASC, id ASC
		LIMIT $5`,
		settleCutoff, curTime, curID, minSev, limit)
	if err != nil {
		return SubEventsPage{}, fmt.Errorf("store: subscription events: %w", err)
	}
	defer rows.Close()

	page := SubEventsPage{Events: make([]EventRow, 0, limit), NextCursor: cursor}
	var lastTime time.Time
	var lastID string
	for rows.Next() {
		var id string
		var e EventRow
		if err := rows.Scan(
			&id,
			&e.Time, &e.Category, &e.Action, &e.Outcome, &e.Severity, &e.Dataset,
			&e.SourceIP, &e.HostName, &e.UserName, &e.RuleID, &e.RuleName,
			&e.TechniqueID, &e.TacticName, &e.Label, &e.Original,
			&e.GeoCountry, &e.GeoCity, &e.FeedName,
			&e.AbuseConfidence, &e.OTXPulseCount, &e.EnrichStatus, &e.EscalatedBy,
			&e.LLMVerdict, &e.LLMSummary,
			&e.FilePath, &e.FileHash, &e.FileHashVerdict, &e.FileHashDetail,
			&e.AgentID,
			&e.RemediationAction, &e.RemediationSource,
			&e.FileDiff,
			&e.ProcessName, &e.ProcessPID,
			&e.HTTPMethod, &e.HTTPURI, &e.HTTPStatus, &e.HTTPHost,
		); err != nil {
			return SubEventsPage{}, err
		}
		page.Events = append(page.Events, e)
		lastTime, lastID = e.Time, id
	}
	if err := rows.Err(); err != nil {
		return SubEventsPage{}, err
	}
	if len(page.Events) > 0 {
		page.NextCursor = encodeEventCursor(lastTime, lastID)
		page.HasMore = len(page.Events) == limit
	}
	return page, nil
}

// SubscriptionIndicators returns curated threat indicators (scored source IPs) for a subscriber,
// highest score first, filtered by a minimum score.
func (s *Store) SubscriptionIndicators(ctx context.Context, minScore, limit int) ([]IPScore, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if minScore < 0 {
		minScore = 0
	}
	rows, err := s.pool.Query(ctx,
		`SELECT host(ip), score, band, fired_times, abuse, otx, max_sev, updated_at
		 FROM ip_scores WHERE score >= $1 ORDER BY score DESC, updated_at DESC LIMIT $2`, minScore, limit)
	if err != nil {
		return nil, fmt.Errorf("store: subscription indicators: %w", err)
	}
	defer rows.Close()
	out := make([]IPScore, 0, limit)
	for rows.Next() {
		var v IPScore
		if err := rows.Scan(&v.IP, &v.Score, &v.Band, &v.FiredTimes, &v.Abuse, &v.OTX, &v.MaxSev, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ── cursor codec ──────────────────────────────────────────────
// The cursor is an opaque, URL-safe token encoding the last (time, id) delivered, so a
// subscriber resumes exactly where it left off with no gaps or duplicates.

const zeroUUID = "00000000-0000-0000-0000-000000000000"

func encodeEventCursor(t time.Time, id string) string {
	raw := fmt.Sprintf("%d|%s", t.UTC().UnixNano(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeEventCursor(cursor string) (time.Time, string, error) {
	if strings.TrimSpace(cursor) == "" {
		return time.Time{}, zeroUUID, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("store: bad cursor: %w", err)
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", errors.New("store: bad cursor format")
	}
	var nanos int64
	if _, err := fmt.Sscanf(parts[0], "%d", &nanos); err != nil {
		return time.Time{}, "", fmt.Errorf("store: bad cursor time: %w", err)
	}
	return time.Unix(0, nanos).UTC(), parts[1], nil
}

// sanitizeScopes keeps only known scopes and guarantees a non-empty default of {"events"}.
func sanitizeScopes(scopes []string) []string {
	valid := map[string]bool{"events": true, "indicators": true}
	seen := map[string]bool{}
	out := make([]string, 0, 2)
	for _, s := range scopes {
		s = strings.TrimSpace(strings.ToLower(s))
		if valid[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		out = []string{"events"}
	}
	return out
}
