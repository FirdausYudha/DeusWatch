// Package tickets is the Tier-2 DFIR case-management store (TheHive/IRIS-style):
// tickets with an open→in_progress→resolved→closed lifecycle, an assignee, case
// notes, and timestamps so time-to-resolve is measurable.
package tickets

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/tenancy"
)

// Valid statuses in workflow order.
var statuses = map[string]bool{"open": true, "in_progress": true, "resolved": true, "closed": true}

// Ticket is a DFIR case.
type Ticket struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    int        `json:"severity"`
	Status      string     `json:"status"`
	Assignee    *string    `json:"assignee"`
	CreatedBy   string     `json:"created_by"`
	SourceIP    *string    `json:"source_ip"`
	RuleID      *string    `json:"rule_id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ResolvedAt  *time.Time `json:"resolved_at"`
	ClosedAt    *time.Time `json:"closed_at"`

	// AckedAt is the first time a human did anything with this ticket: took it, moved it off open,
	// or wrote a note. Distinct from UpdatedAt, which every later edit overwrites. Nil forever on a
	// ticket nobody ever picked up, and the scorecard reports that rather than hiding it.
	AckedAt *time.Time `json:"acked_at"`
	AckedBy *string    `json:"acked_by"`
	// AutoCreated marks a ticket opened by automation rather than typed by a person. Response time
	// on a 3am alert and response time on a colleague's request are different measurements.
	AutoCreated bool `json:"auto_created"`
	// Recurrences counts the further alerts that collapsed onto this ticket. Deduplication
	// without it would quietly hide how big the problem is.
	Recurrences int `json:"recurrences"`
	// DedupeKey collapses a repeating alert onto one live ticket. Not exposed: it is bookkeeping,
	// and showing it invites someone to edit it.
	DedupeKey string `json:"-"`
	// GLPIID links this ticket to its counterpart in GLPI; nil when it has not been pushed.
	GLPIID       *int       `json:"glpi_id"`
	GLPISyncedAt *time.Time `json:"glpi_synced_at"`
}

// Comment is one case note on a ticket.
type Comment struct {
	ID        int64     `json:"id"`
	Author    string    `json:"author"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// Store persists tickets and their comments.
type Store struct {
	pool *pgxpool.Pool
	// notify announces ticket events on the chat/mail channels; nil when none is configured.
	notify TextNotifier
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// queryer is the subset of DB operations tickets uses; both *pgxpool.Pool and pgx.Tx satisfy it.
type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// q runs ticket queries inside the request's scoped transaction when present (so RLS on the tickets
// table filters to the caller's tenants), else on the raw pool. Ticket routes are all session-scoped
// (protect → withScope), so a scope is always present in practice; the pool fallback keeps direct
// callers working. NOTE: ticket creation currently stamps the Default tenant (no active-tenant
// context at create time); when non-Default tenants create tickets, the create path must stamp the
// active workspace's tenant so RLS WITH CHECK accepts it.
func (s *Store) q(ctx context.Context) queryer {
	if tx, ok := tenancy.TxFrom(ctx); ok {
		return tx
	}
	return s.pool
}

// host(source_ip) returns the bare address as text (no /32) and scans into *string
// (pgx won't scan inet directly into *string).
const cols = `id, title, description, severity, status, assignee, created_by, host(source_ip), rule_id,
	created_at, updated_at, resolved_at, closed_at, acked_at, acked_by, auto_created, recurrences,
	COALESCE(dedupe_key,''), glpi_id, glpi_synced_at`

func scanTicket(row pgx.Row) (*Ticket, error) {
	var t Ticket
	if err := row.Scan(&t.ID, &t.Title, &t.Description, &t.Severity, &t.Status, &t.Assignee,
		&t.CreatedBy, &t.SourceIP, &t.RuleID, &t.CreatedAt, &t.UpdatedAt, &t.ResolvedAt, &t.ClosedAt,
		&t.AckedAt, &t.AckedBy, &t.AutoCreated, &t.Recurrences, &t.DedupeKey,
		&t.GLPIID, &t.GLPISyncedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// NewTicket is the input for creating a ticket.
type NewTicket struct {
	Title       string
	Description string
	Severity    int
	Assignee    string
	SourceIP    string
	RuleID      string
	// AutoCreated and DedupeKey are set by automation, not by the API's create handler.
	AutoCreated bool
	DedupeKey   string
}

// Create inserts a ticket and returns it.
func (s *Store) Create(ctx context.Context, createdBy string, n NewTicket) (*Ticket, error) {
	if n.Title == "" {
		return nil, fmt.Errorf("tickets: title is required")
	}
	if n.Severity < 0 || n.Severity > 4 {
		n.Severity = 2
	}
	row := s.q(ctx).QueryRow(ctx,
		`INSERT INTO tickets (title, description, severity, assignee, created_by, source_ip, rule_id,
		                      auto_created, dedupe_key)
		 VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8,$9) RETURNING `+cols,
		n.Title, n.Description, n.Severity, nilIfEmpty(n.Assignee), createdBy,
		nilIfEmpty(n.SourceIP), nilIfEmpty(n.RuleID), n.AutoCreated, nilIfEmpty(n.DedupeKey))
	return scanTicket(row)
}

// List returns tickets, optionally filtered by status, newest first.
func (s *Store) List(ctx context.Context, status string, limit int) ([]Ticket, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + cols + ` FROM tickets`
	args := []any{}
	if status != "" {
		q += ` WHERE status = $1`
		args = append(args, status)
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d`, limit)
	rows, err := s.q(ctx).Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("tickets: list: %w", err)
	}
	defer rows.Close()
	out := make([]Ticket, 0, 16)
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// Get returns one ticket with its comments.
func (s *Store) Get(ctx context.Context, id string) (*Ticket, []Comment, error) {
	t, err := scanTicket(s.q(ctx).QueryRow(ctx, `SELECT `+cols+` FROM tickets WHERE id=$1`, id))
	if err != nil {
		return nil, nil, fmt.Errorf("tickets: not found: %w", err)
	}
	rows, err := s.q(ctx).Query(ctx,
		`SELECT id, author, body, created_at FROM ticket_comments WHERE ticket_id=$1 ORDER BY created_at`, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	comments := make([]Comment, 0, 8)
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.Author, &c.Body, &c.CreatedAt); err != nil {
			return nil, nil, err
		}
		comments = append(comments, c)
	}
	return t, comments, rows.Err()
}

// Update changes a ticket's editable fields and maintains the resolved/closed
// timestamps as the status transitions.
type UpdateFields struct {
	Title       *string
	Description *string
	Severity    *int
	Status      *string
	Assignee    *string
}

// Update applies the edit. actor is the username making it, recorded as the one who picked the
// ticket up if this is the first human touch; pass "" for a change no person made.
func (s *Store) Update(ctx context.Context, id, actor string, f UpdateFields) (*Ticket, error) {
	cur, _, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	// Taking the ticket or moving it off open is somebody picking it up. Editing the title is not:
	// that would let a passing typo fix count as a response and quietly flatter the scorecard.
	pickedUp := (f.Assignee != nil && *f.Assignee != "") ||
		(f.Status != nil && *f.Status != "open")
	if f.Title != nil {
		cur.Title = *f.Title
	}
	if f.Description != nil {
		cur.Description = *f.Description
	}
	if f.Severity != nil && *f.Severity >= 0 && *f.Severity <= 4 {
		cur.Severity = *f.Severity
	}
	if f.Assignee != nil {
		cur.Assignee = nilString(*f.Assignee)
	}
	resolvedAt := cur.ResolvedAt
	closedAt := cur.ClosedAt
	if f.Status != nil {
		if !statuses[*f.Status] {
			return nil, fmt.Errorf("tickets: invalid status %q", *f.Status)
		}
		cur.Status = *f.Status
		now := time.Now()
		switch cur.Status {
		case "resolved":
			if resolvedAt == nil {
				resolvedAt = &now
			}
			closedAt = nil
		case "closed":
			if resolvedAt == nil {
				resolvedAt = &now
			}
			closedAt = &now
		default: // open / in_progress → reopened
			resolvedAt = nil
			closedAt = nil
		}
	}
	ackedAt, ackedBy := cur.AckedAt, cur.AckedBy
	if ackedAt == nil && pickedUp && actor != "" {
		now := time.Now()
		ackedAt, ackedBy = &now, &actor
	}

	// Captured before the write: the announcement below must fire on the TRANSITION, not on every
	// later edit of an already-resolved ticket.
	wasResolved := cur.ResolvedAt != nil

	row := s.q(ctx).QueryRow(ctx,
		`UPDATE tickets SET title=$1, description=$2, severity=$3, status=$4, assignee=$5,
		 resolved_at=$6, closed_at=$7, acked_at=$8, acked_by=$9, updated_at=now()
		 WHERE id=$10 RETURNING `+cols,
		cur.Title, cur.Description, cur.Severity, cur.Status, cur.Assignee, resolvedAt, closedAt,
		ackedAt, ackedBy, id)
	t, err := scanTicket(row)
	if err != nil {
		return nil, err
	}
	if !wasResolved && t.ResolvedAt != nil {
		s.announceResolved(t)
	}
	return t, nil
}

// AddComment appends a case note and bumps the ticket's updated_at.
func (s *Store) AddComment(ctx context.Context, ticketID, author, body string) (*Comment, error) {
	if body == "" {
		return nil, fmt.Errorf("tickets: comment body is required")
	}
	var c Comment
	if err := s.q(ctx).QueryRow(ctx,
		`INSERT INTO ticket_comments (ticket_id, author, body) VALUES ($1,$2,$3)
		 RETURNING id, author, body, created_at`, ticketID, author, body).
		Scan(&c.ID, &c.Author, &c.Body, &c.CreatedAt); err != nil {
		return nil, fmt.Errorf("tickets: add comment: %w", err)
	}
	// Writing the first note is picking the ticket up just as much as taking it is — on an
	// auto-opened alert it is usually the FIRST thing that happens, so a scorecard that ignored it
	// would report "never answered" for tickets that were answered within minutes.
	_, _ = s.q(ctx).Exec(ctx,
		`UPDATE tickets
		    SET updated_at = now(),
		        acked_at   = COALESCE(acked_at, now()),
		        acked_by   = COALESCE(acked_by, $2)
		  WHERE id = $1`, ticketID, author)
	return &c, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nilString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
