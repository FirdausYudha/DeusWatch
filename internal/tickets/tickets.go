// Package tickets is the Tier-2 DFIR case-management store (TheHive/IRIS-style):
// tickets with an open→in_progress→resolved→closed lifecycle, an assignee, case
// notes, and timestamps so time-to-resolve is measurable.
package tickets

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
}

// Comment is one case note on a ticket.
type Comment struct {
	ID        int64     `json:"id"`
	Author    string    `json:"author"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// Store persists tickets and their comments.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// host(source_ip) returns the bare address as text (no /32) and scans into *string
// (pgx won't scan inet directly into *string).
const cols = `id, title, description, severity, status, assignee, created_by, host(source_ip), rule_id, created_at, updated_at, resolved_at, closed_at`

func scanTicket(row pgx.Row) (*Ticket, error) {
	var t Ticket
	if err := row.Scan(&t.ID, &t.Title, &t.Description, &t.Severity, &t.Status, &t.Assignee,
		&t.CreatedBy, &t.SourceIP, &t.RuleID, &t.CreatedAt, &t.UpdatedAt, &t.ResolvedAt, &t.ClosedAt); err != nil {
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
}

// Create inserts a ticket and returns it.
func (s *Store) Create(ctx context.Context, createdBy string, n NewTicket) (*Ticket, error) {
	if n.Title == "" {
		return nil, fmt.Errorf("tickets: title is required")
	}
	if n.Severity < 0 || n.Severity > 4 {
		n.Severity = 2
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO tickets (title, description, severity, assignee, created_by, source_ip, rule_id)
		 VALUES ($1,$2,$3,$4,$5,$6::inet,$7) RETURNING `+cols,
		n.Title, n.Description, n.Severity, nilIfEmpty(n.Assignee), createdBy,
		nilIfEmpty(n.SourceIP), nilIfEmpty(n.RuleID))
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
	rows, err := s.pool.Query(ctx, q, args...)
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
	t, err := scanTicket(s.pool.QueryRow(ctx, `SELECT `+cols+` FROM tickets WHERE id=$1`, id))
	if err != nil {
		return nil, nil, fmt.Errorf("tickets: not found: %w", err)
	}
	rows, err := s.pool.Query(ctx,
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

func (s *Store) Update(ctx context.Context, id string, f UpdateFields) (*Ticket, error) {
	cur, _, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
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
	row := s.pool.QueryRow(ctx,
		`UPDATE tickets SET title=$1, description=$2, severity=$3, status=$4, assignee=$5,
		 resolved_at=$6, closed_at=$7, updated_at=now() WHERE id=$8 RETURNING `+cols,
		cur.Title, cur.Description, cur.Severity, cur.Status, cur.Assignee, resolvedAt, closedAt, id)
	return scanTicket(row)
}

// AddComment appends a case note and bumps the ticket's updated_at.
func (s *Store) AddComment(ctx context.Context, ticketID, author, body string) (*Comment, error) {
	if body == "" {
		return nil, fmt.Errorf("tickets: comment body is required")
	}
	var c Comment
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO ticket_comments (ticket_id, author, body) VALUES ($1,$2,$3)
		 RETURNING id, author, body, created_at`, ticketID, author, body).
		Scan(&c.ID, &c.Author, &c.Body, &c.CreatedAt); err != nil {
		return nil, fmt.Errorf("tickets: add comment: %w", err)
	}
	_, _ = s.pool.Exec(ctx, `UPDATE tickets SET updated_at=now() WHERE id=$1`, ticketID)
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
