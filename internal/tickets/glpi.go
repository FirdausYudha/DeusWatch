package tickets

import (
	"context"
	"fmt"
	"time"
)

// Store-side queries for the GLPI mirror. The HTTP client lives in internal/glpi; this file only
// knows which tickets need pushing and which need their status read back.

// GLPISyncActor is recorded as the responder when a status change arrives from GLPI.
//
// A status change means somebody picked the ticket up, so the SLA clock must stop — but we learn
// it from GLPI's status field, which does not say who. Attributing it to a named person would be a
// guess, and leaving it unattributed would report the ticket as never answered. This names the
// channel instead, and the scorecard shows it as its own row, which is the honest version.
const GLPISyncActor = "(via GLPI)"

// UnpushedTickets returns tickets that have not reached GLPI yet, oldest first so a backlog drains
// in the order it happened.
//
// LIVE tickets only. Switching this integration on at a site with a long ticket history would
// otherwise push every ticket it ever had into GLPI, burying the queue the team actually works and
// making the first impression of the feature a cleanup job. A ticket already resolved before the
// link existed has no business being opened in GLPI now; the open queue is both small and exactly
// what mirroring is for.
func (s *Store) UnpushedTickets(ctx context.Context, limit int) ([]Ticket, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.q(ctx).Query(ctx,
		`SELECT `+cols+` FROM tickets
		  WHERE glpi_id IS NULL AND status IN ('open','in_progress')
		  ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("tickets: unpushed: %w", err)
	}
	defer rows.Close()
	return collectTickets(rows)
}

// LinkedLiveTickets returns tickets already in GLPI whose status could still change there. Closed
// tickets are left out: nothing more is coming, and polling them forever would grow the work the
// sync does without bound.
func (s *Store) LinkedLiveTickets(ctx context.Context, limit int) ([]Ticket, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.q(ctx).Query(ctx,
		`SELECT `+cols+` FROM tickets
		  WHERE glpi_id IS NOT NULL AND status IN ('open','in_progress','resolved')
		  ORDER BY COALESCE(glpi_synced_at, created_at) LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("tickets: linked live: %w", err)
	}
	defer rows.Close()
	return collectTickets(rows)
}

// MarkPushed records the GLPI ticket this one became.
func (s *Store) MarkPushed(ctx context.Context, id string, glpiID int) error {
	_, err := s.q(ctx).Exec(ctx,
		`UPDATE tickets SET glpi_id=$2, glpi_synced_at=now() WHERE id=$1`, id, glpiID)
	if err != nil {
		return fmt.Errorf("tickets: mark pushed: %w", err)
	}
	return nil
}

// TouchGLPISync records that the link was reconciled, even when nothing changed. Without it a
// silently broken sync looks exactly like a quiet one.
func (s *Store) TouchGLPISync(ctx context.Context, id string) error {
	_, err := s.q(ctx).Exec(ctx, `UPDATE tickets SET glpi_synced_at=now() WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("tickets: touch glpi sync: %w", err)
	}
	return nil
}

// ApplyGLPIStatus moves a ticket to the status GLPI reports.
//
// Routed through Update rather than a direct UPDATE so the status change gets the same treatment
// as one made in the UI: resolved_at and closed_at are stamped, and the first pick-up sets
// acked_at. A ticket somebody worked entirely inside GLPI must still appear on the scorecard.
func (s *Store) ApplyGLPIStatus(ctx context.Context, id, status string) (*Ticket, error) {
	t, err := s.Update(ctx, id, GLPISyncActor, UpdateFields{Status: &status})
	if err != nil {
		return nil, err
	}
	if err := s.TouchGLPISync(ctx, id); err != nil {
		return nil, err
	}
	return t, nil
}

// rowScanner is the subset of pgx.Rows collectTickets needs.
type rowScanner interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func collectTickets(rows rowScanner) ([]Ticket, error) {
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

// GLPIContent renders the ticket body GLPI shows. Plain text: GLPI stores HTML, and pushing a
// security alert's raw fields as markup is how a log line with angle brackets becomes a rendering
// bug in somebody's ITSM.
func GLPIContent(t *Ticket) string {
	b := "Raised by DeusWatch.\n\n"
	if t.Description != "" {
		b += t.Description + "\n\n"
	}
	b += "Severity: " + severityName(t.Severity) + "\n"
	if t.SourceIP != nil && *t.SourceIP != "" {
		b += "Source IP: " + *t.SourceIP + "\n"
	}
	if t.RuleID != nil && *t.RuleID != "" {
		b += "Rule: " + *t.RuleID + "\n"
	}
	if t.AutoCreated {
		b += "Opened automatically from a detection alert.\n"
	}
	b += "DeusWatch ticket: " + t.ID + "\n"
	b += "Created: " + t.CreatedAt.UTC().Format(time.RFC3339) + "\n"
	return b
}
