package tickets

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Alert-to-ticket automation.
//
// The field complaint this answers: "User itu kalau ada troubleshoot paling malas isi ticketing,
// isi insiden. Jadi dia lebih ke chatting. Jadi kita kadang dobel: WhatsApp ya kita terima, tiket
// ya kita isi sendiri." A queue that depends on somebody remembering to fill it in is a queue that
// under-reports the work, and since the queue is also how the team is judged, under-reporting it
// costs them twice.
//
// Two rules keep this from making things worse:
//
//   - It is OFF by default. Something that creates records on its own is switched on deliberately.
//   - Everything it opens is deduplicated. A brute-force rule fires every few seconds; without
//     collapsing those onto one ticket the automation would bury the queue it is meant to fill,
//     and the team would turn it off within the hour.

// AutomationConfig is the deployment-wide setting for alert-to-ticket and ticket notifications.
type AutomationConfig struct {
	Enabled          bool   `json:"enabled"`
	MinSeverity      int    `json:"min_severity"`
	DedupeWindowMins int    `json:"dedupe_window_mins"`
	DefaultAssignee  string `json:"default_assignee"`
	NotifyOnCreate   bool   `json:"notify_on_create"`
	NotifyOnResolve  bool   `json:"notify_on_resolve"`
}

// DefaultAutomationConfig is what a deployment that has never saved the form behaves like, and the
// fallback when the row cannot be read. Disabled: never invent ticket traffic because a query
// failed.
func DefaultAutomationConfig() AutomationConfig {
	return AutomationConfig{MinSeverity: 3, DedupeWindowMins: 60, NotifyOnCreate: true}
}

// LoadAutomationConfig reads the singleton config row.
func (s *Store) LoadAutomationConfig(ctx context.Context) (AutomationConfig, error) {
	c := DefaultAutomationConfig()
	err := s.q(ctx).QueryRow(ctx,
		`SELECT enabled, min_severity, dedupe_window_mins, default_assignee,
		        notify_on_create, notify_on_resolve
		   FROM ticket_automation WHERE id = 1`).
		Scan(&c.Enabled, &c.MinSeverity, &c.DedupeWindowMins, &c.DefaultAssignee,
			&c.NotifyOnCreate, &c.NotifyOnResolve)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return DefaultAutomationConfig(), fmt.Errorf("tickets: load automation config: %w", err)
	}
	return c, nil
}

// SaveAutomationConfig writes the singleton config row, clamping the values the UI could get wrong.
func (s *Store) SaveAutomationConfig(ctx context.Context, c AutomationConfig) error {
	if c.MinSeverity < 0 || c.MinSeverity > 4 {
		c.MinSeverity = 3
	}
	if c.DedupeWindowMins < 1 {
		c.DedupeWindowMins = 1
	}
	if c.DedupeWindowMins > 7*24*60 {
		c.DedupeWindowMins = 7 * 24 * 60
	}
	_, err := s.q(ctx).Exec(ctx, `
		INSERT INTO ticket_automation
		    (id, enabled, min_severity, dedupe_window_mins, default_assignee,
		     notify_on_create, notify_on_resolve, updated_at)
		VALUES (1,$1,$2,$3,$4,$5,$6, now())
		ON CONFLICT (id) DO UPDATE SET
		    enabled=$1, min_severity=$2, dedupe_window_mins=$3, default_assignee=$4,
		    notify_on_create=$5, notify_on_resolve=$6, updated_at=now()`,
		c.Enabled, c.MinSeverity, c.DedupeWindowMins, c.DefaultAssignee,
		c.NotifyOnCreate, c.NotifyOnResolve)
	if err != nil {
		return fmt.Errorf("tickets: save automation config: %w", err)
	}
	return nil
}

// severityNames indexes 0..4 for message text.
var severityNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func severityName(s int) string {
	if s < 0 || s >= len(severityNames) {
		return "UNKNOWN"
	}
	return severityNames[s]
}

// Message renders a ticket event for Telegram/email. The whole reason this exists: "kita bisa
// inject misal mau integrasi ke chat Telegram. Jadi setiap ada tiket masuk, masuk ke Telegram."
// People answer chat and ignore the queue, so the queue has to arrive in the chat.
//
// event is "opened" or "resolved".
func Message(t *Ticket, event string) (subject, body string) {
	icon := "🎫"
	if event == "resolved" {
		icon = "✅"
	}
	subject = fmt.Sprintf("%s Ticket %s: %s", icon, event, t.Title)

	var b strings.Builder
	fmt.Fprintf(&b, "%s Ticket %s\n%s\n", icon, event, t.Title)
	fmt.Fprintf(&b, "Severity: %s\n", severityName(t.Severity))
	fmt.Fprintf(&b, "Status: %s\n", t.Status)
	if t.Assignee != nil && *t.Assignee != "" {
		fmt.Fprintf(&b, "Assignee: %s\n", *t.Assignee)
	} else {
		b.WriteString("Assignee: (unassigned)\n")
	}
	if t.SourceIP != nil && *t.SourceIP != "" {
		fmt.Fprintf(&b, "Source IP: %s\n", *t.SourceIP)
	}
	if t.RuleID != nil && *t.RuleID != "" {
		fmt.Fprintf(&b, "Rule: %s\n", *t.RuleID)
	}
	if event == "resolved" && t.ResolvedAt != nil {
		// The number the scorecard is built on, in the message that announces the outcome.
		fmt.Fprintf(&b, "Time to resolve: %s\n", t.ResolvedAt.Sub(t.CreatedAt).Round(time.Second))
	}
	fmt.Fprintf(&b, "Ticket: %s\n", t.ID)
	return subject, strings.TrimRight(b.String(), "\n")
}

// TextNotifier delivers a free-form message to the configured channels. *notify.Dispatcher's
// SendText satisfies it; the package stays free of a notify import so the dependency points one way.
type TextNotifier func(ctx context.Context, subject, body string) error

// SetNotifier attaches the channel used to announce ticket events. Optional: with no notifier the
// store behaves exactly as before.
func (s *Store) SetNotifier(n TextNotifier) { s.notify = n }

// announceResolved sends the "resolved" message, in the background.
//
// Off the request path deliberately: Telegram and SMTP are remote calls with multi-second
// timeouts, and an analyst clicking Resolve should not wait on somebody else's mail server — nor
// see the resolve fail because that server is down. The ticket is already committed by this point,
// so the worst case is a missing message, never a lost state change.
func (s *Store) announceResolved(t *Ticket) {
	if s.notify == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cfg, err := s.LoadAutomationConfig(ctx)
		if err != nil || !cfg.NotifyOnResolve {
			return
		}
		subject, body := Message(t, "resolved")
		if err := s.notify(ctx, subject, body); err != nil {
			log.Printf("tickets: resolve notification failed: %v", err)
		}
	}()
}

// AlertTicket is what automation knows about the alert it is raising a ticket for.
type AlertTicket struct {
	Title    string
	Severity int
	RuleID   string
	SourceIP string
	Agent    string
	Detail   string
}

// DedupeKey identifies "the same problem happening again". Rule plus source plus agent: the same
// rule firing from a different host is a different problem and deserves its own ticket, while the
// same rule from the same host firing all afternoon is one.
func (a AlertTicket) DedupeKey() string {
	return strings.Join([]string{a.RuleID, a.SourceIP, a.Agent}, "|")
}

// TicketForAlert opens a ticket for an alert, or returns the live one it belongs to.
//
// Returns created=false with the existing ticket when a live ticket already covers this alert, so
// the caller can tell "raised a ticket" from "this is already known" and notify accordingly — the
// difference between a useful alert channel and a muted one.
func (s *Store) TicketForAlert(ctx context.Context, c AutomationConfig, a AlertTicket) (t *Ticket, created bool, err error) {
	if !c.Enabled {
		return nil, false, nil
	}
	if a.Severity < c.MinSeverity {
		return nil, false, nil
	}
	if a.Title == "" {
		a.Title = "DeusWatch alert"
	}

	key := a.DedupeKey()
	window := time.Duration(c.DedupeWindowMins) * time.Minute

	// An OPEN ticket within the window absorbs the recurrence. A resolved one deliberately does
	// not: the attack coming back after somebody closed it is news, and reopening the old ticket
	// would hide that it ever stopped.
	existing, err := scanTicket(s.q(ctx).QueryRow(ctx,
		`SELECT `+cols+` FROM tickets
		  WHERE dedupe_key = $1 AND status IN ('open','in_progress') AND created_at >= $2
		  ORDER BY created_at DESC LIMIT 1`, key, time.Now().Add(-window)))
	if err == nil {
		// Count the recurrence on the existing ticket. Collapsing repeats is what keeps the queue
		// readable, but discarding the fact that it fired four hundred more times would hide the
		// scale of the problem from the person holding the ticket.
		if _, err := s.q(ctx).Exec(ctx,
			`UPDATE tickets SET recurrences = recurrences + 1, updated_at = now() WHERE id = $1`,
			existing.ID); err != nil {
			// Non-fatal: the ticket exists, which is what the caller asked about.
			log.Printf("tickets: count recurrence on %s: %v", existing.ID, err)
		} else {
			existing.Recurrences++ // the returned ticket reflects the write just made
		}
		return existing, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("tickets: dedupe lookup: %w", err)
	}

	t, err = s.Create(ctx, "deuswatch", NewTicket{
		Title:       a.Title,
		Description: a.Detail,
		Severity:    a.Severity,
		Assignee:    c.DefaultAssignee,
		SourceIP:    a.SourceIP,
		RuleID:      a.RuleID,
		AutoCreated: true,
		DedupeKey:   key,
	})
	if err != nil {
		return nil, false, err
	}
	return t, true, nil
}
