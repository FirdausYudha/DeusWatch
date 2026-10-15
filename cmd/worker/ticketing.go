package main

import (
	"context"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/notify"
	"deuswatch/internal/tickets"
)

// Alert-to-ticket automation in the worker (gap 4 of the hospital field insight).
//
// The configuration is cached and refreshed on a ticker rather than read per alert. Alerts arrive
// at whatever rate an attack produces them, and a config read on each one would put a query on the
// hot path to save an operator thirty seconds of latency on a setting they change twice a year.

const ticketConfigRefresh = 30 * time.Second

// ticketRaiser opens tickets for qualifying alerts and announces them on the notification channels.
type ticketRaiser struct {
	store      *tickets.Store
	dispatcher *notify.Dispatcher
	cfg        atomic.Pointer[tickets.AutomationConfig]
}

func newTicketRaiser(ctx context.Context, store *tickets.Store, dispatcher *notify.Dispatcher) *ticketRaiser {
	tr := &ticketRaiser{store: store, dispatcher: dispatcher}
	// Start from the real config rather than the default, so a worker restart does not spend the
	// first half-minute with automation off when the operator has it on.
	tr.refresh(ctx)
	return tr
}

func (tr *ticketRaiser) refresh(ctx context.Context) {
	c, err := tr.store.LoadAutomationConfig(ctx)
	if err != nil {
		log.Printf("worker: load ticket automation config: %v", err)
		return
	}
	tr.cfg.Store(&c)
}

// run keeps the cached config fresh.
func (tr *ticketRaiser) run(ctx context.Context) {
	t := time.NewTicker(ticketConfigRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tr.refresh(ctx)
		}
	}
}

// handle opens (or deduplicates onto) a ticket for one alert.
func (tr *ticketRaiser) handle(ctx context.Context, alert *ingest.Event) {
	cp := tr.cfg.Load()
	if cp == nil || !cp.Enabled {
		return
	}
	a := alertTicketFrom(alert)
	t, created, err := tr.store.TicketForAlert(ctx, *cp, a)
	if err != nil {
		log.Printf("worker: open ticket for alert: %v", err)
		return
	}
	if t == nil {
		return // below the threshold
	}
	if !created {
		// A recurrence of something already ticketed. Deliberately silent on the notification
		// channels: re-announcing the same incident every few seconds is how a channel gets muted,
		// and a muted channel is worse than none.
		return
	}
	log.Printf("worker: ticket %s opened for alert %q (severity %d)", t.ID, a.Title, a.Severity)

	if cp.NotifyOnCreate && tr.dispatcher.Enabled() {
		subject, body := tickets.Message(t, "opened")
		if err := tr.dispatcher.SendText(ctx, subject, body); err != nil {
			log.Printf("worker: ticket notification failed: %v", err)
		}
	}
}

// alertTicketFrom pulls the ticket-shaped facts out of an alert event.
func alertTicketFrom(ev *ingest.Event) tickets.AlertTicket {
	a := tickets.AlertTicket{Severity: int(ev.Event.Severity)}
	if ev.Rule != nil {
		a.RuleID = ev.Rule.ID
		a.Title = ev.Rule.Name
		if a.Title == "" {
			a.Title = ev.Rule.ID
		}
	}
	if ev.Source != nil {
		a.SourceIP = ev.Source.IP
	}
	if ev.Agent != nil {
		a.Agent = ev.Agent.ID
	}
	a.Detail = alertDetail(ev, a)
	return a
}

// alertDetail is the ticket body: enough for whoever picks it up to know what they are looking at
// without going back to the alert list first.
func alertDetail(ev *ingest.Event, a tickets.AlertTicket) string {
	var b strings.Builder
	b.WriteString("Opened automatically by DeusWatch from a detection alert.\n\n")
	if a.Agent != "" {
		b.WriteString("Agent: " + a.Agent + "\n")
	}
	if a.SourceIP != "" {
		b.WriteString("Source IP: " + a.SourceIP + "\n")
	}
	if a.RuleID != "" {
		b.WriteString("Rule: " + a.RuleID + "\n")
	}
	if ev.Threat != nil && ev.Threat.Technique.ID != "" {
		b.WriteString("MITRE: " + ev.Threat.Technique.ID + " " + ev.Threat.TacticName + "\n")
	}
	if ev.File != nil && ev.File.Path != "" {
		b.WriteString("File: " + ev.File.Path + "\n")
	}
	if !ev.Timestamp.IsZero() {
		b.WriteString("First seen: " + ev.Timestamp.UTC().Format(time.RFC3339) + "\n")
	}
	if ev.DeusWatch.Label != "" {
		b.WriteString("Label: " + ev.DeusWatch.Label + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
