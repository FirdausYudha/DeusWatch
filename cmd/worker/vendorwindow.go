package main

// The sweep that turns a vendor login outside its agreed hours into an alert (RV-01, S5).
//
// Modelled on the environmental sweep next door, and for the same reason: the judgement cannot be
// a Sigma rule, because Sigma matches one event's fields and has no notion of the current clock
// against a window. So a periodic loop reads the recent vendor logins and asks internal/vendorwindow
// whether each one falls outside its window.

import (
	"context"
	"log"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/store"
	"deuswatch/internal/worker"
)

// vendorSweepInterval is how often the loop runs. A minute is plenty: a vendor login is a discrete
// event already recorded, and the only cost of a slightly late alert is a minute, not a missed
// detection.
const vendorSweepInterval = time.Minute

// vendorLookback bounds how far back each sweep looks, wider than the interval so an event that
// arrived late (buffering, clock skew) is still seen. The exact-key dedup in the store makes the
// overlap harmless: the same login is never alerted twice.
const vendorLookback = 3 * time.Minute

func runVendorWindow(ctx context.Context, st *store.Store, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {
	t := time.NewTicker(vendorSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweepVendorWindow(ctx, st, onAlert, annotate)
		}
	}
}

func sweepVendorWindow(ctx context.Context, st *store.Store, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	logins, err := st.RecentVendorLogins(sctx, time.Now().Add(-vendorLookback))
	if err != nil {
		log.Printf("worker: vendor window: recent logins: %v", err)
		return
	}
	for _, vl := range logins {
		verdict, err := vl.Window.Outside(vl.When)
		if err != nil {
			// A bad timezone on the account is the operator's to fix, and it must not be read as
			// "inside the window". Log it and move on; nothing is alerted on a login we could not
			// judge, because a false alert here teaches people to ignore the channel.
			log.Printf("worker: vendor window: cannot judge %q: %v", vl.Window.Account, err)
			continue
		}
		if !verdict.Outside {
			continue
		}
		exists, err := st.VendorWindowAlertExists(sctx, vl.Window.Account, vl.When, vl.SourceIP)
		if err != nil {
			log.Printf("worker: vendor window: dedup check: %v", err)
			continue
		}
		if exists {
			continue
		}
		ev := vendorWindowEvent(vl, verdict.Reason)
		if annotate != nil {
			annotate(ev)
		}
		if err := st.InsertEvent(sctx, ev); err != nil {
			log.Printf("worker: vendor window: store alert for %q: %v", vl.Window.Account, err)
			continue
		}
		if onAlert != nil {
			onAlert(sctx, ev)
		}
		log.Printf("worker: vendor window: %s", verdict.Reason)
	}
}

// vendorWindowEvent builds the alert. Its timestamp is the LOGIN time, not now: that is what the
// store dedup keys on, and it places the alert on the timeline at the moment that matters.
func vendorWindowEvent(vl store.VendorLogin, reason string) *ingest.Event {
	ev := &ingest.Event{
		Timestamp: vl.When,
		Event: ingest.EventFields{
			Category: "authentication",
			Action:   "vendor_out_of_window",
			Outcome:  "failure",
			Severity: ingest.SeverityHigh,
			Dataset:  "deuswatch.vendor_window",
			Original: reason,
		},
		User: &ingest.User{Name: vl.Window.Account},
		Rule: &ingest.Rule{ID: "deuswatch_vendor_window", Name: "Vendor Access Window (RV-01)"},
		Threat: &ingest.Threat{
			Technique:  ingest.Technique{ID: "T1078", Name: "Valid Accounts"},
			TacticName: "initial-access",
		},
		DeusWatch: ingest.DeusWatch{Label: "vendor_window_violation"},
	}
	if vl.SourceIP != "" {
		ev.Source = &ingest.Endpoint{IP: vl.SourceIP}
	}
	if vl.Host != "" {
		ev.Host = &ingest.Host{Name: vl.Host}
	}
	return ev
}
