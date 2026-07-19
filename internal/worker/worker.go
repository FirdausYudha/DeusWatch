// Package worker ties together the bus + detectors + store: it consumes normalized
// events, stores them, runs detection, and stores the alerts that fire.
package worker

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"deuswatch/internal/bus"
	"deuswatch/internal/detect"
	"deuswatch/internal/enrich"
	"deuswatch/internal/ingest"
)

// AlertHook is called for each alert that fires & is stored (e.g. response
// recommendations + notifications). May be nil. The worker stays unaware of the
// respond/notify details.
type AlertHook func(ctx context.Context, alert *ingest.Event)

// AlertSuppressor decides whether a fired alert should be dropped (not stored, not acted on).
// It powers the trusted-session gate: a file-change alert correlated with a recent login from a
// whitelisted admin/deploy IP is an official change, not an attack. nil = never suppress.
type AlertSuppressor func(ctx context.Context, alert *ingest.Event) bool

// AlertAnnotator enriches an alert in place right before it is stored - e.g. stamping
// the matching remediation playbook onto deuswatch.remediation.*. nil = no annotation.
type AlertAnnotator func(alert *ingest.Event)

// EventSink writes DCS events (satisfied by *store.Store).
type EventSink interface {
	InsertEvent(ctx context.Context, e *ingest.Event) error
}

// Handler returns a bus.Handler for the logs.normalized subject: enrich the event
// (if an enricher is set), persist it, run the detectors, persist any fired alerts,
// then call onAlert for each alert. enricher & onAlert may be nil.
func Handler(ctx context.Context, sink EventSink, enricher *enrich.Enricher, onAlert AlertHook, suppress AlertSuppressor, annotate AlertAnnotator, detectors ...detect.Detector) bus.Handler {
	return func(_ string, data []byte) error {
		var e ingest.Event
		if err := json.Unmarshal(data, &e); err != nil {
			log.Printf("worker: dropped corrupt message: %v", err)
			return nil // poison message: do not redeliver
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now()
		}

		ic, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if enricher != nil {
			if err := enricher.EnrichEvent(ic, &e); err != nil {
				log.Printf("worker: enrichment failed: %v", err) // continue; status=failed
			}
		}

		// Pre-labeled ingested events (e.g. Suricata alerts) are alerts already —
		// annotate before persisting so the recommendation is stored with them.
		if annotate != nil && e.DeusWatch.Label != "" {
			annotate(&e)
		}
		if err := sink.InsertEvent(ic, &e); err != nil {
			return err // returned -> Nak -> redeliver
		}
		// A pre-labeled ingested event (e.g. a Suricata/IDS alert consumed as a log source) is
		// already an alert - an external detector decided so. Drive response/notify on it
		// directly, without a DeusWatch rule needing to re-fire. The trusted-session gate still
		// applies (a no-op for non-file alerts).
		if e.DeusWatch.Label != "" {
			if suppress == nil || !suppress(ic, &e) {
				log.Printf("worker: ALERT %s from %s (rule=%s)",
					e.DeusWatch.Label, alertSourceIP(&e), ruleID(&e))
				if onAlert != nil {
					onAlert(ic, &e)
				}
			}
		}
		for _, det := range detectors {
			alert := det.Inspect(&e)
			if alert == nil {
				continue
			}
			if suppress != nil && suppress(ic, alert) {
				// Trusted-session change (ADR 0002 Phase 4): don't drop it silently — record it as
				// a low-severity `authorized_change` audit event so there is a trail, but do NOT
				// notify or respond (it's an official deploy/content edit, not an attack). A sudden
				// change with no legitimate session is not suppressed and keeps its normal severity.
				markAuthorizedChange(alert)
				if err := sink.InsertEvent(ic, alert); err != nil {
					return err
				}
				log.Printf("worker: authorized change on %s recorded (trusted session; not alerted)",
					alertTarget(alert))
				continue
			}
			if annotate != nil {
				annotate(alert)
			}
			if err := sink.InsertEvent(ic, alert); err != nil {
				return err
			}
			log.Printf("worker: ALERT %s from %s (rule=%s)",
				alert.DeusWatch.Label, alertSourceIP(alert), ruleID(alert))
			if onAlert != nil {
				onAlert(ic, alert)
			}
		}
		return nil
	}
}

// markAuthorizedChange turns a trusted-session-suppressed file alert into a low-severity audit
// event: it keeps the file + who-data context but relabels it `authorized_change`, records the
// original severity, drops the severity below the notify threshold, and strips any
// remediation/containment so nothing fires downstream (ADR 0002 Phase 4).
func markAuthorizedChange(alert *ingest.Event) {
	alert.DeusWatch.Severity.Original = alert.Event.Severity
	alert.DeusWatch.Severity.EscalatedBy = "trusted-session (authorized change)"
	alert.Event.Severity = ingest.SeverityLow
	alert.DeusWatch.Label = "authorized_change"
	alert.DeusWatch.Remediation = ingest.Remediation{}
	alert.DeusWatch.Containment = nil
	if alert.Event.Outcome == "" {
		alert.Event.Outcome = "success"
	}
}

func alertSourceIP(e *ingest.Event) string {
	if e.Source != nil {
		return e.Source.IP
	}
	return "-"
}

// alertTarget is the most identifying locator for a log line: the changed file path for a
// file event, else the source IP.
func alertTarget(e *ingest.Event) string {
	if e.File != nil && e.File.Path != "" {
		return e.File.Path
	}
	return alertSourceIP(e)
}

func ruleID(e *ingest.Event) string {
	if e.Rule != nil {
		return e.Rule.ID
	}
	return "-"
}
