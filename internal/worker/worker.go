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

// EventSink writes DCS events (satisfied by *store.Store).
type EventSink interface {
	InsertEvent(ctx context.Context, e *ingest.Event) error
}

// Handler returns a bus.Handler for the logs.normalized subject: enrich the event
// (if an enricher is set), persist it, run the detectors, persist any fired alerts,
// then call onAlert for each alert. enricher & onAlert may be nil.
func Handler(ctx context.Context, sink EventSink, enricher *enrich.Enricher, onAlert AlertHook, detectors ...detect.Detector) bus.Handler {
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

		if err := sink.InsertEvent(ic, &e); err != nil {
			return err // returned -> Nak -> redeliver
		}
		for _, det := range detectors {
			alert := det.Inspect(&e)
			if alert == nil {
				continue
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

func alertSourceIP(e *ingest.Event) string {
	if e.Source != nil {
		return e.Source.IP
	}
	return "-"
}

func ruleID(e *ingest.Event) string {
	if e.Rule != nil {
		return e.Rule.ID
	}
	return "-"
}
