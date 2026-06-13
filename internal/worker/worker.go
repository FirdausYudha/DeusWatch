// Package worker menyatukan bus + detektor + store: ia mengonsumsi event
// normalized, menyimpannya, menjalankan deteksi, dan menyimpan alert yang terpicu.
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
	"deuswatch/internal/respond"
)

// EventSink menulis event DCS (dipenuhi oleh *store.Store).
type EventSink interface {
	InsertEvent(ctx context.Context, e *ingest.Event) error
}

// Handler mengembalikan bus.Handler untuk subject logs.normalized: enrich event
// (bila enricher disetel), persist, jalankan detektor, persist alert yang terpicu,
// dan (bila engine disetel) buat rekomendasi respons untuk tiap alert.
// enricher & engine boleh nil (lewati tahap itu).
func Handler(ctx context.Context, sink EventSink, enricher *enrich.Enricher, engine *respond.Engine, detectors ...detect.Detector) bus.Handler {
	return func(_ string, data []byte) error {
		var e ingest.Event
		if err := json.Unmarshal(data, &e); err != nil {
			log.Printf("worker: pesan rusak di-drop: %v", err)
			return nil // poison message: jangan redeliver
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now()
		}

		ic, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if enricher != nil {
			if err := enricher.EnrichEvent(ic, &e); err != nil {
				log.Printf("worker: enrichment gagal: %v", err) // lanjut; status=failed
			}
		}

		if err := sink.InsertEvent(ic, &e); err != nil {
			return err // dikembalikan -> Nak -> redeliver
		}
		for _, det := range detectors {
			alert := det.Inspect(&e)
			if alert == nil {
				continue
			}
			if err := sink.InsertEvent(ic, alert); err != nil {
				return err
			}
			log.Printf("worker: ALERT %s dari %s (rule=%s)",
				alert.DeusWatch.Label, alertSourceIP(alert), ruleID(alert))
			if engine != nil {
				if _, err := engine.Recommend(ic, alert); err != nil {
					log.Printf("worker: rekomendasi respons gagal: %v", err)
				}
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
