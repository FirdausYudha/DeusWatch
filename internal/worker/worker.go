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
)

// AlertHook dipanggil untuk tiap alert yang terpicu & tersimpan (mis. rekomendasi
// respons + notifikasi). Boleh nil. Worker tetap tak tahu detail respond/notify.
type AlertHook func(ctx context.Context, alert *ingest.Event)

// EventSink menulis event DCS (dipenuhi oleh *store.Store).
type EventSink interface {
	InsertEvent(ctx context.Context, e *ingest.Event) error
}

// Handler mengembalikan bus.Handler untuk subject logs.normalized: enrich event
// (bila enricher disetel), persist, jalankan detektor, persist alert yang terpicu,
// lalu memanggil onAlert untuk tiap alert. enricher & onAlert boleh nil.
func Handler(ctx context.Context, sink EventSink, enricher *enrich.Enricher, onAlert AlertHook, detectors ...detect.Detector) bus.Handler {
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
