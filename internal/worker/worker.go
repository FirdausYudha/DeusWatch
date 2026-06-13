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
	"deuswatch/internal/ingest"
)

// EventSink menulis event DCS (dipenuhi oleh *store.Store).
type EventSink interface {
	InsertEvent(ctx context.Context, e *ingest.Event) error
}

// Handler mengembalikan bus.Handler untuk subject logs.normalized: persist event,
// jalankan detektor brute-force, persist alert bila terpicu.
func Handler(ctx context.Context, sink EventSink, det *detect.BruteForceDetector) bus.Handler {
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

		if err := sink.InsertEvent(ic, &e); err != nil {
			return err // dikembalikan -> Nak -> redeliver
		}
		if alert := det.Inspect(&e); alert != nil {
			if err := sink.InsertEvent(ic, alert); err != nil {
				return err
			}
			log.Printf("worker: ALERT %s dari %s (rule=%s, %s)",
				alert.DeusWatch.Label, alert.Source.IP, alert.Rule.ID, alert.Threat.Technique.ID)
		}
		return nil
	}
}
