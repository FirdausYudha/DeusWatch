package main

// The sweep that turns an environmental reading into something somebody is told about (gap 6).
//
// Readings arrive at the API, which records them and judges them against their limits but
// announces nothing. This is where a change becomes an alert, for two reasons. Every notification
// path already lives in the worker, and splitting them across two processes means two places to
// look when a notification does not arrive. And the harder half of this feature is not the
// threshold at all: it is noticing a sensor that has STOPPED reporting, which no amount of
// handling pushed readings can detect, because the whole symptom is that none arrive.

import (
	"context"
	"log"
	"time"

	"deuswatch/internal/selfhealth"
	"deuswatch/internal/store"
	"deuswatch/internal/worker"
)

// envSweepInterval is how often both halves run. A minute is fine for a room that takes tens of
// minutes to drift out of range, and a breach is usually noticed by the reading that caused it
// rather than by this loop.
const envSweepInterval = time.Minute

func runEnvSensors(ctx context.Context, st *store.Store, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {
	t := time.NewTicker(envSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweepEnvSensors(ctx, st, onAlert, annotate)
		}
	}
}

func sweepEnvSensors(ctx context.Context, st *store.Store, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Threshold crossings, in both directions. PendingEnvTransitions marks them announced as it
	// selects them, so a slow notifier cannot cause the same alert twice.
	pending, err := st.PendingEnvTransitions(sctx)
	if err != nil {
		log.Printf("worker: env sensor transitions: %v", err)
	}
	for _, e := range pending {
		recovered := !e.Alerting
		raiseEnvAlert(sctx, st, onAlert, annotate, e, e.Breach, recovered, false)
		if recovered {
			log.Printf("worker: env sensor %q (%s) back within limits", e.Name, e.Location)
		} else {
			log.Printf("worker: env sensor %q (%s) BREACH: %s", e.Name, e.Location, e.Breach)
		}
	}

	// Silence. A pushed sensor that stops reporting leaves its last good reading on the board, and
	// nothing on that screen says the number is old: the display is identical to a healthy sensor.
	// StaleEnvSensors latches each one, so this is one alert per outage rather than one a minute.
	stale, err := st.StaleEnvSensors(sctx)
	if err != nil {
		log.Printf("worker: env sensor staleness: %v", err)
		return
	}
	for _, e := range stale {
		raiseEnvAlert(sctx, st, onAlert, annotate, e, e.StaleWhy, false, true)
		log.Printf("worker: env sensor %q (%s) has gone quiet: %s", e.Name, e.Location, e.StaleWhy)
	}
}

func raiseEnvAlert(ctx context.Context, st *store.Store, onAlert worker.AlertHook,
	annotate worker.AlertAnnotator, e store.EnvSensor, message string, recovered, stale bool) {

	ev := selfhealth.EnvSensorEvent(time.Now(), e.Name, e.Location, message, recovered, stale)
	if annotate != nil {
		annotate(ev)
	}
	if err := st.InsertEvent(ctx, ev); err != nil {
		log.Printf("worker: store env sensor alert for %q: %v", e.Name, err)
		return
	}
	if onAlert != nil {
		onAlert(ctx, ev)
	}
}
