package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"deuswatch/internal/probe"
	"deuswatch/internal/secret"
	"deuswatch/internal/selfhealth"
	"deuswatch/internal/store"
	"deuswatch/internal/worker"
)

// Service/API health probing (gap 1 of the hospital field insight).
//
// Scheduling is a single ticker that scans for DUE checks rather than one goroutine per check.
// The checks are edited live from the UI, and a goroutine-per-check design has to chase every
// add, edit, disable and delete to avoid leaking a prober or probing a deleted endpoint. A scan
// reads the current configuration every few seconds and is therefore correct by construction; at
// the tens-of-checks scale this feature is for, the scan costs one indexed query.

const (
	// How often to look for checks whose interval has elapsed. This is the scheduling granularity,
	// not the probe rate: a 60s check is probed every 60s, give or take one tick.
	serviceProbeTick = 5 * time.Second
	// Probes run in parallel so one unreachable endpoint sitting on its timeout does not delay
	// every other check behind it, which is exactly the situation this feature exists to report.
	serviceProbeConcurrency = 8
	// Cap on redirect following. A login page that bounces to itself is a failure, not a probe.
	serviceProbeMaxRedirects = 5
)

func runServiceChecks(ctx context.Context, st *store.Store, cipher *secret.Cipher,
	onAlert worker.AlertHook, annotate worker.AlertAnnotator) {

	hc := &http.Client{
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= serviceProbeMaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	log.Printf("worker: service health prober active (scan every %s)", serviceProbeTick)

	t := time.NewTicker(serviceProbeTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probeDueChecks(ctx, st, cipher, hc, onAlert, annotate)
		}
	}
}

// probeDueChecks runs every check whose interval has elapsed.
func probeDueChecks(ctx context.Context, st *store.Store, cipher *secret.Cipher, hc *http.Client,
	onAlert worker.AlertHook, annotate worker.AlertAnnotator) {

	lc, cancel := context.WithTimeout(ctx, 30*time.Second)
	checks, err := st.EnabledServiceChecks(lc)
	cancel()
	if err != nil {
		log.Printf("worker: load service checks: %v", err)
		return
	}

	now := time.Now()
	due := make([]store.ServiceCheck, 0, len(checks))
	for _, c := range checks {
		if c.LastCheckedAt == nil ||
			now.Sub(*c.LastCheckedAt) >= time.Duration(c.IntervalSecs)*time.Second {
			due = append(due, c)
		}
	}
	if len(due) == 0 {
		return
	}

	sem := make(chan struct{}, serviceProbeConcurrency)
	var wg sync.WaitGroup
	for _, c := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func(c store.ServiceCheck) {
			defer wg.Done()
			defer func() { <-sem }()
			probeOneCheck(ctx, st, cipher, hc, c, onAlert, annotate)
		}(c)
	}
	wg.Wait()
}

// probeOneCheck performs one check, records it, and emits the alert when the state changed.
func probeOneCheck(ctx context.Context, st *store.Store, cipher *secret.Cipher, hc *http.Client,
	c store.ServiceCheck, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {

	headers, err := decodeCheckHeaders(cipher, c.HeadersEnc)
	if err != nil {
		// Deliberately NOT recorded as a failed probe. Sending the request without its credentials
		// would get a 401 and report the monitored service as down, which blames the wrong system
		// and sends someone to debug an integration that is fine.
		log.Printf("worker: service check %q skipped: %v", c.Name, err)
		return
	}

	res := probe.Run(ctx, probe.Check{
		Kind:         c.Kind,
		Target:       c.Target,
		Method:       c.Method,
		Headers:      headers,
		ExpectStatus: c.ExpectStatus,
		ExpectBody:   c.ExpectBody,
		Timeout:      time.Duration(c.TimeoutSecs) * time.Second,
		LatencyWarn:  time.Duration(c.LatencyWarnMS) * time.Millisecond,
	}, hc)

	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	transition, after, err := st.RecordServiceCheckResult(rctx, c.ID, store.ServiceCheckResult{
		OK:        res.OK,
		Status:    res.Status,
		LatencyMS: int(res.Latency.Milliseconds()),
		Error:     res.Error,
	})
	if err != nil {
		log.Printf("worker: record service check %q: %v", c.Name, err)
		return
	}
	if transition == store.TransitionNone {
		return
	}

	ev := selfhealth.ServiceCheckEvent(time.Now(), after.Name, after.Group,
		transition == store.TransitionDown, after.LastError, after.ConsecFailures)
	if annotate != nil {
		annotate(ev)
	}
	if err := st.InsertEvent(rctx, ev); err != nil {
		log.Printf("worker: store service check alert: %v", err)
		return
	}
	if onAlert != nil {
		onAlert(rctx, ev)
	}
	log.Printf("worker: service check %q (%s) -> %s", after.Name, after.Group, transition)
}

// decodeCheckHeaders unseals the stored request headers. No headers is the ordinary case and is
// not an error; configured-but-unreadable is, because probing without them tests the wrong thing.
func decodeCheckHeaders(cipher *secret.Cipher, enc string) (map[string]string, error) {
	if enc == "" {
		return nil, nil
	}
	if cipher == nil {
		return nil, fmt.Errorf("credentials are configured but the secrets cipher is unavailable (set SECRETS_KEY)")
	}
	plain, err := cipher.Decrypt(enc)
	if err != nil {
		return nil, fmt.Errorf("stored credentials could not be decrypted: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(plain), &m); err != nil {
		return nil, fmt.Errorf("stored credentials are not a JSON object: %w", err)
	}
	return m, nil
}
