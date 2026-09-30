package main

import (
	"context"
	"testing"
	"time"
)

// TestSafeGoRecoversPanic proves a panicking supervised loop does NOT crash the process (a bare
// `go fn()` would): the panic is recovered and fn is observed to have run. If the panic escaped,
// this test binary would abort instead of passing.
func TestSafeGoRecoversPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan struct{}, 1)

	safeGo(ctx, "test", func() {
		select {
		case ran <- struct{}{}:
		default:
		}
		panic("boom")
	})

	select {
	case <-ran:
		// fn executed and its panic was contained; process still alive.
	case <-time.After(2 * time.Second):
		t.Fatal("supervised goroutine never ran")
	}
	cancel()
}
