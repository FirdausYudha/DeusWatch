package worker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

// fakeBatchSink records each batch it was handed, and can be told to fail.
type fakeBatchSink struct {
	mu      sync.Mutex
	batches [][]*ingest.Event
	fail    error
	delay   time.Duration
}

func (f *fakeBatchSink) InsertEvents(_ context.Context, evs []*ingest.Event) error {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]*ingest.Event, len(evs))
	copy(cp, evs)
	f.batches = append(f.batches, cp)
	return f.fail
}

func (f *fakeBatchSink) counts() (batches, rows int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.batches {
		rows += len(b)
	}
	return len(f.batches), rows
}

// TestBatcherFlushesOnSize is the throughput claim: enough events arriving together are stored in
// one statement, not one per event.
func TestBatcherFlushesOnSize(t *testing.T) {
	sink := &fakeBatchSink{}
	b := NewBatcher(sink, 10, time.Hour) // linger long enough that only size can trigger a flush
	defer b.Close()

	var acked atomic.Int64
	for i := 0; i < 30; i++ {
		b.Add(context.Background(), &ingest.Event{}, func(err error) {
			if err == nil {
				acked.Add(1)
			}
		})
	}
	waitFor(t, func() bool { n, _ := sink.counts(); return n == 3 })
	if n, rows := sink.counts(); n != 3 || rows != 30 {
		t.Fatalf("%d batches holding %d rows, want 3 batches of 10", n, rows)
	}
	waitFor(t, func() bool { return acked.Load() == 30 })
}

// TestBatcherFlushesOnLinger covers the quiet system: a single event must not sit in the buffer
// waiting for traffic that never comes.
func TestBatcherFlushesOnLinger(t *testing.T) {
	sink := &fakeBatchSink{}
	b := NewBatcher(sink, 1000, 30*time.Millisecond)
	defer b.Close()

	ackErr := make(chan error, 1)
	b.Add(context.Background(), &ingest.Event{}, func(err error) { ackErr <- err })
	select {
	case err := <-ackErr:
		if err != nil {
			t.Fatalf("ack reported %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a lone event was never flushed; a quiet system would never store anything")
	}
	if n, rows := sink.counts(); n != 1 || rows != 1 {
		t.Fatalf("%d batches holding %d rows, want 1 of 1", n, rows)
	}
}

// TestBatcherAckOnlyAfterCommit is the durability contract: nothing may be acknowledged while it
// is still only in memory, or a crash would lose it with no redelivery.
func TestBatcherAckOnlyAfterCommit(t *testing.T) {
	sink := &fakeBatchSink{delay: 150 * time.Millisecond}
	b := NewBatcher(sink, 2, time.Hour)
	defer b.Close()

	var acked atomic.Bool
	inserted := make(chan struct{})
	b.Add(context.Background(), &ingest.Event{}, func(error) { acked.Store(true) })
	b.Add(context.Background(), &ingest.Event{}, func(error) { close(inserted) })

	time.Sleep(30 * time.Millisecond) // the insert is in flight and has not returned
	if acked.Load() {
		t.Fatal("an event was acknowledged before its batch committed")
	}
	select {
	case <-inserted:
	case <-time.After(2 * time.Second):
		t.Fatal("the batch never committed")
	}
	if !acked.Load() {
		t.Fatal("the batch committed but its events were never acknowledged")
	}
}

// TestBatcherNaksWholeBatchOnFailure: a failed insert must Nak every message in the batch so
// JetStream redelivers them, rather than quietly dropping the ones that shared the statement.
func TestBatcherNaksWholeBatchOnFailure(t *testing.T) {
	boom := errors.New("insert failed")
	sink := &fakeBatchSink{fail: boom}
	b := NewBatcher(sink, 5, time.Hour)
	defer b.Close()

	var naks atomic.Int64
	for i := 0; i < 5; i++ {
		b.Add(context.Background(), &ingest.Event{}, func(err error) {
			if errors.Is(err, boom) {
				naks.Add(1)
			}
		})
	}
	waitFor(t, func() bool { return naks.Load() == 5 })
}

// TestBatcherCloseFlushesRemainder: a planned restart stores what it is holding instead of
// leaving a buffer's worth of work to redelivery.
func TestBatcherCloseFlushesRemainder(t *testing.T) {
	sink := &fakeBatchSink{}
	b := NewBatcher(sink, 1000, time.Hour)

	var acked atomic.Int64
	for i := 0; i < 7; i++ {
		b.Add(context.Background(), &ingest.Event{}, func(err error) {
			if err == nil {
				acked.Add(1)
			}
		})
	}
	b.Close()
	if n, rows := sink.counts(); n != 1 || rows != 7 {
		t.Fatalf("after Close: %d batches holding %d rows, want 1 of 7", n, rows)
	}
	if acked.Load() != 7 {
		t.Fatalf("%d events acknowledged after Close, want 7", acked.Load())
	}
	b.Close() // idempotent: a second Close must not panic or hang
}

// TestBatcherAddAfterCloseNaks: the shutdown race must redeliver, not drop and not panic on a
// closed channel.
func TestBatcherAddAfterCloseNaks(t *testing.T) {
	b := NewBatcher(&fakeBatchSink{}, 10, time.Hour)
	b.Close()
	got := make(chan error, 1)
	b.Add(context.Background(), &ingest.Event{}, func(err error) { got <- err })
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("Add after Close acknowledged the event; it would be lost")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Add after Close neither stored nor reported the event")
	}
}

// TestBatcherPreservesEventIdentity guards the obvious slice-reuse bug: the loop reuses its
// backing array between flushes, so a batch handed to the sink must not be mutated afterwards.
func TestBatcherPreservesEventIdentity(t *testing.T) {
	sink := &fakeBatchSink{}
	b := NewBatcher(sink, 2, time.Hour)
	defer b.Close()

	want := []string{"a", "b", "c", "d"}
	for _, id := range want {
		e := &ingest.Event{}
		e.Event.Dataset = id
		b.Add(context.Background(), e, func(error) {})
	}
	waitFor(t, func() bool { n, _ := sink.counts(); return n == 2 })

	sink.mu.Lock()
	defer sink.mu.Unlock()
	var got []string
	for _, batch := range sink.batches {
		for _, e := range batch {
			got = append(got, e.Event.Dataset)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (the batch slice was reused under the sink)", got, want)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}
