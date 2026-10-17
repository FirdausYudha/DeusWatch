package worker

import (
	"context"
	"log"
	"sync"
	"time"

	"deuswatch/internal/ingest"
)

// BatchSink writes many events in one go (satisfied by *store.Store).
type BatchSink interface {
	InsertEvents(ctx context.Context, evs []*ingest.Event) error
}

// EventQueue accepts an event for storage and reports the outcome through ack once that event is
// durably stored, which is also when the bus message behind it may be acknowledged. The direct
// implementation calls ack before returning; the Batcher calls it after its batch commits.
type EventQueue interface {
	Add(ctx context.Context, e *ingest.Event, ack func(error))
}

// DirectQueue stores each event on its own, one round trip per event. It is the behaviour the
// pipeline had before batching and the fallback when no batch sink is configured.
type DirectQueue struct{ Sink EventSink }

func (d DirectQueue) Add(ctx context.Context, e *ingest.Event, ack func(error)) {
	ack(d.Sink.InsertEvent(ctx, e))
}

// Batcher groups events into one multi-row INSERT.
//
// Why this exists: the detect consumer's callback used to spend most of its time waiting on a
// per-event round trip to Postgres, and the NATS callback is serial, so that wait was the
// pipeline's throughput ceiling. Here the handler enqueues and returns, the consumer immediately
// pulls the next message, and one statement stores up to MaxRows of them.
//
// Durability is unchanged. The bus message is acknowledged from the ack passed in here, which the
// Batcher calls only after the INSERT has committed, so a crash with a full buffer loses nothing:
// those messages were never acked and JetStream redelivers them.
type Batcher struct {
	sink    BatchSink
	maxRows int
	linger  time.Duration

	in       chan queued
	quit     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

type queued struct {
	ev  *ingest.Event
	ack func(error)
}

// Batch tuning. MaxRows is the batch the runtime aims for and the depth of the incoming buffer;
// linger bounds how long a half-full batch waits, so a quiet system still stores an event
// promptly rather than holding it until enough traffic arrives to fill a batch.
const (
	DefaultBatchRows   = 200
	DefaultBatchLinger = 200 * time.Millisecond
)

// NewBatcher starts the flush loop. Call Close to drain it.
func NewBatcher(sink BatchSink, maxRows int, linger time.Duration) *Batcher {
	if maxRows <= 0 {
		maxRows = DefaultBatchRows
	}
	if linger <= 0 {
		linger = DefaultBatchLinger
	}
	b := &Batcher{
		sink:    sink,
		maxRows: maxRows,
		linger:  linger,
		// Twice MaxRows so producers can keep filling the next batch while the current one is
		// in flight. A full channel blocks Add, which is the backpressure we want: it stalls the
		// consumer instead of growing an unbounded in-memory queue of unacked events.
		in:      make(chan queued, maxRows*2),
		quit:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go b.run()
	return b
}

// Add enqueues an event. It blocks while the buffer is full (backpressure) and returns as soon as
// the event is queued; ack is called later, from the flush loop.
func (b *Batcher) Add(ctx context.Context, e *ingest.Event, ack func(error)) {
	select {
	case b.in <- queued{ev: e, ack: ack}:
	case <-b.stopped:
		// The loop has gone: Nak so the message is redelivered rather than dropped.
		ack(context.Canceled)
	case <-ctx.Done():
		ack(ctx.Err())
	}
}

func (b *Batcher) run() {
	defer close(b.stopped)
	// Go 1.23 onward, Stop and Reset guarantee no stale value is left in the channel, so the
	// loop does not need to drain it.
	timer := time.NewTimer(b.linger)
	timer.Stop()
	batch := make([]queued, 0, b.maxRows)
	timing := false

	flush := func() {
		if timing {
			timer.Stop()
			timing = false
		}
		b.flush(batch)
		batch = batch[:0]
	}

	for {
		select {
		case q := <-b.in:
			batch = append(batch, q)
			if len(batch) >= b.maxRows {
				flush()
				continue
			}
			if !timing {
				timer.Reset(b.linger)
				timing = true
			}
		case <-timer.C:
			timing = false
			flush()
		case <-b.quit:
			// Take whatever is already buffered so a planned restart stores its in-flight work
			// instead of leaving it to redelivery. Anything an Add puts in after this drains is
			// never acked, so JetStream redelivers it: late, never lost.
			for {
				select {
				case q := <-b.in:
					batch = append(batch, q)
					if len(batch) >= b.maxRows {
						b.flush(batch)
						batch = batch[:0]
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		}
	}
}

// flush stores one batch and reports the single outcome to every event in it. Each event is
// acknowledged individually because each came from its own bus message.
func (b *Batcher) flush(batch []queued) {
	if len(batch) == 0 {
		return
	}
	evs := make([]*ingest.Event, len(batch))
	for i, q := range batch {
		evs[i] = q.ev
	}
	// Its own timeout, not the handler's: the handler has already returned, so there is no
	// caller-scoped deadline left to inherit, and a batch must not be cancelled by whichever
	// request happened to contribute its first event.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := b.sink.InsertEvents(ctx, evs)
	cancel()
	if err != nil {
		log.Printf("worker: storing a batch of %d events failed, they will be redelivered: %v", len(batch), err)
	}
	for _, q := range batch {
		q.ack(err)
	}
}

// Close drains the buffer, flushes what is left, and waits for the loop to finish. It does not
// close the incoming channel: Add runs on the bus callback goroutine, and closing underneath it
// would turn a shutdown race into a send-on-closed-channel panic.
func (b *Batcher) Close() {
	b.stopOnce.Do(func() {
		close(b.quit)
		<-b.stopped
	})
}
