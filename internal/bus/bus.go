// Package bus wraps NATS JetStream as the DeusWatch message bus.
//
// Pipeline flow (design doc section 2): logs.raw -> logs.normalized ->
// logs.enriched -> alerts. JetStream is only a persistent streaming buffer;
// the source of truth remains PostgreSQL (no cache, no cache collisions).
package bus

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Pipeline subjects.
const (
	SubjectLogsRaw        = "logs.raw"
	SubjectLogsNormalized = "logs.normalized"
	SubjectLogsEnriched   = "logs.enriched"
	SubjectAlerts         = "alerts"
)

// Stream names.
const (
	StreamLogs   = "LOGS"
	StreamAlerts = "ALERTS"
)

// Bus wraps the NATS connection + JetStream handle.
type Bus struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// Connect opens a connection to NATS then ensures the DeusWatch streams exist.
func Connect(ctx context.Context, url string) (*Bus, error) {
	if url == "" {
		url = nats.DefaultURL
	}
	nc, err := nats.Connect(url,
		nats.Name("deuswatch"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("bus: connect NATS: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("bus: jetstream: %w", err)
	}
	b := &Bus{nc: nc, js: js}
	if err := b.ensureStreams(ctx); err != nil {
		nc.Close()
		return nil, err
	}
	return b, nil
}

func (b *Bus) ensureStreams(ctx context.Context) error {
	configs := []jetstream.StreamConfig{
		{
			Name:        StreamLogs,
			Description: "DeusWatch log pipeline (raw -> normalized -> enriched)",
			Subjects:    []string{"logs.>"},
			Storage:     jetstream.FileStorage,
			Retention:   jetstream.LimitsPolicy,
			MaxAge:      24 * time.Hour, // buffer; the source of truth is in Postgres
		},
		{
			Name:        StreamAlerts,
			Description: "DeusWatch alerts",
			Subjects:    []string{SubjectAlerts},
			Storage:     jetstream.FileStorage,
			Retention:   jetstream.LimitsPolicy,
			MaxAge:      72 * time.Hour,
		},
	}
	for _, cfg := range configs {
		if _, err := b.js.CreateOrUpdateStream(ctx, cfg); err != nil {
			return fmt.Errorf("bus: ensure stream %s: %w", cfg.Name, err)
		}
	}
	return nil
}

// Publish publishes the payload to the subject and waits for the JetStream ack (synchronous).
func (b *Bus) Publish(ctx context.Context, subject string, data []byte) error {
	if _, err := b.js.Publish(ctx, subject, data); err != nil {
		return fmt.Errorf("bus: publish %s: %w", subject, err)
	}
	return nil
}

// Handler processes a single message. Returning an error Naks the message (redeliver).
type Handler func(subject string, data []byte) error

// MsgHandler processes a message and takes ownership of acknowledging it: it must eventually
// call done exactly once, with nil to Ack or an error to Nak. It may return before done is
// called, which is the point: a handler that batches its database writes returns immediately and
// acknowledges only once the batch has committed, so the consumer keeps pulling while the batch
// fills instead of blocking on one round trip per message.
//
// The contract is what keeps batching safe. Acking on enqueue would tell JetStream the event is
// handled while it is still only in memory, and a crash would lose it with no redelivery. A
// handler that never calls done loses nothing either: the message stays unacked and JetStream
// redelivers it after AckWait.
type MsgHandler func(subject string, data []byte, done func(error))

// Consume creates a durable consumer on the stream for filterSubject, then calls the
// handler for each message. Returns a stop function to halt consumption.
func (b *Bus) Consume(ctx context.Context, stream, durable, filterSubject string, h Handler) (func(), error) {
	return b.ConsumeMsg(ctx, stream, durable, filterSubject,
		func(subject string, data []byte, done func(error)) { done(h(subject, data)) })
}

// ConsumeMsg is Consume for a handler that acknowledges on its own schedule.
func (b *Bus) ConsumeMsg(ctx context.Context, stream, durable, filterSubject string, h MsgHandler) (func(), error) {
	cons, err := b.js.CreateOrUpdateConsumer(ctx, stream, jetstream.ConsumerConfig{
		Durable:       durable,
		FilterSubject: filterSubject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		// Start from new messages when the consumer is first created (avoid replaying an
		// old backlog); a durable still resumes from the last ack on restart.
		DeliverPolicy: jetstream.DeliverNewPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("bus: consumer %s: %w", durable, err)
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		// Exactly one of Ack/Nak/Term must reach the server. sync.Once makes that true even if a
		// batching handler reports twice, which would otherwise ack a message belonging to the
		// NEXT delivery and drop it silently.
		var once sync.Once
		done := func(err error) {
			once.Do(func() {
				if err != nil {
					_ = msg.Nak()
					return
				}
				_ = msg.Ack()
			})
		}
		// A handler panic must never crash the process: the NATS callback runs in its own
		// goroutine, so an unrecovered panic here would take down the whole worker (no detection,
		// no heartbeat). Recover it, log loudly with a stack, and Term the offending message so a
		// poison message is not redelivered forever, the consumer stays alive and keeps working.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("bus: PANIC handling message on %q: %v\n%s", msg.Subject(), r, debug.Stack())
				once.Do(func() { _ = msg.Term() })
			}
		}()
		h(msg.Subject(), msg.Data(), done)
	})
	if err != nil {
		return nil, fmt.Errorf("bus: consume %s: %w", durable, err)
	}
	return cc.Stop, nil
}

// Connected reports whether the NATS connection is currently up (used by /readyz).
func (b *Bus) Connected() bool {
	return b != nil && b.nc != nil && b.nc.IsConnected()
}

// Close closes the connection gracefully (drains pending messages first).
func (b *Bus) Close() {
	if b.nc != nil {
		_ = b.nc.Drain()
	}
}
