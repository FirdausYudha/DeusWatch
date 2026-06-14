// Package bus wraps NATS JetStream as the DeusWatch message bus.
//
// Pipeline flow (design doc section 2): logs.raw -> logs.normalized ->
// logs.enriched -> alerts. JetStream is only a persistent streaming buffer;
// the source of truth remains PostgreSQL (no cache, no cache collisions).
package bus

import (
	"context"
	"fmt"
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

// Consume creates a durable consumer on the stream for filterSubject, then calls the
// handler for each message. Returns a stop function to halt consumption.
func (b *Bus) Consume(ctx context.Context, stream, durable, filterSubject string, h Handler) (func(), error) {
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
		if err := h(msg.Subject(), msg.Data()); err != nil {
			_ = msg.Nak()
			return
		}
		_ = msg.Ack()
	})
	if err != nil {
		return nil, fmt.Errorf("bus: consume %s: %w", durable, err)
	}
	return cc.Stop, nil
}

// Close closes the connection gracefully (drains pending messages first).
func (b *Bus) Close() {
	if b.nc != nil {
		_ = b.nc.Drain()
	}
}
