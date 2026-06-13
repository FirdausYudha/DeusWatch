// Package bus membungkus NATS JetStream sebagai message bus DeusWatch.
//
// Alur pipeline (design doc bagian 2): logs.raw -> logs.normalized ->
// logs.enriched -> alerts. JetStream hanya buffer streaming yang persisten;
// sumber kebenaran tetap PostgreSQL (tidak ada cache, tidak ada tabrakan cache).
package bus

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Subject pipeline.
const (
	SubjectLogsRaw        = "logs.raw"
	SubjectLogsNormalized = "logs.normalized"
	SubjectLogsEnriched   = "logs.enriched"
	SubjectAlerts         = "alerts"
)

// Nama stream.
const (
	StreamLogs   = "LOGS"
	StreamAlerts = "ALERTS"
)

// Bus membungkus koneksi NATS + handle JetStream.
type Bus struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// Connect membuka koneksi ke NATS lalu memastikan stream DeusWatch ada.
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
			Description: "Pipeline log DeusWatch (raw -> normalized -> enriched)",
			Subjects:    []string{"logs.>"},
			Storage:     jetstream.FileStorage,
			Retention:   jetstream.LimitsPolicy,
			MaxAge:      24 * time.Hour, // buffer; sumber kebenaran ada di Postgres
		},
		{
			Name:        StreamAlerts,
			Description: "Alert DeusWatch",
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

// Publish menerbitkan payload ke subject dan menunggu ack JetStream (sinkron).
func (b *Bus) Publish(ctx context.Context, subject string, data []byte) error {
	if _, err := b.js.Publish(ctx, subject, data); err != nil {
		return fmt.Errorf("bus: publish %s: %w", subject, err)
	}
	return nil
}

// Handler memproses satu pesan. Mengembalikan error akan men-Nak pesan (redeliver).
type Handler func(subject string, data []byte) error

// Consume membuat consumer durable pada stream untuk filterSubject, lalu memanggil
// handler tiap pesan. Mengembalikan fungsi stop untuk menghentikan konsumsi.
func (b *Bus) Consume(ctx context.Context, stream, durable, filterSubject string, h Handler) (func(), error) {
	cons, err := b.js.CreateOrUpdateConsumer(ctx, stream, jetstream.ConsumerConfig{
		Durable:       durable,
		FilterSubject: filterSubject,
		AckPolicy:     jetstream.AckExplicitPolicy,
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

// Close menutup koneksi dengan rapi (drain pesan tertunda lebih dulu).
func (b *Bus) Close() {
	if b.nc != nil {
		_ = b.nc.Drain()
	}
}
