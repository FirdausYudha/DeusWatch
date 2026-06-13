// Command agent adalah kolektor log endpoint DeusWatch (Linux & Windows).
//
// Source default dipilih per-OS saat kompilasi (Linux: berkas auth/syslog;
// Windows: Event Log) — lihat internal/agent. Override sumber tunggal lewat
// LOG_FILE. Semua baris dikirim ke manager (gateway) lewat mTLS.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"deuswatch/internal/agent"
	"deuswatch/internal/ingest"
	"deuswatch/internal/mtls"
)

func main() {
	gatewayURL := getenv("GATEWAY_URL", "https://localhost:8443")
	certDir := getenv("CERT_DIR", "deploy/certs")
	host := getenv("HOST_NAME", hostname())
	fromStart := os.Getenv("FROM_START") == "1"

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	shipper, err := agent.NewShipper(gatewayURL, mtls.Paths(certDir))
	if err != nil {
		log.Fatalf("agent: shipper (sertifikat di %q?): %v", certDir, err)
	}

	sources := resolveSources()
	if len(sources) == 0 {
		log.Fatalf("agent: tidak ada source log — set LOG_FILE atau jalankan di OS yang didukung")
	}

	lines := make(chan agent.Line, 256)
	go func() {
		agent.Collect(ctx, sources, fromStart, lines)
		close(lines)
	}()

	log.Printf("DeusWatch agent: host=%s, %d source -> %s", host, len(sources), gatewayURL)
	for _, s := range sources {
		log.Printf("  source: dataset=%s type=%s path=%s", s.Dataset, s.Type, s.Path)
	}

	batch := make([]ingest.RawLog, 0, 64)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := shipper.Send(ctx, batch); err != nil {
			log.Printf("agent: gagal kirim %d baris: %v", len(batch), err)
		} else {
			log.Printf("agent: terkirim %d baris", len(batch))
		}
		batch = batch[:0]
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case line, ok := <-lines:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ingest.RawLog{
				Timestamp: time.Now(), Host: host, Dataset: line.Dataset, Message: line.Message,
			})
			if len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// resolveSources: LOG_FILE (sumber tunggal) bila diset, selain itu default per-OS.
func resolveSources() []agent.Source {
	if lf := os.Getenv("LOG_FILE"); lf != "" {
		return []agent.Source{{Dataset: getenv("DATASET", "file"), Type: "file", Path: lf}}
	}
	return agent.DefaultSources()
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}
