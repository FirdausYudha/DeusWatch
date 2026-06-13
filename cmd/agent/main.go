// Command agent adalah kolektor log endpoint DeusWatch (Fase 1: Linux).
// Men-tail berkas log dan mengirim baris mentah ke gateway lewat mTLS.
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
	logFile := getenv("LOG_FILE", "/var/log/auth.log")
	dataset := getenv("DATASET", "sshd")
	host := getenv("HOST_NAME", hostname())
	fromStart := os.Getenv("FROM_START") == "1"

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	shipper, err := agent.NewShipper(gatewayURL, mtls.Paths(certDir))
	if err != nil {
		log.Fatalf("agent: shipper (sertifikat di %q?): %v", certDir, err)
	}

	lines := make(chan string, 256)
	go func() {
		if err := agent.FollowFile(ctx, logFile, fromStart, lines); err != nil {
			log.Printf("agent: tail %q berhenti: %v", logFile, err)
		}
		close(lines)
	}()

	log.Printf("DeusWatch agent: tail %q (dataset=%s, host=%s) -> %s", logFile, dataset, host, gatewayURL)

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
				Timestamp: time.Now(), Host: host, Dataset: dataset, Message: line,
			})
			if len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
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
