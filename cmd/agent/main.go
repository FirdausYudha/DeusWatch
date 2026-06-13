// Command agent adalah kolektor log endpoint DeusWatch (Linux & Windows).
//
// Source default dipilih per-OS saat kompilasi (Linux: berkas auth/syslog;
// Windows: Event Log) — lihat internal/agent. Override sumber tunggal lewat
// LOG_FILE. Semua baris dikirim ke manager (gateway) lewat mTLS.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"deuswatch/internal/agent"
	"deuswatch/internal/ingest"
	"deuswatch/internal/mtls"
)

func main() {
	enrollMode := flag.Bool("enroll", false, "tukar token enrollment jadi sertifikat lalu keluar")
	enrollToken := flag.String("token", "", "token enrollment (mode -enroll)")
	enrollName := flag.String("name", "", "nama agent (mode -enroll)")
	enrollManager := flag.String("manager", "http://localhost:8080", "URL manager untuk enroll")
	outDir := flag.String("out", "", "direktori output sertifikat (default CERT_DIR)")
	flag.Parse()

	if *enrollMode {
		dir := *outDir
		if dir == "" {
			dir = getenv("CERT_DIR", "deploy/certs")
		}
		if err := doEnroll(*enrollManager, *enrollToken, *enrollName, dir); err != nil {
			log.Fatalf("agent: enroll gagal: %v", err)
		}
		return
	}

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

	buf, err := agent.NewBuffer(getenv("BUFFER_DIR", "agent-buffer"), 1000)
	if err != nil {
		log.Fatalf("agent: buffer: %v", err)
	}

	// Sumber: config push dari manager bila ada, selain itu default per-OS / LOG_FILE.
	sources := resolveSources()
	var configVersion int
	if cfg, err := shipper.FetchConfig(ctx); err != nil {
		log.Printf("agent: gagal ambil config push (pakai default): %v", err)
	} else if cfg != nil && len(cfg.Sources) > 0 {
		sources, configVersion = cfg.Sources, cfg.Version
		log.Printf("agent: config push v%d diterapkan dari manager", cfg.Version)
	}
	if len(sources) == 0 {
		log.Fatalf("agent: tidak ada source log — set LOG_FILE atau jalankan di OS yang didukung")
	}

	// Pantau perubahan config; versi baru -> shutdown agar service-manager restart & terapkan.
	go watchConfig(ctx, shipper, configVersion, stopSignals)
	// Kirim ulang batch yang ter-buffer (store-and-forward) + heartbeat.
	go drainBuffer(ctx, shipper, buf)
	go heartbeatLoop(ctx, shipper)

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
		if body, err := json.Marshal(batch); err == nil {
			if serr := shipper.SendRaw(ctx, body); serr != nil {
				if berr := buf.Save(body); berr == nil {
					log.Printf("agent: manager offline — %d baris di-buffer (%v)", len(batch), serr)
				} else {
					log.Printf("agent: gagal kirim & buffer: %v / %v", serr, berr)
				}
			} else {
				log.Printf("agent: terkirim %d baris", len(batch))
			}
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

// watchConfig mem-poll config push; bila versi naik, memicu shutdown agar
// service-manager me-restart agent dengan config baru (apply atomik sederhana).
func watchConfig(ctx context.Context, shipper *agent.Shipper, current int, stop func()) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cfg, err := shipper.FetchConfig(ctx)
			if err != nil || cfg == nil {
				continue
			}
			if cfg.Version > current {
				log.Printf("agent: config baru v%d terdeteksi — restart untuk menerapkan", cfg.Version)
				stop()
				return
			}
		}
	}
}

// drainBuffer mengirim ulang batch yang ter-buffer di disk saat manager kembali online.
func drainBuffer(ctx context.Context, shipper *agent.Shipper, buf *agent.Buffer) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			files, err := buf.Pending()
			if err != nil {
				continue
			}
			for _, f := range files {
				body, rerr := os.ReadFile(f)
				if rerr != nil {
					_ = buf.Remove(f)
					continue
				}
				if serr := shipper.SendRaw(ctx, body); serr != nil {
					break // manager masih offline; coba lagi nanti
				}
				_ = buf.Remove(f)
				log.Printf("agent: buffer terkirim ulang (%s)", filepath.Base(f))
			}
		}
	}
}

// heartbeatLoop mengirim heartbeat berkala ke manager.
func heartbeatLoop(ctx context.Context, shipper *agent.Shipper) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := shipper.Heartbeat(ctx); err != nil {
				log.Printf("agent: heartbeat gagal: %v", err)
			}
		}
	}
}

// doEnroll menukar token enrollment menjadi sertifikat client unik dan
// menyimpannya (ca.crt, client.crt, client.key) ke dir.
func doEnroll(manager, token, name, dir string) error {
	if token == "" || name == "" {
		return fmt.Errorf("-token dan -name wajib")
	}
	body, _ := json.Marshal(map[string]string{"token": token, "name": name, "os": runtime.GOOS})
	resp, err := http.Post(strings.TrimRight(manager, "/")+"/api/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("manager menolak (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var bundle struct {
		AgentID    string `json:"agent_id"`
		CACert     string `json:"ca_cert"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	p := mtls.Paths(dir)
	if err := os.WriteFile(p.CACert, []byte(bundle.CACert), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p.ClientCert, []byte(bundle.ClientCert), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p.ClientKey, []byte(bundle.ClientKey), 0o600); err != nil {
		return err
	}
	log.Printf("agent: enrolled sebagai %q (id=%s); sertifikat tersimpan di %s", name, bundle.AgentID, dir)
	return nil
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
