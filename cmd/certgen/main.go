// Command certgen membuat bundel sertifikat mTLS (CA + server + client) untuk
// DeusWatch. Dipakai installer/pengembang untuk meng-generate sertifikat
// self-signed secara otomatis.
//
//	go run ./cmd/certgen --out deploy/certs
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"deuswatch/internal/mtls"
)

func main() {
	out := flag.String("out", "deploy/certs", "direktori output sertifikat")
	dns := flag.String("dns", "localhost,gateway,api", "SAN DNS server (pisah koma)")
	ips := flag.String("ip", "127.0.0.1,::1", "SAN IP server (pisah koma)")
	days := flag.Int("days", 825, "masa berlaku sertifikat daun (hari)")
	force := flag.Bool("force", false, "regenerate walau sertifikat sudah ada")
	flag.Parse()

	// Idempotent: lewati bila CA sudah ada (dipakai init container compose).
	if !*force {
		if _, err := os.Stat(mtls.Paths(*out).CACert); err == nil {
			log.Printf("certgen: sertifikat sudah ada di %q — dilewati (pakai -force untuk regenerate)", *out)
			return
		}
	}

	paths, err := mtls.GenerateBundle(mtls.Options{
		Dir:       *out,
		ServerDNS: splitNonEmpty(*dns),
		ServerIPs: parseIPs(*ips),
		ValidFor:  time.Duration(*days) * 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("certgen: %v", err)
	}

	log.Printf("Bundel sertifikat mTLS dibuat di %q:", *out)
	log.Printf("  CA     : %s (+ ca.key)", paths.CACert)
	log.Printf("  Server : %s (+ server.key)", paths.ServerCert)
	log.Printf("  Client : %s (+ client.key)", paths.ClientCert)
	log.Printf("Masa berlaku daun: %d hari. JANGAN commit berkas ini (sudah di-gitignore).", *days)
}

func splitNonEmpty(csv string) []string {
	var out []string
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseIPs(csv string) []net.IP {
	var out []net.IP
	for _, s := range splitNonEmpty(csv) {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		} else {
			log.Fatalf("certgen: IP tidak valid: %q", s)
		}
	}
	return out
}
