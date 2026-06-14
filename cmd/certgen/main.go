// Command certgen creates an mTLS certificate bundle (CA + server + client) for
// DeusWatch. Used by installers/developers to auto-generate self-signed certs.
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
	out := flag.String("out", "deploy/certs", "certificate output directory")
	dns := flag.String("dns", "localhost,gateway,api", "server SAN DNS (comma-separated)")
	ips := flag.String("ip", "127.0.0.1,::1", "server SAN IPs (comma-separated)")
	days := flag.Int("days", 825, "leaf certificate validity (days)")
	force := flag.Bool("force", false, "regenerate even if certificates already exist")
	flag.Parse()

	// Idempotent: skip if the CA already exists (used by the compose init container).
	if !*force {
		if _, err := os.Stat(mtls.Paths(*out).CACert); err == nil {
			log.Printf("certgen: certificates already exist in %q — skipped (use -force to regenerate)", *out)
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

	log.Printf("mTLS certificate bundle created in %q:", *out)
	log.Printf("  CA     : %s (+ ca.key)", paths.CACert)
	log.Printf("  Server : %s (+ server.key)", paths.ServerCert)
	log.Printf("  Client : %s (+ client.key)", paths.ClientCert)
	log.Printf("Leaf validity: %d days. DO NOT commit these files (already gitignored).", *days)
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
			log.Fatalf("certgen: invalid IP: %q", s)
		}
	}
	return out
}
