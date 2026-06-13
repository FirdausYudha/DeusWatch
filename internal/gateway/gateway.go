// Package gateway adalah ingest gateway DeusWatch: menerima log mentah dari agent
// (lewat mTLS), memvalidasi, menormalkan ke DCS, lalu menerbitkannya ke NATS.
package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"deuswatch/internal/bus"
	"deuswatch/internal/ingest"
)

const maxBodyBytes = 8 << 20 // 8 MiB per batch

// Publisher menerbitkan payload ke subject (dipenuhi *bus.Bus).
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// LogsHandler menerima batch RawLog (JSON array) dari agent, menormalkan tiap
// entri ke DCS, dan menerbitkannya ke logs.normalized. Identitas agent diambil
// dari Common Name sertifikat client (lebih tepercaya daripada nilai kiriman).
func LogsHandler(pub Publisher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, "gagal baca body", http.StatusBadRequest)
			return
		}
		var raws []ingest.RawLog
		if err := json.Unmarshal(body, &raws); err != nil {
			http.Error(w, "JSON tidak valid (harap array RawLog)", http.StatusBadRequest)
			return
		}

		// Identitas dari sertifikat mTLS (mengikat log ke agent yang terautentikasi).
		var certCN string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}

		ctx := r.Context()
		accepted := 0
		for _, raw := range raws {
			if raw.Message == "" {
				continue // validasi: pesan wajib
			}
			if certCN != "" {
				raw.AgentID = certCN
			}
			ev, _ := ingest.Normalize(raw)
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			if err := pub.Publish(ctx, bus.SubjectLogsNormalized, data); err != nil {
				http.Error(w, "publish gagal", http.StatusServiceUnavailable)
				return
			}
			accepted++
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": accepted})
	}
}
