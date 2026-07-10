package decoders

import (
	"encoding/json"
	"net/http"
	"strconv"

	"deuswatch/internal/ingest"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// CollectionHandler: GET (list) / POST (create) on /api/decoders.
// MUST be wrapped with RequirePermission(PermManageRules).
func (s *Store) CollectionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list, err := s.List(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, list)

		case http.MethodPost:
			var sp ingest.DecoderSpec
			if err := json.NewDecoder(r.Body).Decode(&sp); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			d, err := s.Create(r.Context(), sp)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusCreated, d)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// SamplesHandler: GET /api/decoders/samples?dataset=X - recent raw log lines for a dataset, so
// the operator can SEE what their logs look like before writing a decoder.
func (s *Store) SamplesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dataset := r.URL.Query().Get("dataset")
		if dataset == "" {
			http.Error(w, "dataset is required", http.StatusBadRequest)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		lines, err := s.RecentRawByDataset(r.Context(), dataset, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dataset": dataset, "lines": lines})
	}
}

// TestHandler: POST /api/decoders/test {spec, line} - applies a decoder to one line and returns
// the extracted fields, so the operator can iterate on the regex without saving.
func (s *Store) TestHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ingest.DecoderSpec
			Line string `json:"line"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		matched, ev, err := ingest.TestDecoder(req.DecoderSpec, req.Line)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fields := map[string]string{}
		put := func(k, v string) {
			if v != "" {
				fields[k] = v
			}
		}
		put("event.category", ev.Event.Category)
		put("event.action", ev.Event.Action)
		put("event.outcome", ev.Event.Outcome)
		if ev.Source != nil {
			put("source.ip", ev.Source.IP)
			if ev.Source.Port != 0 {
				put("source.port", strconv.Itoa(int(ev.Source.Port)))
			}
		}
		if ev.Destination != nil {
			put("destination.ip", ev.Destination.IP)
			if ev.Destination.Port != 0 {
				put("destination.port", strconv.Itoa(int(ev.Destination.Port)))
			}
		}
		if ev.User != nil {
			put("user.name", ev.User.Name)
		}
		if ev.Host != nil {
			put("host.name", ev.Host.Name)
		}
		if ev.Process != nil {
			put("process.name", ev.Process.Name)
			put("process.command_line", ev.Process.CommandLine)
		}
		if ev.File != nil {
			put("file.path", ev.File.Path)
		}
		writeJSON(w, http.StatusOK, map[string]any{"matched": matched, "fields": fields})
	}
}

// ItemHandler: PUT (update) / DELETE on /api/decoders/{id}.
func (s *Store) ItemHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req struct {
				ingest.DecoderSpec
				Enabled bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			d, err := s.Update(r.Context(), id, req.DecoderSpec, req.Enabled)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, d)

		case http.MethodDelete:
			if err := s.Delete(r.Context(), id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
