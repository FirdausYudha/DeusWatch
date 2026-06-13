package sigma

import "deuswatch/internal/ingest"

// FlattenEvent meratakan Event DCS menjadi map ber-key ECS dotted, bentuk yang
// dievaluasi rule Sigma. Inilah lapisan PEMETAAN FIELD yang menjadi biaya nyata
// memakai rule Sigma komunitas (lihat ADR): rule harus ditulis/diselaraskan ke
// taksonomi field ini. Hanya field non-kosong yang dimasukkan.
func FlattenEvent(e *ingest.Event) map[string]any {
	m := map[string]any{}
	put := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}

	m["event.severity"] = int(e.Event.Severity)
	put("event.category", e.Event.Category)
	put("event.action", e.Event.Action)
	put("event.outcome", e.Event.Outcome)
	put("event.dataset", e.Event.Dataset)
	put("event.original", e.Event.Original)

	if e.Source != nil {
		put("source.ip", e.Source.IP)
		if e.Source.Port != 0 {
			m["source.port"] = int(e.Source.Port)
		}
	}
	if e.Destination != nil {
		put("destination.ip", e.Destination.IP)
		if e.Destination.Port != 0 {
			m["destination.port"] = int(e.Destination.Port)
		}
	}
	if e.Host != nil {
		put("host.name", e.Host.Name)
		put("host.os.type", e.Host.OSType)
	}
	if e.User != nil {
		put("user.name", e.User.Name)
		put("user.domain", e.User.Domain)
	}
	if e.Process != nil {
		put("process.name", e.Process.Name)
		put("process.command_line", e.Process.CommandLine)
		if e.Process.PID != 0 {
			m["process.pid"] = e.Process.PID
		}
	}
	if e.File != nil {
		put("file.path", e.File.Path)
		put("file.hash.sha256", e.File.HashSHA256)
	}
	if e.Network != nil {
		put("network.protocol", e.Network.Protocol)
		put("network.transport", e.Network.Transport)
	}
	return m
}
