package sigma

import (
	"strings"

	"deuswatch/internal/ingest"
)

// fieldAliases maps common field names (community-rule / product style) to DCS/ECS
// keys. This is the heart of the "processing pipeline": aligning the rule's field
// taxonomy to DeusWatch's. Add an entry here when adopting a new rule.
var fieldAliases = map[string]string{
	"user":          "user.name",
	"username":      "user.name",
	"src_ip":        "source.ip",
	"sourceip":      "source.ip",
	"srcip":         "source.ip",
	"src_port":      "source.port",
	"dst_ip":        "destination.ip",
	"destinationip": "destination.ip",
	"commandline":   "process.command_line",
	"cmdline":       "process.command_line",
	"image":         "process.name",
	"computer":      "host.name",
	"hostname":      "host.name",
	"uri":           "http.uri",
	"url":           "http.uri",
	"request_uri":   "http.uri",
	"c-uri":         "http.uri",
	"cs-method":     "http.method",
	"sc-status":     "http.status_code",
}

// resolveField returns the DCS key for a rule field name. Alias matching is
// case-insensitive; names that are already ECS / unknown are returned as-is.
func resolveField(name string) string {
	if v, ok := fieldAliases[strings.ToLower(name)]; ok {
		return v
	}
	return name
}

// FlattenEvent flattens a DCS Event into a dotted-ECS-keyed map, the form Sigma rules
// evaluate against. This is the FIELD-MAPPING layer that is the real cost of using
// community Sigma rules (see ADR): rules must be written/aligned to this field
// taxonomy. Only non-empty fields are included.
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
	// FIM file-hash reputation verdict (set by the enrich worker), so rules can match it.
	put("deuswatch.file_hash.verdict", e.DeusWatch.FileHash.Verdict)
	if e.Network != nil {
		put("network.protocol", e.Network.Protocol)
		put("network.transport", e.Network.Transport)
	}
	// HTTP / WAF request context, so rules can match the blocked URI, method, host or status
	// (e.g. a ModSecurity block on /solr/admin).
	if e.HTTP != nil {
		put("http.method", e.HTTP.Method)
		put("http.uri", e.HTTP.URI)
		put("http.host", e.HTTP.Host)
		if e.HTTP.StatusCode != 0 {
			m["http.status_code"] = e.HTTP.StatusCode
		}
	}
	// The rule identity carried BY the event (e.g. the OWASP CRS rule id a WAF blocked on),
	// so rules can key off the upstream detector's verdict.
	if e.Rule != nil {
		put("rule.id", e.Rule.ID)
		put("rule.name", e.Rule.Name)
	}
	return m
}
