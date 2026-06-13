package ingest

import (
	"regexp"
	"strconv"
	"time"
)

// RawLog adalah amplop log mentah yang dikirim agent ke gateway, sebelum dinormalkan.
type RawLog struct {
	Timestamp time.Time `json:"timestamp"`
	Host      string    `json:"host"`
	AgentID   string    `json:"agent_id"`
	Dataset   string    `json:"dataset"` // sumber log: sshd, nginx, ...
	Message   string    `json:"message"` // baris log mentah
}

var (
	// "Failed password for root from 1.2.3.4 port 54321 ssh2"
	// "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
	reSSHFailed = regexp.MustCompile(`^Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	// "Accepted password for deploy from 10.0.0.5 port 22 ssh2"
	reSSHAccepted = regexp.MustCompile(`^Accepted \w+ for (\S+) from (\S+) port (\d+)`)
)

// Normalize mengubah RawLog menjadi Event DCS. Mengembalikan (event, true) bila
// baris dikenali & terpetakan. Untuk format tak dikenal tetap menghasilkan event
// minimal (dataset + original) agar log tidak hilang, dengan flag false.
func Normalize(raw RawLog) (*Event, bool) {
	ts := raw.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	e := &Event{
		Timestamp: ts,
		Event:     EventFields{Dataset: raw.Dataset, Original: raw.Message, Severity: SeverityInfo},
	}
	if raw.Host != "" {
		e.Host = &Host{Name: raw.Host, OSType: "linux"}
	}
	if raw.AgentID != "" {
		e.Agent = &Agent{ID: raw.AgentID}
	}

	if raw.Dataset == "sshd" && normalizeSSHD(raw.Message, e) {
		return e, true
	}
	return e, false
}

func normalizeSSHD(msg string, e *Event) bool {
	if m := reSSHFailed.FindStringSubmatch(msg); m != nil {
		e.Event.Category = "authentication"
		e.Event.Action = "ssh_login"
		e.Event.Outcome = "failure"
		e.Event.Severity = SeverityLow // satu kegagalan = rendah; alert brute-force yang High
		e.User = &User{Name: m[1]}
		e.Source = endpoint(m[2], m[3])
		return true
	}
	if m := reSSHAccepted.FindStringSubmatch(msg); m != nil {
		e.Event.Category = "authentication"
		e.Event.Action = "ssh_login"
		e.Event.Outcome = "success"
		e.Event.Severity = SeverityInfo
		e.User = &User{Name: m[1]}
		e.Source = endpoint(m[2], m[3])
		return true
	}
	return false
}

func endpoint(ip, port string) *Endpoint {
	ep := &Endpoint{IP: ip}
	if p, err := strconv.Atoi(port); err == nil && p > 0 && p <= 65535 {
		ep.Port = uint16(p)
	}
	return ep
}
