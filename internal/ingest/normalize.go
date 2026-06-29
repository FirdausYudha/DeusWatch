package ingest

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RawLog is the envelope of a raw log line the agent sends to the gateway, before
// normalization.
type RawLog struct {
	Timestamp time.Time `json:"timestamp"`
	Host      string    `json:"host"`
	AgentID   string    `json:"agent_id"`
	Dataset   string    `json:"dataset"` // log source: sshd, nginx, ...
	Message   string    `json:"message"` // raw log line
}

var (
	// Matched ANYWHERE in the line so the leading syslog prefix (timestamp, host,
	// "sshd[pid]:") doesn't prevent a match. Examples (after the prefix):
	//   "Failed password for root from 1.2.3.4 port 54321 ssh2"
	//   "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
	reSSHFailed = regexp.MustCompile(`Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	// "Accepted password for deploy from 10.0.0.5 port 22 ssh2"
	reSSHAccepted = regexp.MustCompile(`Accepted \w+ for (\S+) from (\S+) port (\d+)`)

	// Netfilter/UFW kernel log fields, e.g.:
	//   "[UFW BLOCK] IN=eth0 OUT= MAC=.. SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=40000 DPT=23 .."
	reFwSRC   = regexp.MustCompile(`\bSRC=(\S+)`)
	reFwDPT   = regexp.MustCompile(`\bDPT=(\d+)`)
	reFwProto = regexp.MustCompile(`\bPROTO=(\S+)`)
)

// Normalize turns a RawLog into a DCS Event. Returns (event, true) when the line is
// recognized and mapped. For unknown formats it still produces a minimal event
// (dataset + original) so the log is not lost, with the flag set to false.
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
		osType := "linux"
		if strings.HasPrefix(raw.Dataset, "windows") {
			osType = "windows"
		}
		e.Host = &Host{Name: raw.Host, OSType: osType}
	}
	if raw.AgentID != "" {
		e.Agent = &Agent{ID: raw.AgentID}
	}

	if raw.Dataset == "sshd" && normalizeSSHD(raw.Message, e) {
		return e, true
	}
	if raw.Dataset == "fim" && normalizeFIM(raw.Message, e) {
		return e, true
	}
	if strings.HasPrefix(raw.Dataset, "windows") {
		return e, normalizeWindows(raw.Message, e)
	}
	if raw.Dataset == "firewall" && normalizeFirewall(raw.Message, e) {
		return e, true
	}
	return e, false
}

// normalizeFirewall parses a Netfilter/UFW/iptables kernel log line into DCS network.*
// fields (source IP, destination port, transport). A single blocked packet is just noise
// (severity info); the Port Scan aggregation rule turns many blocks from one IP into an alert.
func normalizeFirewall(msg string, e *Event) bool {
	m := reFwSRC.FindStringSubmatch(msg)
	if m == nil {
		return false // not a recognizable firewall line
	}
	e.Event.Category = "network"
	e.Source = &Endpoint{IP: m[1]}
	if dm := reFwDPT.FindStringSubmatch(msg); dm != nil {
		if p, err := strconv.Atoi(dm[1]); err == nil && p > 0 && p <= 65535 {
			e.Destination = &Endpoint{Port: uint16(p)}
		}
	}
	if pm := reFwProto.FindStringSubmatch(msg); pm != nil {
		e.Network = &Network{Transport: strings.ToLower(pm[1])}
	}
	low := strings.ToLower(msg)
	if strings.Contains(low, "block") || strings.Contains(low, "drop") ||
		strings.Contains(low, "deny") || strings.Contains(low, "reject") {
		e.Event.Action = "firewall_block"
		e.Event.Outcome = "blocked"
	} else {
		e.Event.Action = "firewall_allow"
		e.Event.Outcome = "allowed"
	}
	e.Event.Severity = SeverityInfo
	return true
}

// winEvent is the structured payload the Windows agent sends per event log entry: the
// numeric EventID plus the key EventData fields, so normalization keys off the
// locale-independent ID rather than the (localized) rendered message text.
type winEvent struct {
	ID        int    `json:"id"`
	IP        string `json:"ip"`
	User      string `json:"user"`
	LogonType string `json:"logon_type"`
	Text      string `json:"text"`
}

// normalizeWindows maps a Windows Event Log entry (Security/System) to DCS fields. It
// recognizes the common logon events (4625 failed, 4624 success, 4740 lockout) by EventID
// so it works regardless of the OS display language. Returns true when the event is mapped
// to a known type; otherwise the cleaned message is still kept (returns false).
func normalizeWindows(msg string, e *Event) bool {
	var w winEvent
	if err := json.Unmarshal([]byte(msg), &w); err != nil || w.ID == 0 {
		return false
	}
	if w.Text != "" {
		e.Event.Original = w.Text // human-readable message instead of the JSON envelope
	}
	if w.User != "" && w.User != "-" {
		e.User = &User{Name: w.User}
	}
	if ip := w.IP; ip != "" && ip != "-" && ip != "::1" && ip != "127.0.0.1" {
		e.Source = &Endpoint{IP: ip}
	}

	switch w.ID {
	case 4625: // An account failed to log on (covers RDP type 10, network/SMB type 3, etc.)
		e.Event.Category = "authentication"
		e.Event.Action = "windows_logon"
		e.Event.Outcome = "failure"
		e.Event.Severity = SeverityLow // one failure = low; the brute-force aggregation is high
		return true
	case 4624: // An account was successfully logged on
		e.Event.Category = "authentication"
		e.Event.Action = "windows_logon"
		e.Event.Outcome = "success"
		e.Event.Severity = SeverityInfo
		return true
	case 4740: // A user account was locked out (a strong brute-force indicator)
		e.Event.Category = "iam"
		e.Event.Action = "account_locked"
		e.Event.Outcome = "failure"
		e.Event.Severity = SeverityMedium
		return true
	default:
		return false // unmapped Windows event: stored as a raw info log
	}
}

// normalizeFIM parses the agent's FIM JSON payload ({path,action,sha256,size,mode})
// into DCS file.* fields. action: created/modified/deleted.
func normalizeFIM(msg string, e *Event) bool {
	var c struct {
		Path   string `json:"path"`
		Action string `json:"action"`
		SHA256 string `json:"sha256"`
		Mode   string `json:"mode"`
	}
	if err := json.Unmarshal([]byte(msg), &c); err != nil || c.Path == "" || c.Action == "" {
		return false
	}
	e.Event.Category = "file"
	e.Event.Action = "file_" + c.Action
	e.Event.Outcome = "success"
	e.File = &File{Path: c.Path, HashSHA256: c.SHA256, Mode: c.Mode}
	// Changes/deletions are riskier than newly created files.
	if c.Action == "created" {
		e.Event.Severity = SeverityLow
	} else {
		e.Event.Severity = SeverityMedium
	}
	return true
}

func normalizeSSHD(msg string, e *Event) bool {
	if m := reSSHFailed.FindStringSubmatch(msg); m != nil {
		e.Event.Category = "authentication"
		e.Event.Action = "ssh_login"
		e.Event.Outcome = "failure"
		e.Event.Severity = SeverityLow // one failure = low; the brute-force alert is High
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
