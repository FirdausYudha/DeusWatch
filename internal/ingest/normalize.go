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

	// Client IP at the start of a web access log line (Combined/Common Log Format):
	//   1.2.3.4 - - [10/Oct/2026:...] "GET /slot HTTP/1.1" 200 1234 "-" "curl/8"
	reWebIP = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

	// ModSecurity / OWASP CRS Apache error fields, e.g.:
	//   [client 165.22.76.50:22637] ModSecurity: Access denied with code 403 (phase 1).
	//   … [id "920280"] [msg "Request Missing a Host Header"] [severity "CRITICAL"]
	//   [uri "/solr/admin"] [hostname "target.example"] [unique_id "alkK…"]
	reMSClient   = regexp.MustCompile(`\[client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?\]`)
	reMSCode     = regexp.MustCompile(`Access denied with code (\d{3})`)
	reMSID       = regexp.MustCompile(`\[id "([^"]*)"\]`)
	reMSMsg      = regexp.MustCompile(`\[msg "([^"]*)"\]`)
	reMSSeverity = regexp.MustCompile(`\[severity "([^"]*)"\]`)
	reMSURI      = regexp.MustCompile(`\[uri "([^"]*)"\]`)
	reMSHostname = regexp.MustCompile(`\[hostname "([^"]*)"\]`)
)

// datasetKind reduces a source's (possibly descriptive) dataset label to the base keyword the
// normalizer dispatches on. Operators name sources freely in the UI - "fim (download)",
// "firewall (ufw)", "nginx prod" - so matching the raw label exactly would silently drop them
// to raw/unknown events. We take the first token (lowercased, before any space or "("), so the
// label is preserved for display while the kind still routes to the right parser.
func datasetKind(ds string) string {
	ds = strings.ToLower(strings.TrimSpace(ds))
	if i := strings.IndexAny(ds, " (\t"); i >= 0 {
		ds = ds[:i]
	}
	return ds
}

// Normalize turns a RawLog into a DCS Event. Returns (event, true) when the line is
// recognized and mapped. For unknown formats it still produces a minimal event
// (dataset + original) so the log is not lost, with the flag set to false.
func Normalize(raw RawLog) (*Event, bool) {
	ts := raw.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	kind := datasetKind(raw.Dataset)
	e := &Event{
		Timestamp: ts,
		Event:     EventFields{Dataset: raw.Dataset, Original: raw.Message, Severity: SeverityInfo},
	}
	if raw.Host != "" {
		osType := "linux"
		if strings.HasPrefix(kind, "windows") {
			osType = "windows"
		}
		e.Host = &Host{Name: raw.Host, OSType: osType}
	}
	if raw.AgentID != "" {
		e.Agent = &Agent{ID: raw.AgentID}
	}

	if kind == "sshd" && normalizeSSHD(raw.Message, e) {
		return e, true
	}
	if kind == "fim" && normalizeFIM(raw.Message, e) {
		return e, true
	}
	// A type=fim source may carry ANY dataset label ("web", "wordpress", ...) - operators
	// name sources freely and the source *type* is not part of RawLog. Sniff the agent's
	// FIM JSON payload ({path,action,...}) whatever the label, so FIM events are never
	// mis-routed to a text parser (e.g. dataset "web" would feed FIM JSON to the access-log
	// parser and surface as an unparsed raw line - no file.path, no diff, no Restore).
	if strings.HasPrefix(strings.TrimSpace(raw.Message), "{") && normalizeFIM(raw.Message, e) {
		return e, true
	}
	if strings.HasPrefix(kind, "windows") {
		return e, normalizeWindows(raw.Message, e)
	}
	if kind == "firewall" && normalizeFirewall(raw.Message, e) {
		return e, true
	}
	if kind == "modsecurity" || kind == "waf" || kind == "modsec" {
		return e, normalizeModSecurity(raw.Message, e)
	}
	// A WAF line can arrive under any dataset label (OPNsense syslog, "web", …). Sniff the
	// ModSecurity signature so it is parsed as a rich WAF event whatever the label - only the
	// [client …] variant (the actual blocked request), not the noise 'Producer:' lines.
	if strings.Contains(raw.Message, "ModSecurity:") && strings.Contains(raw.Message, "[id \"") &&
		strings.Contains(raw.Message, "[client ") && normalizeModSecurity(raw.Message, e) {
		return e, true
	}
	if kind == "web" || kind == "nginx" || kind == "apache" {
		return e, normalizeWeb(raw.Message, e)
	}
	if kind == "suricata" || kind == "eve" || kind == "snort" {
		return e, normalizeSuricata(raw.Message, e)
	}
	// No built-in matched: fall back to any operator-defined custom decoder for this dataset.
	if applyDecoders(kind, raw.Message, e) {
		return e, true
	}
	return e, false
}

// suricataEVE is the subset of a Suricata/Snort EVE JSON record DeusWatch maps (the "alert"
// event type). Other EVE event types (flow/http/dns/tls telemetry) are ignored.
type suricataEVE struct {
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	Alert     *struct {
		Action      string `json:"action"`
		SignatureID int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
		Metadata    struct {
			MitreTechniqueID []string `json:"mitre_technique_id"`
			MitreTacticName  []string `json:"mitre_tactic_name"`
		} `json:"metadata"`
	} `json:"alert"`
}

// normalizeSuricata maps a Suricata/Snort EVE JSON "alert" record into a DCS network-intrusion
// alert: the signature becomes the rule (id + name), src/dest IP+port and protocol are carried,
// the Suricata priority maps to a DCS severity, and MITRE tags (when the ruleset carries them,
// e.g. ET Pro) are mapped. It is PRE-LABELED (dw_label set) because an IDS already decided this
// is an alert - so it surfaces in the Alerts view and the worker drives response/notify on it
// directly, without a DeusWatch rule re-firing. event.category is "intrusion_detection" so the
// log-based Sigma rules (scoped by category) never re-evaluate it. Non-alert EVE lines return
// false; configure Suricata's eve-log to emit only 'alert' to keep volume sane.
func normalizeSuricata(msg string, e *Event) bool {
	var s suricataEVE
	if err := json.Unmarshal([]byte(msg), &s); err != nil || s.EventType != "alert" || s.Alert == nil {
		return false
	}
	e.Event.Category = "intrusion_detection"
	e.Event.Action = "network_ids_alert"
	e.Event.Severity = suricataSeverity(s.Alert.Severity)
	e.Event.Outcome = "detected"
	if a := strings.ToLower(s.Alert.Action); a == "blocked" || a == "dropped" {
		e.Event.Outcome = "blocked" // Suricata was inline (IPS) and already dropped it
	}
	if s.SrcIP != "" {
		e.Source = endpointNum(s.SrcIP, s.SrcPort)
	}
	if s.DestIP != "" {
		e.Destination = endpointNum(s.DestIP, s.DestPort)
	}
	if s.Proto != "" || s.AppProto != "" {
		e.Network = &Network{Transport: strings.ToLower(s.Proto), Protocol: strings.ToLower(s.AppProto)}
	}
	e.Rule = &Rule{ID: "suricata-" + strconv.Itoa(s.Alert.SignatureID), Name: s.Alert.Signature}
	if tech := firstNonEmpty(s.Alert.Metadata.MitreTechniqueID); tech != "" {
		e.Threat = &Threat{
			Technique:  Technique{ID: strings.ToUpper(tech)},
			TacticName: cleanTactic(firstNonEmpty(s.Alert.Metadata.MitreTacticName)),
		}
	}
	e.DeusWatch.Label = "network_intrusion" // pre-labeled: an IDS already caught this
	return true
}

// suricataSeverity maps a Suricata alert priority (1 highest .. 3 lowest) to a DCS severity.
func suricataSeverity(prio int) Severity {
	switch prio {
	case 1:
		return SeverityHigh
	case 2:
		return SeverityMedium
	case 3:
		return SeverityLow
	default:
		return SeverityMedium
	}
}

func endpointNum(ip string, port int) *Endpoint {
	ep := &Endpoint{IP: ip}
	if port > 0 && port <= 65535 {
		ep.Port = uint16(port)
	}
	return ep
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// cleanTactic turns an ET/MITRE tactic token ("command_and_control", "credential-access") into
// readable text ("command and control").
func cleanTactic(s string) string {
	return strings.NewReplacer("_", " ", "-", " ").Replace(strings.ToLower(strings.TrimSpace(s)))
}

// normalizeWeb maps a web-server access log line (nginx/apache Combined Log Format) to a DCS
// web event. It keeps the full line as event.original so the keyword-based web detection rules
// (web defacement, judi-online markers, path scanning) match against it, and extracts the
// client IP so a matched attacker can be banned by the response engine.
func normalizeWeb(msg string, e *Event) bool {
	e.Event.Category = "web"
	e.Event.Action = "http_request"
	e.Event.Severity = SeverityInfo // a single request is noise; the rules raise real hits
	if m := reWebIP.FindStringSubmatch(msg); m != nil {
		if ip := m[1]; ip != "127.0.0.1" && ip != "0.0.0.0" {
			e.Source = &Endpoint{IP: ip}
		}
	}
	return true // original carries the full line for keyword matching
}

// normalizeModSecurity parses a ModSecurity / OWASP CRS Apache error line into DCS: the client
// IP, the WAF rule id + message (into rule.*), the blocked URI / target host / status (into
// http.*), and a severity mapped from the CRS level. This turns a WAF block into a first-class
// event that scoring and the ban engine act on. Returns false if it isn't a recognizable WAF
// block (no client + id), so the caller can fall back.
//
// Dedup note: OPNsense/Apache emit the same block up to 3× (an httpd RFC5424 copy, an httpd
// syslog copy, and a modsecurity[…] "Apache-Error" copy) plus a noise "Producer:" line. Only
// the two httpd copies carry [client …]; the caller requires it, so the modsecurity[…] and
// Producer lines are ignored. To avoid the httpd RFC5424-vs-syslog duplicate, ingest ONE log
// file (docs/modsecurity.md) - stateless normalization can't dedup by unique_id across lines.
func normalizeModSecurity(msg string, e *Event) bool {
	client := reMSClient.FindStringSubmatch(msg)
	id := reMSID.FindStringSubmatch(msg)
	if client == nil || id == nil {
		return false
	}
	e.Event.Category = "web"
	e.Event.Action = "waf_block"
	e.Event.Outcome = "blocked"
	e.Event.Dataset = "modsecurity"

	src := &Endpoint{IP: client[1]}
	if len(client) > 2 && client[2] != "" {
		if p, err := strconv.Atoi(client[2]); err == nil && p > 0 && p <= 65535 {
			src.Port = uint16(p)
		}
	}
	e.Source = src

	// WAF rule identity -> rule.* (id + human message).
	rule := &Rule{ID: id[1]}
	if m := reMSMsg.FindStringSubmatch(msg); m != nil {
		rule.Name = m[1]
	}
	e.Rule = rule

	// HTTP context -> http.*.
	h := &HTTP{}
	if m := reMSURI.FindStringSubmatch(msg); m != nil {
		h.URI = m[1]
	}
	if m := reMSHostname.FindStringSubmatch(msg); m != nil {
		h.Host = m[1]
	}
	if m := reMSCode.FindStringSubmatch(msg); m != nil {
		if code, err := strconv.Atoi(m[1]); err == nil {
			h.StatusCode = code
		}
	}
	if h.URI != "" || h.Host != "" || h.StatusCode != 0 {
		e.HTTP = h
	}

	// Severity from the CRS level. CRS labels most protocol-enforcement hits CRITICAL even for
	// routine scanner noise, so we map conservatively (CRITICAL -> high, not critical) to avoid
	// alert fatigue; the composite score + repeated-block rule surface the IPs that matter.
	sev := SeverityLow
	if m := reMSSeverity.FindStringSubmatch(msg); m != nil {
		switch strings.ToUpper(m[1]) {
		case "EMERGENCY", "ALERT", "CRITICAL":
			sev = SeverityHigh
		case "ERROR":
			sev = SeverityMedium
		case "WARNING":
			sev = SeverityLow
		default:
			sev = SeverityInfo
		}
	}
	e.Event.Severity = sev
	return true
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
	case 4688: // A new process was created (command line is in the rendered text if auditing is on)
		e.Event.Category = "process"
		e.Event.Action = "windows_process_created"
		e.Event.Severity = SeverityInfo
		return true
	case 4104: // PowerShell scriptblock logging (Microsoft-Windows-PowerShell/Operational)
		e.Event.Category = "process"
		e.Event.Action = "powershell_scriptblock"
		e.Event.Severity = SeverityLow
		return true
	case 4720: // A user account was created
		e.Event.Category = "iam"
		e.Event.Action = "windows_account_created"
		e.Event.Severity = SeverityMedium
		return true
	case 4726: // A user account was deleted
		e.Event.Category = "iam"
		e.Event.Action = "windows_account_deleted"
		e.Event.Severity = SeverityMedium
		return true
	case 4728, 4732, 4756: // A member was added to a security-enabled (global/local/universal) group
		e.Event.Category = "iam"
		e.Event.Action = "windows_group_member_added"
		e.Event.Severity = SeverityMedium
		return true
	case 1102: // The Windows Security audit log was cleared (classic anti-forensics)
		e.Event.Category = "iam"
		e.Event.Action = "windows_audit_log_cleared"
		e.Event.Severity = SeverityHigh
		return true
	default:
		return false // unmapped Windows event: stored as a raw info log
	}
}

// normalizeFIM parses the agent's FIM JSON payload ({path,action,sha256,size,mode})
// into DCS file.* fields. action: created/modified/deleted.
func normalizeFIM(msg string, e *Event) bool {
	var c struct {
		Path       string `json:"path"`
		Action     string `json:"action"`
		SHA256     string `json:"sha256"`
		Mode       string `json:"mode"`
		Diff       string `json:"diff"`
		Actor      string `json:"actor"`
		ActorExe   string `json:"actor_exe"`
		ActorPID   int    `json:"actor_pid"`
		ActorStart string `json:"actor_start"`
		User       string `json:"user"`
		Syscall    string `json:"syscall"`
	}
	if err := json.Unmarshal([]byte(msg), &c); err != nil || c.Path == "" || c.Action == "" {
		return false
	}
	// Only the agent's FIM actions - keeps the label-agnostic JSON sniff in Normalize from
	// swallowing other JSON logs that happen to have path/action fields.
	switch {
	case c.Action == "created", c.Action == "modified", c.Action == "deleted",
		c.Action == "restored", c.Action == "encrypted",
		// Operator/response actions the agent reports so they land in the event timeline as an
		// audit trail. "quarantined" was previously dropped here, which silently cost the
		// quarantine feature its record; kill_* carries the kill-switch outcome
		// (kill_killed / kill_skipped_protected / kill_failed / ...).
		c.Action == "quarantined", strings.HasPrefix(c.Action, "kill_"):
	default:
		return false
	}
	e.Event.Category = "file"
	e.Event.Action = "file_" + c.Action
	e.Event.Outcome = "success"
	e.File = &File{Path: c.Path, HashSHA256: c.SHA256, Mode: c.Mode, Diff: c.Diff}
	// Who-data (Linux/auditd): the process/user that changed the file. This is the
	// differentiator over hash-only FIM — an alert can name the actor, not just the file.
	if c.Actor != "" || c.ActorPID != 0 {
		e.Process = &Process{Name: c.Actor, PID: c.ActorPID, CommandLine: c.ActorExe, Start: c.ActorStart}
	}
	if c.User != "" {
		e.User = &User{Name: c.User}
	}
	// Changes/deletions are riskier than newly created files; a restore is the operator's
	// own recovery action (audit trail, not a threat).
	switch c.Action {
	case "created":
		e.Event.Severity = SeverityLow
	case "restored":
		e.Event.Severity = SeverityInfo
	case "encrypted":
		e.Event.Severity = SeverityHigh // a file turned into encrypted/random data — ransomware signal
	default:
		e.Event.Severity = SeverityMedium
	}
	return true
}

func normalizeSSHD(msg string, e *Event) bool {
	// Any sshd line is an authentication-service log: set the category up front (even for lines
	// we don't structure into user/outcome below) so category-scoped auth rules can match the
	// raw text (e.g. "POSSIBLE BREAK-IN ATTEMPT", "Bad protocol version identification").
	e.Event.Category = "authentication"
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
