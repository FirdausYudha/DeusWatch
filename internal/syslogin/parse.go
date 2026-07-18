// Package syslogin is a native syslog listener (UDP + TCP) that ingests logs from devices
// with no DeusWatch agent — routers, switches, firewalls, appliances — straight into the
// pipeline. Each message becomes a RawLog, is normalized to DCS (the built-in + custom
// decoders apply, keyed off the syslog TAG so an "sshd" line hits the sshd parser), and is
// published to logs.normalized, exactly like an agent-shipped line.
package syslogin

import (
	"strconv"
	"strings"
	"time"
)

// Message is the parsed content of one syslog line (RFC 3164 or RFC 5424).
type Message struct {
	Timestamp time.Time
	Host      string // the sending host
	Tag       string // program / app-name, e.g. "sshd" (drives the dataset -> the right decoder)
	Content   string // the human-readable message
}

// Parse parses one syslog line. It returns ok=false only for an empty line; otherwise it
// always yields a Message — falling back to the whole line as Content — so a format we don't
// fully understand is still ingested (raw) rather than dropped.
func Parse(line string, now time.Time) (Message, bool) {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return Message{}, false
	}
	rest := line
	// Strip the priority "<NN>" (facility*8 + severity).
	if strings.HasPrefix(rest, "<") {
		if i := strings.IndexByte(rest, '>'); i > 0 && i <= 4 {
			if _, err := strconv.Atoi(rest[1:i]); err == nil {
				rest = rest[i+1:]
			}
		}
	}
	// RFC 5424 starts with the version "1 " right after the priority.
	if strings.HasPrefix(rest, "1 ") {
		if m, ok := parse5424(rest[2:], now); ok {
			return m, true
		}
	}
	if m, ok := parse3164(rest, now); ok {
		return m, true
	}
	return Message{Timestamp: now, Content: rest}, true
}

// field splits off the first space-delimited token.
func field(s string) (tok, rest string, ok bool) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return "", "", false
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", true
}

// dash maps the syslog "nil" value "-" to empty.
func dash(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

// parse5424: TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
func parse5424(s string, now time.Time) (Message, bool) {
	ts, s, ok := field(s)
	if !ok {
		return Message{}, false
	}
	host, s, _ := field(s)
	app, s, _ := field(s)
	_, s, _ = field(s) // procid
	_, s, _ = field(s) // msgid

	s = strings.TrimLeft(s, " ")
	var msg string
	switch {
	case strings.HasPrefix(s, "-"): // no structured data
		msg = strings.TrimSpace(s[1:])
	case strings.HasPrefix(s, "["): // skip the balanced [sd] element(s)
		depth, i := 0, 0
		for ; i < len(s); i++ {
			if s[i] == '[' {
				depth++
			} else if s[i] == ']' {
				if depth--; depth == 0 {
					i++
					break
				}
			}
		}
		msg = strings.TrimSpace(s[i:])
	default:
		msg = strings.TrimSpace(s)
	}

	t := parseTime(ts, now)
	return Message{Timestamp: t, Host: dash(host), Tag: dash(app), Content: msg}, true
}

// parse3164: TIMESTAMP HOSTNAME TAG[pid]: MSG  (timestamp = "Mmm dd hh:mm:ss", 15 chars)
func parse3164(s string, now time.Time) (Message, bool) {
	if len(s) < 16 {
		return Message{}, false
	}
	t, err := time.Parse("Jan _2 15:04:05", s[:15])
	if err != nil {
		return Message{}, false
	}
	// RFC 3164 carries no year — assume the current one, in the server's location.
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())

	host, rest, ok := field(strings.TrimLeft(s[15:], " "))
	if !ok {
		return Message{}, false
	}
	tag, content := splitTag(rest)
	return Message{Timestamp: t, Host: host, Tag: tag, Content: content}, true
}

// splitTag pulls the program tag off the front: "sshd[1234]: msg" -> ("sshd", "msg");
// "kernel: msg" -> ("kernel", "msg"). A colon that isn't a tag separator — deep in the line,
// or preceded by non-tag characters like a JSON message — yields ("", whole line).
func splitTag(s string) (tag, content string) {
	colon := strings.IndexByte(s, ':')
	if colon < 0 || colon > 48 {
		return "", strings.TrimSpace(s)
	}
	cand := s[:colon]
	if b := strings.IndexByte(cand, '['); b >= 0 { // strip "[pid]"
		cand = cand[:b]
	}
	cand = strings.TrimSpace(cand)
	if cand == "" || !isTagToken(cand) {
		return "", strings.TrimSpace(s) // not a real tag (e.g. JSON) — keep the whole line
	}
	return cand, strings.TrimSpace(s[colon+1:])
}

// isTagToken reports whether s is a plausible syslog program tag: [A-Za-z0-9._/-]+.
func isTagToken(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' || c == '/') {
			return false
		}
	}
	return true
}

func parseTime(v string, now time.Time) time.Time {
	if v == "-" || v == "" {
		return now
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return now
}
