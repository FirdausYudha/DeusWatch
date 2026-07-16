package agent

import (
	"path"
	"strconv"
	"strings"
)

// WhoData identifies the process/user that caused a file change — Linux audit "who-data".
// It answers "who touched this file", the differentiator over plain hash-diff FIM.
type WhoData struct {
	Actor   string // process short name (audit comm), e.g. "vim"
	Exe     string // process executable path, e.g. "/usr/bin/vim"
	PID     int    // process id
	User    string // login user (audit auid) if resolvable, else the uid
	Syscall string // the syscall that changed the file (rename/unlink/openat…)
}

// WhoDataSource returns the most recent actor for a changed path, if known. Implemented by the
// Linux audit watcher; nil / not-found simply means no who-data (FIM still reports the change).
type WhoDataSource interface {
	Lookup(path string) (WhoData, bool)
}

// fimWhoData is the process-wide who-data source shared by all FIM sources (Linux/auditd only).
// Set once at agent startup via SetFIMWhoData; nil = disabled.
var fimWhoData WhoDataSource

// SetFIMWhoData enables who-data enrichment for FIM sources. Call once at startup.
func SetFIMWhoData(w WhoDataSource) { fimWhoData = w }

// auditEvent is the who-data parsed from one audit event (a set of records sharing an id).
type auditEvent struct {
	who   WhoData
	paths []string // absolute paths the event touched (PATH records resolved against CWD)
	keyed bool     // the SYSCALL carried our key= — only then is it a FIM who-data event
}

// parseAuditEvent parses the records (lines) of ONE audit event into who-data + affected paths.
// It is deliberately pure/portable (no syscalls) so it is unit-testable on any OS. It only
// returns keyed=true when the SYSCALL record carries key="deuswatch_fim" (our watch), so
// unrelated audit traffic is ignored.
func parseAuditEvent(lines []string, key string) auditEvent {
	var ev auditEvent
	var cwd string
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "type=SYSCALL"):
			f := auditFields(ln)
			if k := f["key"]; k != key && !strings.Contains(k, key) {
				// Not our watch — but keep parsing in case (some kernels split key). If no
				// record carries the key, keyed stays false and the event is dropped.
			} else {
				ev.keyed = true
			}
			ev.who.Syscall = syscallName(f["syscall"])
			ev.who.PID = atoi(f["pid"])
			ev.who.Actor = unquote(f["comm"])
			ev.who.Exe = unquote(f["exe"])
			ev.who.User = pickUser(f["auid"], f["uid"])
		case strings.HasPrefix(ln, "type=CWD"):
			cwd = unquote(auditFields(ln)["cwd"])
		case strings.HasPrefix(ln, "type=PATH"):
			name := unquote(auditFields(ln)["name"])
			if name == "" {
				continue
			}
			ev.paths = append(ev.paths, resolvePath(cwd, name))
		}
	}
	return ev
}

// auditFields splits an audit record's "k=v" / `k="v"` pairs into a map. Values may be quoted,
// hex-encoded (no quotes, even hex), or bare. Quoting/hex is decoded by unquote at read time.
func auditFields(line string) map[string]string {
	out := map[string]string{}
	for _, tok := range splitAudit(line) {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		out[tok[:eq]] = tok[eq+1:]
	}
	return out
}

// splitAudit tokenizes on spaces but keeps quoted values ("...") intact.
func splitAudit(line string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			b.WriteByte(c)
		case c == ' ' && !inQuote:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// unquote returns a human string from an audit value: strips surrounding quotes, decodes a
// hex-encoded value (auditd hex-encodes names/exe that contain spaces or non-printables), and
// maps the literal "(null)" to empty.
func unquote(v string) string {
	if v == "" || v == "(null)" {
		return ""
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	// Bare value that is all hex and even length -> hex-encoded string.
	if len(v)%2 == 0 && isHex(v) {
		if dec, ok := decodeHex(v); ok {
			return dec
		}
	}
	return v
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func decodeHex(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i+1 < len(s); i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return "", false
		}
		b.WriteByte(hi<<4 | lo)
	}
	return b.String(), true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// resolvePath joins a PATH name against the event's CWD (audit paths are always forward-slash).
func resolvePath(cwd, name string) string {
	if strings.HasPrefix(name, "/") {
		return path.Clean(name)
	}
	if cwd == "" {
		return name
	}
	return path.Clean(cwd + "/" + name)
}

// pickUser prefers the login uid (auid) over the effective uid, ignoring the "unset" sentinel
// (4294967295 / -1) that appears for non-login contexts.
func pickUser(auid, uid string) string {
	if u := numericUser(auid); u != "" {
		return u
	}
	return numericUser(uid)
}

func numericUser(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "4294967295" || v == "-1" || v == "unset" {
		return ""
	}
	return v
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// auditEventID extracts the "TS:ID" event id from an audit record's msg=audit(...) field, so
// records of the same event can be grouped. Returns "" if absent.
func auditEventID(line string) string {
	const marker = "msg=audit("
	i := strings.Index(line, marker)
	if i < 0 {
		return ""
	}
	rest := line[i+len(marker):]
	if j := strings.IndexByte(rest, ')'); j >= 0 {
		return rest[:j]
	}
	return ""
}

// syscallName maps the common file-changing syscall numbers (x86-64) to names, so the dashboard
// reads "unlink" not "87". Unknown numbers pass through unchanged.
func syscallName(n string) string {
	switch strings.TrimSpace(n) {
	case "2", "257":
		return "open"
	case "82", "264":
		return "rename"
	case "87", "263":
		return "unlink"
	case "1", "18":
		return "write"
	case "88", "265":
		return "symlink"
	case "90", "268":
		return "chmod"
	case "":
		return ""
	}
	return n
}
