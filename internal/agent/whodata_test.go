package agent

import "testing"

// A realistic audit event for `vim /var/www/html/index.php` under our watch key.
var vimEdit = []string{
	`type=SYSCALL msg=audit(1626791011.123:456): arch=c000003e syscall=257 success=yes exit=3 items=2 ppid=1234 pid=2345 auid=1000 uid=0 gid=0 euid=0 comm="vim" exe="/usr/bin/vim" subj=unconfined key="deuswatch_fim"`,
	`type=CWD msg=audit(1626791011.123:456): cwd="/var/www/html"`,
	`type=PATH msg=audit(1626791011.123:456): item=0 name="/var/www/html" inode=100 nametype=PARENT`,
	`type=PATH msg=audit(1626791011.123:456): item=1 name="index.php" inode=101 nametype=NORMAL`,
}

func TestParseAuditEventWhoAndPaths(t *testing.T) {
	ev := parseAuditEvent(vimEdit, auditKeyForTest)
	if !ev.keyed {
		t.Fatal("event carrying our key must be keyed")
	}
	if ev.who.Actor != "vim" || ev.who.Exe != "/usr/bin/vim" || ev.who.PID != 2345 {
		t.Fatalf("who process wrong: %+v", ev.who)
	}
	if ev.who.User != "1000" { // auid preferred over uid=0
		t.Fatalf("who user = %q, want 1000 (auid)", ev.who.User)
	}
	if ev.who.Syscall != "open" { // 257 -> open
		t.Fatalf("syscall = %q, want open", ev.who.Syscall)
	}
	// The relative PATH name is resolved against CWD; the absolute one is kept.
	want := map[string]bool{"/var/www/html": true, "/var/www/html/index.php": true}
	if len(ev.paths) != 2 {
		t.Fatalf("paths = %v, want 2", ev.paths)
	}
	for _, p := range ev.paths {
		if !want[p] {
			t.Fatalf("unexpected resolved path %q (from %v)", p, ev.paths)
		}
	}
}

func TestParseAuditEventIgnoresUnkeyed(t *testing.T) {
	unkeyed := []string{
		`type=SYSCALL msg=audit(1:2): syscall=257 pid=9 comm="cat" exe="/bin/cat" auid=0 key="something_else"`,
		`type=PATH msg=audit(1:2): item=0 name="/etc/passwd"`,
	}
	if ev := parseAuditEvent(unkeyed, auditKeyForTest); ev.keyed {
		t.Fatal("an event without our key must not be keyed")
	}
}

func TestPickUserFallsBackFromUnsetAuid(t *testing.T) {
	// auid unset (4294967295) -> fall back to uid.
	if u := pickUser("4294967295", "33"); u != "33" {
		t.Fatalf("pickUser fallback = %q, want 33", u)
	}
	if u := pickUser("1000", "0"); u != "1000" {
		t.Fatalf("pickUser prefers auid, got %q", u)
	}
}

func TestUnquoteHexAndQuoted(t *testing.T) {
	if got := unquote(`"/usr/bin/vim"`); got != "/usr/bin/vim" {
		t.Fatalf("quoted unquote = %q", got)
	}
	// auditd hex-encodes a name with a space: "/tmp/a b" -> hex.
	hex := "2f746d702f6120" // "/tmp/a "
	if got := unquote(hex); got != "/tmp/a " {
		t.Fatalf("hex unquote = %q, want %q", got, "/tmp/a ")
	}
	if got := unquote("(null)"); got != "" {
		t.Fatalf("(null) must decode to empty, got %q", got)
	}
}

func TestAuditEventID(t *testing.T) {
	if id := auditEventID(`type=CWD msg=audit(1626791011.123:456): cwd="/x"`); id != "1626791011.123:456" {
		t.Fatalf("event id = %q", id)
	}
	if id := auditEventID("no marker here"); id != "" {
		t.Fatalf("missing marker must yield empty id, got %q", id)
	}
}

// auditKeyForTest mirrors the linux collector's key without importing the linux-only file.
const auditKeyForTest = "deuswatch_fim"
