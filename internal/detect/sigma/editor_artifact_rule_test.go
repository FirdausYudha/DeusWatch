package sigma

import (
	"os"
	"testing"

	"deuswatch/internal/ingest"
)

// The editor-artifact rule was written to a "minimal false positives" requirement, so the
// negative cases below are the point of this test, not an afterthought. Each one is a path that
// really does appear in a web root during ordinary operation, and every one of them must stay
// silent, otherwise the rule trains operators to ignore it, which is worse than not having it.
func TestEditorArtifactInWebrootRule(t *testing.T) {
	data, err := os.ReadFile("../../../rules/sigma/editor_artifact_in_webroot.yml")
	if err != nil {
		t.Fatalf("read rule: %v", err)
	}
	r := mustParse(t, string(data))

	if r.Severity() != ingest.SeverityMedium {
		t.Fatalf("expected medium severity, got %v", r.Severity())
	}
	if tech, _ := r.MITRE(); tech != "T1059.004" {
		t.Fatalf("expected T1059.004, got %q", tech)
	}

	fileEvent := func(path, action string) map[string]any {
		return FlattenEvent(&ingest.Event{
			Event: ingest.EventFields{Category: "file", Action: action},
			File:  &ingest.File{Path: path},
		})
	}

	// Must fire: an editor working file created inside a served directory.
	hits := []struct{ path, why string }{
		{"/var/www/html/.index.php.swp", "vim swap in the Debian/Ubuntu web root"},
		{"/var/www/html/.test.txt.swo", "vim secondary swap"},
		{"/var/www/html/.conf.swn", "vim tertiary swap"},
		{"/usr/share/nginx/html/.index.html.swp", "nginx default root"},
		{"/srv/http/.index.php.swp", "Arch web root"},
		{"/srv/www/.app.php.swp", "SUSE web root"},
		{"/home/deploy/public_html/.index.php.swp", "per-user site"},
		{"/opt/lampp/htdocs/.index.php.swp", "XAMPP"},
		{"/var/www/html/.index.php.un~", "vim persistent undo"},
		{"/var/www/html/.#index.php", "Emacs lock file"},
	}
	for _, h := range hits {
		if ok, err := r.Matches(fileEvent(h.path, "file_created")); err != nil || !ok {
			t.Errorf("should fire (%s): %s, ok=%v err=%v", h.why, h.path, ok, err)
		}
	}

	// Must stay silent. These are the false positives the rule was shaped to avoid.
	misses := []struct{ path, action, why string }{
		// Wrong action: one alert per editing session, not three. vim writes the swap file,
		// updates it, then removes it; only the creation should speak.
		{"/var/www/html/.index.php.swp", "file_modified", "same session, already alerted on create"},
		{"/var/www/html/.index.php.swp", "file_deleted", "editor exiting cleanly"},

		// Outside a web root: editing your own dotfiles or a config is not this rule's business.
		{"/home/deploy/.bashrc.swp", "file_created", "user's home directory"},
		{"/etc/nginx/.nginx.conf.swp", "file_created", "config dir, covered by the /etc FIM rules"},
		{"/tmp/.scratch.swp", "file_created", "scratch space"},

		// Deployment and build tooling, which is exactly what must not be caught.
		{"/var/www/html/.index.php.YvB3kR", "file_created", "rsync temp file (random suffix)"},
		{"/var/www/html/index.php.orig", "file_created", "patch/merge leftover"},
		{"/var/www/html/index.php.rej", "file_created", "rejected hunk"},
		{"/var/www/html/index.php~", "file_created", "generic backup, too weak a signal"},
		{"/var/www/html/index.php.bak", "file_created", "deploy backup"},
		{"/var/www/html/composer.lock", "file_created", "package manager"},
		{"/var/www/html/.git/index.lock", "file_created", "git"},

		// Ordinary content, including files whose names merely contain a dot or hash.
		{"/var/www/html/index.php", "file_created", "plain page"},
		{"/var/www/html/style.swap.css", "file_created", "'swap' in the middle, not a swap file"},
		{"/var/www/html/report#2.pdf", "file_created", "hash mid-name, not an Emacs artifact"},
	}
	for _, m := range misses {
		if ok, _ := r.Matches(fileEvent(m.path, m.action)); ok {
			t.Errorf("FALSE POSITIVE (%s): %s [%s]", m.why, m.path, m.action)
		}
	}
}
