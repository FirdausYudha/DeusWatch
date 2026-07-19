package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestFIMSnapshots exercises record (with de-dup), the timeline, the path list, and retention
// pruning against a real Postgres. Integration — skipped if Postgres is down.
func TestFIMSnapshots(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	agent, path := "snap-test-agent", "/etc/snap-test.conf"
	_, _ = st.pool.Exec(ctx, `DELETE FROM fim_snapshots WHERE agent_name=$1`, agent)

	// First version is recorded.
	if created, err := st.RecordSnapshot(ctx, FIMSnapshot{AgentName: agent, Path: path, SHA256: "aaa", Size: 10}, nil); err != nil || !created {
		t.Fatalf("first record: created=%v err=%v", created, err)
	}
	// Same hash again → de-duplicated (no new version).
	if created, err := st.RecordSnapshot(ctx, FIMSnapshot{AgentName: agent, Path: path, SHA256: "aaa"}, nil); err != nil || created {
		t.Fatalf("dup record should be skipped: created=%v err=%v", created, err)
	}
	// A changed hash → new version.
	if created, err := st.RecordSnapshot(ctx, FIMSnapshot{AgentName: agent, Path: path, SHA256: "bbb", Trigger: "scheduled"}, nil); err != nil || !created {
		t.Fatalf("changed record: created=%v err=%v", created, err)
	}

	snaps, err := st.ListSnapshots(ctx, agent, path, 0)
	if err != nil || len(snaps) != 2 {
		t.Fatalf("want 2 versions, got %d err=%v", len(snaps), err)
	}
	if snaps[0].SHA256 != "bbb" { // newest first
		t.Fatalf("newest should be bbb, got %q", snaps[0].SHA256)
	}

	paths, err := st.ListSnapshotPaths(ctx, agent)
	if err != nil || len(paths) != 1 || paths[0].Versions != 2 {
		t.Fatalf("want 1 path with 2 versions, got %+v err=%v", paths, err)
	}

	// Retain only the newest 1 → prunes the older version.
	if n, err := st.PruneSnapshots(ctx, agent, path, 1); err != nil || n != 1 {
		t.Fatalf("prune want 1 deleted, got %d err=%v", n, err)
	}
	if snaps, _ := st.ListSnapshots(ctx, agent, path, 0); len(snaps) != 1 {
		t.Fatalf("after prune want 1 version, got %d", len(snaps))
	}
	_, _ = st.pool.Exec(ctx, `DELETE FROM fim_snapshots WHERE agent_name=$1`, agent)
}

// TestManagerStoredSnapshotContent proves a manager-stored version keeps its content centrally
// and that SnapshotContent reads it back (Phase 5 durability / restore-from-manager).
func TestManagerStoredSnapshotContent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	agent, path := "mgr-store-agent", "/etc/mgr.conf"
	_, _ = st.pool.Exec(ctx, `DELETE FROM fim_snapshots WHERE agent_name=$1`, agent)

	// Agent-stored version → no content on the manager.
	if _, err := st.RecordSnapshot(ctx, FIMSnapshot{AgentName: agent, Path: path, SHA256: "aaa", Storage: "agent"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.SnapshotContent(ctx, agent, path, "aaa"); ok {
		t.Fatal("agent-stored version must not have manager content")
	}
	// Manager-stored version → content retained centrally.
	content := []byte("central copy of the config\n")
	if _, err := st.RecordSnapshot(ctx, FIMSnapshot{AgentName: agent, Path: path, SHA256: "bbb", Storage: "manager"}, content); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.SnapshotContent(ctx, agent, path, "bbb")
	if err != nil || !ok || string(got) != string(content) {
		t.Fatalf("manager content: got %q ok=%v err=%v", got, ok, err)
	}
	_, _ = st.pool.Exec(ctx, `DELETE FROM fim_snapshots WHERE agent_name=$1`, agent)
}

// TestFileActions exercises the manager→agent action queue (request → pending/deliver → result).
func TestFileActions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	agent, path := "action-test-agent", "/var/www/html/x.php"
	_, _ = st.pool.Exec(ctx, `DELETE FROM agent_file_actions WHERE agent_name=$1`, agent)

	if err := st.RequestFileAction(ctx, agent, path, "quarantine", "alice"); err != nil {
		t.Fatalf("request: %v", err)
	}
	// Dedup: an identical still-pending request is a no-op.
	if err := st.RequestFileAction(ctx, agent, path, "quarantine", "alice"); err != nil {
		t.Fatalf("request dup: %v", err)
	}
	if err := st.RequestFileAction(ctx, agent, path, "bogus", "alice"); err == nil {
		t.Fatal("unknown action should be rejected")
	}

	// Agent polls → gets the one action, now marked delivered.
	pend, err := st.PendingFileActions(ctx, agent)
	if err != nil || len(pend) != 1 || pend[0].Action != "quarantine" {
		t.Fatalf("pending: got %+v err=%v", pend, err)
	}
	// A second poll returns nothing (already delivered).
	if again, _ := st.PendingFileActions(ctx, agent); len(again) != 0 {
		t.Fatalf("second poll should be empty, got %d", len(again))
	}

	// Agent reports the outcome.
	if err := st.SetFileActionResult(ctx, pend[0].ID, "done", "quarantined to /var/lib/deuswatch/quarantine/x.php.abc.q"); err != nil {
		t.Fatalf("result: %v", err)
	}
	acts, err := st.ListFileActions(ctx, agent, path, 10)
	if err != nil || len(acts) != 1 || acts[0].Status != "done" || acts[0].Result == "" {
		t.Fatalf("list actions: got %+v err=%v", acts, err)
	}

	// restore_version carries the target version hash through the queue.
	sha := "1111111111111111111111111111111111111111111111111111111111111111"
	if err := st.RequestRestoreVersion(ctx, agent, path, sha, "bob"); err != nil {
		t.Fatalf("request restore-version: %v", err)
	}
	if err := st.RequestRestoreVersion(ctx, agent, path, "short", "bob"); err == nil {
		t.Fatal("a non-64-char sha should be rejected")
	}
	rv, err := st.PendingFileActions(ctx, agent)
	if err != nil || len(rv) != 1 || rv[0].Action != "restore_version" || rv[0].VersionSHA != sha {
		t.Fatalf("restore-version pending: got %+v err=%v", rv, err)
	}
	_, _ = st.pool.Exec(ctx, `DELETE FROM agent_file_actions WHERE agent_name=$1`, agent)
}

// TestBulkRestoreVersions proves the point-in-time revert queues, for each watched file, its
// latest version at or before the chosen time (the ransomware recovery action).
func TestBulkRestoreVersions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	agent := "bulk-restore-agent"
	_, _ = st.pool.Exec(ctx, `DELETE FROM fim_snapshots WHERE agent_name=$1`, agent)
	_, _ = st.pool.Exec(ctx, `DELETE FROM agent_file_actions WHERE agent_name=$1`, agent)

	// Two files, each with a "good" version (2h ago) and an "encrypted" version (10m ago).
	seed := func(path, sha string, ago time.Duration) {
		_, e := st.pool.Exec(ctx,
			`INSERT INTO fim_snapshots (agent_name, path, sha256, storage, trigger, captured_at)
			 VALUES ($1,$2,$3,'agent','on_change', now() - $4::interval)`,
			agent, path, sha, fmt.Sprintf("%d seconds", int(ago.Seconds())))
		if e != nil {
			t.Fatal(e)
		}
	}
	seed("/var/www/a.php", "good-a", 2*time.Hour)
	seed("/var/www/a.php", "enc-a", 10*time.Minute)
	seed("/var/www/b.php", "good-b", 2*time.Hour)
	seed("/var/www/b.php", "enc-b", 10*time.Minute)

	// Roll back to 1h ago → should pick each file's GOOD (pre-encryption) version.
	asOf := time.Now().Add(-1 * time.Hour)
	n, err := st.BulkRestoreVersions(ctx, agent, "/var/www", asOf, "responder")
	if err != nil || n != 2 {
		t.Fatalf("bulk restore queued %d (want 2), err=%v", n, err)
	}
	acts, _ := st.PendingFileActions(ctx, agent)
	got := map[string]string{}
	for _, a := range acts {
		if a.Action != "restore_version" {
			t.Fatalf("unexpected action %q", a.Action)
		}
		got[a.Path] = a.VersionSHA
	}
	if got["/var/www/a.php"] != "good-a" || got["/var/www/b.php"] != "good-b" {
		t.Fatalf("bulk restore picked the wrong versions: %+v", got)
	}
	_, _ = st.pool.Exec(ctx, `DELETE FROM fim_snapshots WHERE agent_name=$1`, agent)
	_, _ = st.pool.Exec(ctx, `DELETE FROM agent_file_actions WHERE agent_name=$1`, agent)
}
