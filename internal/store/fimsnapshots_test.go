package store

import (
	"context"
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
